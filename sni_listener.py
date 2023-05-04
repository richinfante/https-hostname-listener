import argparse
import socket
from datetime import datetime
import ipaddress

def extract_hostname(packet_data):
    """Extracts the hostname from the SNI portion of a TLS hello packet, or HTTP Host header"""
    if packet_data[0] == 0x16:  # TLS Client Hello
        session_id_length = packet_data[43]
        # print('Session ID Len:', session_id_length)
        # session_id = packet_data[44:44+session_id_length].hex()
        # print('Session ID:', session_id)

        cipher_suites_offset = 44+session_id_length
        cipher_suites_length = int.from_bytes(packet_data[cipher_suites_offset:cipher_suites_offset+2], byteorder='big')
        # print('Cipher Suites Len:', cipher_suites_length)
        # cipher_suites = packet_data[cipher_suites_offset+2:cipher_suites_offset+2+cipher_suites_length].hex()
        # print('Cipher Suites:', cipher_suites)

        compression_methods_offset = cipher_suites_offset+2+cipher_suites_length
        compression_methods_length = packet_data[compression_methods_offset]
        # print('Compression Methods Len:', compression_methods_length)
        # compression_methods = packet_data[compression_methods_offset+1:compression_methods_offset+1+compression_methods_length].hex()
        # print('Compression Methods:', compression_methods)

        extensions_offset = compression_methods_offset+1+compression_methods_length
        extensions_length = int.from_bytes(packet_data[extensions_offset:extensions_offset+2], byteorder='big')
        # print('Extensions Len:', extensions_length)
        extensions_data = packet_data[extensions_offset+2:extensions_offset+2+extensions_length]

        offset = 0
        while offset < extensions_length:
            extension_type = int.from_bytes(extensions_data[offset:offset+2], byteorder='big')
            extension_length = int.from_bytes(extensions_data[offset+2:offset+4], byteorder='big')
            extension_data = extensions_data[offset+4:offset+4+extension_length]

            # SNI extension is type 0
            # https://tools.ietf.org/html/rfc6066#section-3
            if extension_type == 0:
                sni_field = extension_data[5:]
                return 'https://%s' % sni_field.decode()

            offset += 4+extension_length

    # HTTP Host header
    # If no luck, try to parse as a normal HTTP request
    # Split on \r\n to get lines and look for Host header
    for line in packet_data.split(b'\r\n'):
        if line.startswith(b'Host: '):
            return 'http://%s' % line[6:].decode()

    return None

def run_server():
    """Runs the SNI listener server"""
    parser = argparse.ArgumentParser(description='HTTP/SNI Hostname Listener')
    parser.add_argument('--port', type=int, default=443, help='Port to listen on')
    parser.add_argument('--bind-addr', type=str, default='0.0.0.0', help='Address to bind to')
    parser.add_argument('--recv-size', type=int, default=4096, help='Amount of data to read from the socket. This should not need to be changed')
    parser.add_argument('--quiet', action='store_true', default=False, help='Suppress output for all non-sni requests')

    args = parser.parse_args()

    # Parse arguments
    port = args.port
    bind_addr = args.bind_addr
    recv_size = args.recv_size
    quiet = args.quiet

    # Validate argument for ipaddress
    bind_addr_obj = ipaddress.ip_address(bind_addr)

    # Create socket (if bind is IPv4, use IPv4 socket, else use IPv6 socket)
    if bind_addr_obj.version == 4:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # IPv4, TCP
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow socket reuse
        server_socket.bind((bind_addr, port))  # Bind to port

    # IPv6
    elif bind_addr_obj.version == 6:
        server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((bind_addr, port, 0, 0))  # Bind to port

    # Invalid IP address (should never happen since we validate above)
    else:
        raise Exception("Invalid IP address")

    # Actually listen on the socket
    server_socket.listen()

    # print info about the server and output format
    if not quiet:
        print(f'Hostname Discovery listening on {bind_addr}:{port}')
        print("# cols: timestamp, client_ip:client_port, proto://hostname")

    # Accept connections
    while True:
        # Accept connection and read data
        conn, addr = server_socket.accept()
        data = conn.recv(recv_size)
        conn.close()

        line_prefix = f"{datetime.now().isoformat()} {addr[0]}:{addr[1]}"

        # Extract hostname from SNI
        try:
            hostname = extract_hostname(data)
        except Exception as err:
            if not quiet:
                print(f"{line_prefix}: Error parsing TLS Client Hello: {err}")
            continue

        # Log findings
        if hostname:
            print(f"{line_prefix} {hostname}")
        elif not quiet:
            print(f"{line_prefix} (No hostname found)")

# Entry point
if __name__ == '__main__':
    run_server()
