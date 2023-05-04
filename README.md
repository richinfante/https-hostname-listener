# SNI-LISTENER

This program listens on a port of your choice, and dumps information from the TLS-SNI extension header.

This doesn't work with eSNI, but it will reveal the intented hostname for any client hello it recieves with the hostname unencrypted.

Encrypted SNI (ESNI) protects this information leakage by encypting the hostname. For more info, see: https://www.cloudflare.com/learning/ssl/what-is-encrypted-sni/

## Starting The Listener
```
sudo python3 sni_listener.py --port 443
```

## Example Output
If you load "https://localhost:443" in the browser, you would see output like this:

```
Hostname Discovery listening on https://0.0.0.0:443
# cols: timestamp, client_ip:client_port, hostname
2023-05-03T21:49:19.917972 127.0.0.1:51747 localhost
2023-05-03T21:49:19.918568 127.0.0.1:51749 localhost
2023-05-03T21:49:20.947262 127.0.0.1:51751 localhost
```