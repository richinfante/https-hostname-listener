# HTTPS-HOST-LISTENER

This program listens on a port of your choice, and dumps information from the TLS-SNI extension header and HTTP host header for all requests recieved.

This doesn't work with eSNI, but it will reveal the intented hostname for any client hello it recieves with the hostname unencrypted.

Encrypted SNI (ESNI) protects this information leakage by encypting the hostname. For more info, see: https://www.cloudflare.com/learning/ssl/what-is-encrypted-sni/

If we don't find a valid TLS hello, this program tries to parse the packet as a normal HTTP packet and extract the `Host` header.

## Starting The Listener
```
sudo python3 sni_listener.py --port 443
```

## Example Output
If you load "https://localtest.me/" in the browser, you would see output like below.

This works since `localtest.me` resolves to 127.0.0.1. (this is a domain someone set up that resolves this way). You could also try "https://localhost" which is typically in your local HOSTS file.

```
Hostname Discovery listening on https://0.0.0.0:443
# cols: timestamp, client_ip:client_port, proto://hostname
2023-05-03T22:03:57.310837 127.0.0.1:52371 https://localtest.me
2023-05-03T22:03:57.311421 127.0.0.1:52372 https://localtest.me
2023-05-03T22:03:57.990252 127.0.0.1:52373 https://localtest.me
```
