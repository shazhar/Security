#!/usr/bin/python3

# Code adopted from: https://www.piware.de/2011/01/creating-an-https-server-in-python/
from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl

httpd = HTTPServer(('0.0.0.0', 443), SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile='cert-and-key.pem', server_side=True)
print("Running Simple HTTPS Server on Port 443")
httpd.serve_forever()
