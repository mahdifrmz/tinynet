#!/usr/bin/python3
import http.server
import socketserver
import sys
from http import HTTPStatus

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(HTTPStatus.OK)
        self.end_headers()
        self.wfile.write(b'Hello world')

httpd = socketserver.TCPServer(('0.0.0.0', int(sys.argv[1])), Handler)
httpd.serve_forever()