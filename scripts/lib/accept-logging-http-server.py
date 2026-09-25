"""`python3 -m http.server`, bound to 0.0.0.0, that also logs every accept.

Usage: accept-logging-http-server.py <port> <directory>

The proof harnesses grade a listener's log as the host's own witness of who
reached it. `http.server` alone logs only requests it answered and exceptions
it hit, so a connection that is accepted and closed without a request leaves
no line at all: a forbidden port reached that way would read as silent. This
writes `accept <peer> <port>` to stderr the moment the listening socket
returns a connection, before the request is read, and is otherwise
`http.server` unchanged, so its access lines and tracebacks keep the framing
scripts/lib/broker-reach-evidence.sh reads.
"""

import functools
import http.server
import sys


class AcceptLoggingServer(http.server.ThreadingHTTPServer):
    def verify_request(self, request, client_address):
        # Called by socketserver on every connection `accept()` returned,
        # before the handler reads a byte.
        sys.stderr.write("accept %s %d\n" % (client_address[0], client_address[1]))
        sys.stderr.flush()
        return True


def main():
    port, directory = int(sys.argv[1]), sys.argv[2]
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
    with AcceptLoggingServer(("0.0.0.0", port), handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
