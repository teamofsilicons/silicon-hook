"""A TCP relay from 127.0.0.1:<listen> to 127.0.0.1:<target>: scenario 9 cuts Hook off from Silicon Accounts with it.

    python3 scripts/e2e_accounts/relay.py <listen port> <target port>
"""

import socket
import sys
import threading


def pipe(source, sink):
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            sink.sendall(data)
    except OSError:
        pass
    finally:
        for end in (source, sink):
            try:
                end.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def main():
    listen, target = int(sys.argv[1]), int(sys.argv[2])
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", listen))
    server.listen(64)
    while True:
        client, _ = server.accept()
        try:
            upstream = socket.create_connection(("127.0.0.1", target), timeout=5)
        except OSError:
            client.close()
            continue
        threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
        threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()


if __name__ == "__main__":
    main()
