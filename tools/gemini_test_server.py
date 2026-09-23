#!/usr/bin/env python3
"""A Gemini server on the development machine, for testing the client
against known documents and known misbehaviour.

    python3 tools/gemini_test_server.py [--port 1965] [--cert build/certs/p256.crt --key build/certs/p256.key]
                                        [--keylog build/keylog.txt] [--adversary NAME]

Serves the documents in tools/site/ (gemini://host/ is index.gmi), plus:
    /input          status 10, then echoes the query
    /secret         status 11 (sensitive input)
    /redirect       30 to /
    /loop           30 to /loop, forever
    /gone           51
    /slow           44
    /big            a 200 KB document
    /binary         20 application/octet-stream, 4 KB of bytes
    /latin          20 text/gemini;charset=iso-8859-1
    /nocrlf         a header without CRLF, then nothing (the client must time out)
    /silent         accepts the request and never answers
Adversaries (--adversary): 'silent' never answers any request; 'slow'
sends one byte a second; 'close' closes after the TLS handshake.

--keylog writes TLS secrets in NSS key-log format, so Wireshark or the
host harness can decrypt a capture while the record layer is debugged.
Needs Python 3.8+; the certificates come from openssl (see build.py certs).
"""
import argparse, os, socket, ssl, sys, threading, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SITE = ROOT / "site"


def gmi(name):
    p = SITE / name
    return p.read_bytes() if p.exists() else None


def respond(url, adversary):
    """Returns (header without CRLF, body bytes, delay per byte)."""
    path = url.split("://", 1)[-1].split("/", 1)
    path = "/" + (path[1] if len(path) > 1 else "")
    query = ""
    if "?" in path:
        path, query = path.split("?", 1)
    if path == "/input":
        if not query:
            return "10 Type something", b"", 0
        return "20 text/gemini", ("# You typed\n\n%s\n" % query).encode(), 0
    if path == "/secret":
        if not query:
            return "11 Password", b"", 0
        return "20 text/gemini", b"# Accepted\n", 0
    if path == "/redirect":
        return "30 /", b"", 0
    if path == "/loop":
        return "30 /loop", b"", 0
    if path == "/gone":
        return "51 Not found", b"", 0
    if path == "/slow":
        return "44 Slow down", b"", 0
    if path == "/big":
        body = b"# A big document\n\n" + b"".join(b"Line %d of a document that is far too big to hold in memory at once, so the client must stream it into attic RAM as it arrives.\n" % i for i in range(1500))
        return "20 text/gemini", body, 0
    if path == "/binary":
        return "20 application/octet-stream", bytes(range(256)) * 16, 0
    if path == "/latin":
        return "20 text/gemini;charset=iso-8859-1", "# Café\n\nMüller, Ångström, señor.\n".encode("latin-1"), 0
    if path == "/nocrlf":
        return None, b"20 text/gemini", 0
    if path == "/silent":
        return None, None, 0
    name = "index.gmi" if path == "/" else path.lstrip("/")
    if not name.endswith(".gmi") and (SITE / (name + ".gmi")).exists():
        name += ".gmi"
    body = gmi(name)
    if body is None:
        return "51 Not found", b"", 0
    return "20 text/gemini", body, (1 if adversary == "slow" else 0)


def serve(conn, addr, args):
    try:
        conn.settimeout(30)
        if args.adversary == "close":
            conn.close(); return
        if args.adversary == "silent":
            time.sleep(120); conn.close(); return
        req = b""
        while not req.endswith(b"\r\n") and len(req) < 1100:
            b = conn.recv(1)
            if not b:
                break
            req += b
        url = req.rstrip(b"\r\n").decode("utf-8", "replace")
        if len(req) > 1026 or not url.startswith("gemini://"):
            conn.sendall(b"59 Bad request\r\n"); conn.close(); return
        print(f"{addr[0]} {url}", flush=True)
        header, body, delay = respond(url, args.adversary)
        if header is None and body is None:
            time.sleep(120); conn.close(); return
        if header is None:
            conn.sendall(body); time.sleep(60); conn.close(); return
        conn.sendall(header.encode() + b"\r\n")
        if delay:
            for i in range(len(body)):
                conn.sendall(body[i:i + 1]); time.sleep(delay)
        else:
            conn.sendall(body)
        conn.close()
    except Exception as e:                       # a client that hangs up mid-way is normal
        print(f"{addr[0]} {e}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=1965)
    ap.add_argument("--cert", default=str(ROOT.parent / "build" / "certs" / "p256.crt"))
    ap.add_argument("--key", default=str(ROOT.parent / "build" / "certs" / "p256.key"))
    ap.add_argument("--keylog")
    ap.add_argument("--adversary", choices=["silent", "slow", "close"])
    args = ap.parse_args()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(args.cert, args.key)
    if args.keylog:
        ctx.keylog_filename = args.keylog
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", args.port)); s.listen(5)
    print(f"gemini test server on :{args.port}, {Path(args.cert).name}, adversary={args.adversary}", flush=True)
    while True:
        c, a = s.accept()
        def go(c=c, a=a):
            try:
                tls = ctx.wrap_socket(c, server_side=True)
            except Exception as e:
                print(f"{a[0]} handshake: {e}", flush=True); c.close(); return
            serve(tls, a, args)
        threading.Thread(target=go, daemon=True).start()


if __name__ == "__main__":
    main()
