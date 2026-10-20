"""Serve only a report directory on loopback, choosing an unused port."""
import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from .engine import ROOT

def main():
    p=argparse.ArgumentParser(description='Preview a generated AD lab report on loopback')
    p.add_argument('--directory',type=Path,default=ROOT/'evidence/replay');p.add_argument('--port',type=int,default=0)
    args=p.parse_args()
    if not (args.directory/'report.html').is_file():p.error('report.html is missing; run python -m adlab report first')
    server=ThreadingHTTPServer(('127.0.0.1',args.port),partial(SimpleHTTPRequestHandler,directory=str(args.directory.resolve())))
    print(f'Open http://127.0.0.1:{server.server_port}/report.html',flush=True)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()
if __name__=='__main__':main()
