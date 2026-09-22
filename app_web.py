import os
import socket
import threading
import time
import webbrowser
from pathlib import Path

from web.server import create_app

def find_free_port(start_port=5000, end_port=5010):
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('127.0.0.1', port)) != 0:
                return port
    print(f"Warning: No free ports found in range {start_port}-{end_port}, falling back to port 0 (OS assigned)")
    return 0

def open_browser(url):
    time.sleep(1)
    webbrowser.open(url)

from werkzeug.serving import make_server

if __name__ == '__main__':
    storage_dir = Path("./secure_storage").resolve()
    app = create_app(str(storage_dir))
    
    port = find_free_port()
    
    # Use make_server to support port=0 (OS assigned) and get the actual port
    server = make_server('127.0.0.1', port, app)
    actual_port = server.server_address[1]
    url = f"http://127.0.0.1:{actual_port}"
    
    print(f"Cryptix running at {url}")
    
    threading.Thread(target=open_browser, args=(url,), daemon=True).start()
    
    # Run server
    server.serve_forever()
