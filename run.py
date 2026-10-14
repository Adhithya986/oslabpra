import argparse
import sys
import webbrowser
import threading
import time
import uvicorn
from app.config import SERVER_HOST, SERVER_PORT, APP_NAME, APP_SUBTITLE, VERSION

def open_browser_delayed(url: str):
    time.sleep(1.2)
    webbrowser.open(url)

def main():
    parser = argparse.ArgumentParser(description=f"{APP_NAME} - {APP_SUBTITLE}")
    parser.add_argument("--host", default=SERVER_HOST, help=f"Host interface (default: {SERVER_HOST})")
    parser.add_argument("--port", type=int, default=SERVER_PORT, help=f"Port number (default: {SERVER_PORT})")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch web browser")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}"

    print("=" * 65)
    print(f"  {APP_NAME} v{VERSION} — {APP_SUBTITLE}")
    print("=" * 65)
    print(f"  -> Dashboard URL:      {url}")
    print(f"  -> WebSocket Stream:   ws://{args.host}:{args.port}/ws/live")
    print(f"  -> API Documentation:  {url}/docs")
    print("=" * 65)
    print("  [+] Starting real-time system metrics engine...")
    print("  [+] Initializing threat detection & heuristic scanner...")
    print("  [+] Press Ctrl+C to terminate monitor.\n")

    if not args.no_browser:
        threading.Thread(target=open_browser_delayed, args=(url,), daemon=True).start()

    uvicorn.run("app.main:app", host=args.host, port=args.port, log_level="info")

if __name__ == "__main__":
    main()
