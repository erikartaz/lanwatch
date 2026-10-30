"""Entry point to launch the LANWatch Sentinel web application."""

import sys
import webbrowser
import uvicorn
from lanscanner.api.app import app


def main():
    print("=" * 60)
    print("  LANWatch - Home LAN Sentinel & Security Assessment")
    print("  Avvio del server su: http://127.0.0.1:8000")
    print("=" * 60)
    
    # Try to open the default browser automatically
    try:
        webbrowser.open("http://127.0.0.1:8000")
    except Exception:
        pass

    uvicorn.run(
        "lanscanner.api.app:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
