"""Entry point to launch the LANWatch Sentinel web application."""

import os
import sys
import webbrowser
import uvicorn
from lanscanner.api.app import app


def main():
    port = int(os.environ.get("PORT", "8088"))
    print("=" * 60)
    print("  LANWatch - Home LAN Sentinel & Security Assessment")
    print(f"  Avvio del server su: http://127.0.0.1:{port}")
    print("=" * 60)
    
    # Try to open the default browser automatically
    try:
        webbrowser.open(f"http://127.0.0.1:{port}")
    except Exception:
        pass

    uvicorn.run(
        "lanscanner.api.app:app",
        host="0.0.0.0",
        port=port,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
