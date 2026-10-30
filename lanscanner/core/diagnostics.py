"""Network diagnostics: Wake-on-LAN, ping latency, and internet connection health."""

import asyncio
import os
import re
import socket
import subprocess
import sys
import time
from typing import Dict, Optional
from lanscanner.core.oui import normalize_mac


def send_wake_on_lan(mac: str, broadcast_ip: str = "255.255.255.255", port: int = 9) -> bool:
    """Send Wake-on-LAN magic packet to power on a target device."""
    normalized = normalize_mac(mac)
    if not normalized:
        return False

    # Extract 6 raw bytes
    raw_mac = bytes.fromhex(normalized.replace(":", ""))
    magic_packet = b"\xff" * 6 + raw_mac * 16

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(magic_packet, (broadcast_ip, port))
        sock.close()
        return True
    except Exception:
        return False


async def measure_ping_latency(ip: str, timeout_ms: int = 800) -> Optional[float]:
    """Measure single ping latency in milliseconds, cross-platform with TCP fallback."""
    def _do_ping():
        # 1. Try ICMP ping (OS-specific flags)
        try:
            if sys.platform.startswith("win"):
                cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
            else:
                # Linux iputils ping: -c 1 (count), -W <seconds>
                timeout_sec = max(1, int(round(timeout_ms / 1000.0)))
                cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]

            output = subprocess.check_output(
                cmd,
                text=True,
                stderr=subprocess.DEVNULL,
                errors="ignore"
            )
            # Match time=<val>ms or tempo=<val>ms
            m = re.search(r"(?:time|tempo)[=<](\d+(?:\.\d+)?)\s*ms", output, re.IGNORECASE)
            if m:
                return float(m.group(1))
            elif "TTL=" in output or "ttl=" in output:
                return 1.0  # Under 1ms on local LAN
        except Exception:
            pass

        # 2. Socket TCP probe fallback if ICMP is dropped/forbidden
        t0 = time.time()
        # Ports: 53 (DNS / routers / internet), 80/443 (HTTP/S router gateways)
        probe_ports = [53, 80, 443]
        for port in probe_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout_ms / 1000.0)
                res = s.connect_ex((ip, port))
                s.close()
                # 0 = open, 111 (Linux ECONNREFUSED) or 10061 (Win WSAECONNREFUSED) proves host is alive!
                if res in (0, 111, 10061):
                    return max(0.5, round((time.time() - t0) * 1000.0, 1))
            except Exception:
                pass

        return None

    try:
        res = await asyncio.wait_for(asyncio.to_thread(_do_ping), timeout=(timeout_ms / 1000.0) + 0.4)
        return res
    except Exception:
        return None


async def get_network_connection_health(gateway_ip: str) -> Dict[str, any]:
    """Measure latency to the local gateway and to Internet DNS."""
    gw_task = asyncio.create_task(measure_ping_latency(gateway_ip, timeout_ms=600))
    inet_task = asyncio.create_task(measure_ping_latency("1.1.1.1", timeout_ms=700))

    gw_lat, inet_lat = await asyncio.gather(gw_task, inet_task, return_exceptions=True)

    gw_ms = gw_lat if isinstance(gw_lat, (int, float)) else None
    inet_ms = inet_lat if isinstance(inet_lat, (int, float)) else None

    # Secondary Internet fallback to 8.8.8.8 if 1.1.1.1 timed out
    if inet_ms is None:
        inet_ms = await measure_ping_latency("8.8.8.8", timeout_ms=700)

    # Status classification
    if inet_ms is not None:
        if inet_ms < 25:
            status = "Ottima Connessione"
            color = "emerald"
        elif inet_ms < 60:
            status = "Buona"
            color = "blue"
        else:
            status = "Latenza Alta"
            color = "amber"
    elif gw_ms is not None:
        status = "LAN OK (Internet Non Raggiungibile)"
        color = "amber"
    else:
        status = "Offline"
        color = "rose"

    return {
        "gateway_ms": gw_ms,
        "internet_ms": inet_ms,
        "status_label": status,
        "color": color,
    }


if __name__ == "__main__":
    async def main():
        print("Testing network health...")
        health = await get_network_connection_health("192.168.1.254")
        print("Health:", health)
    asyncio.run(main())
