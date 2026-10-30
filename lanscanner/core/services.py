"""Non-intrusive service, open port metadata, and HTTP title/TLS cert detector."""

import asyncio
import re
import socket
import ssl
from typing import Dict, List, Optional

# Focused, standard ports for technical inventory, classification and security assessment
INVENTORY_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    554: "RTSP",
    1883: "MQTT",
    8006: "Proxmox-PVE",
    8008: "GoogleCast-DIAL",
    8080: "HTTP-Alt",
    8123: "HomeAssistant",
    8443: "HTTPS-Alt",
    9000: "Portainer/Management",
}

# SSL context that accepts self-signed LAN certificates
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


def _extract_cert_subject(sock: ssl.SSLSocket) -> Optional[str]:
    """Extract Common Name or Organization from TLS certificate without validation."""
    try:
        cert = sock.getpeercert(binary_form=True)
        # Fallback or check if binary cert is available
        # With CERT_NONE, getpeercert() returns {} unless we inspect binary DER
        if cert:
            # Simple heuristic regex on binary DER cert to extract CommonName ASCII string
            # CN OID is 2.5.4.3 (0x55 0x04 0x03)
            idx = cert.find(b"\x55\x04\x03")
            if idx != -1 and idx + 5 < len(cert):
                tag = cert[idx + 3]
                length = cert[idx + 4]
                if tag in (19, 12) and length < 64:  # PrintableString or UTF8String
                    cn = cert[idx + 5 : idx + 5 + length].decode("ascii", errors="ignore").strip()
                    if cn:
                        return cn
    except Exception:
        pass
    return None


async def probe_port(ip: str, port: int, service_name: str, timeout: float = 0.5) -> Optional[Dict]:
    """Test if a standard service port is open and extract title, banner, and cert metadata."""
    is_tls = port in (443, 8006, 8443)
    title = None
    banner = None
    cert_cn = None

    try:
        if is_tls:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=SSL_CTX),
                timeout=timeout
            )
            # Try to grab TLS cert info
            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj:
                    cert_cn = _extract_cert_subject(ssl_obj)
            except Exception:
                pass
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )

        # For web-based ports, send lightweight HTTP GET to extract HTML <title> and Server header
        if port in (80, 443, 8006, 8080, 8123, 8443, 9000):
            try:
                req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0 (LANScanner)\r\nConnection: close\r\n\r\n"
                writer.write(req.encode("ascii"))
                await writer.drain()

                raw_resp = await asyncio.wait_for(reader.read(2048), timeout=0.6)
                text = raw_resp.decode("utf-8", errors="ignore")

                # Extract Server header
                for line in text.splitlines():
                    if line.lower().startswith("server:"):
                        banner = line.split(":", 1)[1].strip()
                        break

                # Extract <title>...</title>
                title_match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    raw_title = title_match.group(1).replace("&nbsp;", " ").strip()
                    # Clean newlines and excessive whitespace
                    title = " ".join(raw_title.split())

            except Exception:
                pass

        elif port in (21, 22, 23):
            # Daemons like SSH, FTP, Telnet typically send a banner greeting upon connection
            try:
                raw_resp = await asyncio.wait_for(reader.read(256), timeout=0.3)
                banner = raw_resp.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        return {
            "port": port,
            "service": service_name,
            "banner": banner,
            "title": title,
            "cert_cn": cert_cn,
        }

    except Exception:
        return None


async def scan_host_services(ip: str, concurrency: int = 6) -> List[Dict]:
    """Check standard inventory ports on a single host."""
    results = []
    sem = asyncio.Semaphore(concurrency)

    async def worker(port: int, svc: str):
        async with sem:
            res = await probe_port(ip, port, svc)
            if res:
                results.append(res)

    await asyncio.gather(*(worker(port, svc) for port, svc in INVENTORY_PORTS.items()))
    return sorted(results, key=lambda x: x["port"])


async def scan_all_services(ips: List[str], max_hosts_concurrent: int = 8) -> Dict[str, List[Dict]]:
    """Scan standard inventory ports for multiple active hosts."""
    host_results = {}
    sem = asyncio.Semaphore(max_hosts_concurrent)

    async def host_worker(ip: str):
        async with sem:
            svcs = await scan_host_services(ip)
            if svcs:
                host_results[ip] = svcs

    await asyncio.gather(*(host_worker(ip) for ip in ips), return_exceptions=True)
    return host_results
