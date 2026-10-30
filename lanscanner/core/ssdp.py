"""SSDP (Simple Service Discovery Protocol) and UPnP metadata parser."""

import asyncio
import re
import socket
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
import httpx

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_MX = 2
SSDP_ST = "ssdp:all"

M_SEARCH_MSG = (
    f"M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    f'MAN: "ssdp:discover"\r\n'
    f"MX: {SSDP_MX}\r\n"
    f"ST: {SSDP_ST}\r\n"
    f"\r\n"
).encode("utf-8")


def _parse_headers(data: str) -> Dict[str, str]:
    headers = {}
    lines = data.splitlines()
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().upper()] = v.strip()
    return headers


async def _fetch_device_xml(location_url: str, timeout: float = 2.0) -> Dict[str, any]:
    """Fetch and parse UPnP rootDesc.xml for rich metadata and exposed services."""
    info = {
        "friendly_name": None,
        "manufacturer": None,
        "model_name": None,
        "model_number": None,
        "model_description": None,
        "device_type": None,
        "services": [],
        "has_upnp_igd": False,
    }

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            resp = await client.get(location_url)
            if resp.status_code != 200:
                return info

            xml_text = resp.text
            # Remove XML namespace prefixes for easy parsing
            clean_xml = re.sub(r'\sxmlns(:\w+)?="[^"]+"', "", xml_text, count=1)
            root = ET.fromstring(clean_xml)

            # Extract device details
            device_elem = root.find(".//device")
            if device_elem is not None:
                def get_tag(tag):
                    e = device_elem.find(f".//{tag}")
                    return e.text.strip() if e is not None and e.text else None

                info["friendly_name"] = get_tag("friendlyName")
                info["manufacturer"] = get_tag("manufacturer")
                info["model_name"] = get_tag("modelName")
                info["model_number"] = get_tag("modelNumber")
                info["model_description"] = get_tag("modelDescription")
                info["device_type"] = get_tag("deviceType")

            # Extract services
            for s in root.findall(".//service"):
                st = s.find("serviceType")
                if st is not None and st.text:
                    s_type = st.text.strip()
                    info["services"].append(s_type)
                    if "WANIPConnection" in s_type or "WANPPPConnection" in s_type:
                        info["has_upnp_igd"] = True

    except Exception:
        pass

    return info


async def scan_ssdp(local_ip: Optional[str] = None, timeout: float = 3.0) -> Dict[str, Dict]:
    """Send SSDP M-SEARCH broadcast and collect UPnP device responses."""
    devices_by_ip: Dict[str, Dict] = {}
    locations_to_fetch: Dict[str, str] = {}

    loop = asyncio.get_running_loop()

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    
    if local_ip:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
            sock.bind((local_ip, 0))
        except Exception:
            pass

    sock.setblocking(False)

    try:
        # Broadcast M-SEARCH multiple times slightly spaced
        for _ in range(2):
            sock.sendto(M_SEARCH_MSG, (SSDP_ADDR, SSDP_PORT))
            await asyncio.sleep(0.1)
    except Exception:
        pass

    end_time = loop.time() + timeout

    while loop.time() < end_time:
        try:
            data, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 4096), timeout=0.3)
            ip = addr[0]
            msg = data.decode("utf-8", errors="ignore")
            headers = _parse_headers(msg)

            location = headers.get("LOCATION")
            server = headers.get("SERVER")
            usn = headers.get("USN")

            # Determine real device IP: if LOCATION contains an IPv4 address, prefer it!
            # Repeaters, Wi-Fi bridges (e.g. GL.iNet Mango) or IGMP proxies forward SSDP
            # with their own source IP, while LOCATION points to the actual device hosting the service.
            target_ip = ip
            if location:
                try:
                    from urllib.parse import urlparse
                    parsed_host = urlparse(location).hostname
                    if parsed_host and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed_host):
                        target_ip = parsed_host
                except Exception:
                    pass

            if target_ip not in devices_by_ip:
                devices_by_ip[target_ip] = {
                    "ip": target_ip,
                    "server": server,
                    "location": location,
                    "usn": usn,
                    "upnp_info": None,
                }
            if location and target_ip not in locations_to_fetch:
                locations_to_fetch[target_ip] = location

        except (asyncio.TimeoutError, BlockingIOError):
            continue
        except Exception:
            break

    sock.close()

    # Fetch device XMLs concurrently
    async def fetch_worker(ip: str, url: str):
        parsed = await _fetch_device_xml(url)
        if ip in devices_by_ip:
            devices_by_ip[ip]["upnp_info"] = parsed

    fetch_tasks = [fetch_worker(ip, url) for ip, url in locations_to_fetch.items()]
    if fetch_tasks:
        await asyncio.gather(*fetch_tasks, return_exceptions=True)

    return devices_by_ip


if __name__ == "__main__":
    async def main():
        from lanscanner.core.network import detect_network
        net = detect_network()
        print(f"Broadcasting SSDP M-SEARCH from {net['ip']} (3s)...")
        results = await scan_ssdp(local_ip=net['ip'], timeout=3.0)
        print(f"Discovered {len(results)} hosts via SSDP / UPnP:")
        for ip, d in results.items():
            upnp = d.get("upnp_info") or {}
            print(f" - {ip}: {upnp.get('friendly_name') or d.get('server')} (Model: {upnp.get('model_name')}, Manufacturer: {upnp.get('manufacturer')})")
            if upnp.get("has_upnp_igd"):
                print(f"   [!] UPnP Internet Gateway Device (IGD) active!")
    asyncio.run(main())
