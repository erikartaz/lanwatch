"""mDNS / Bonjour passive discovery using zeroconf."""

import asyncio
import socket
from typing import Dict, List, Optional
from zeroconf import IPVersion, ServiceBrowser, ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

COMMON_SERVICES = [
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_googlecast._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_smb._tcp.local.",
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_printer._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_homekit._tcp.local.",
    "_hap._tcp.local.",
    "_esphomelib._tcp.local.",
    "_shelly._tcp.local.",
    "_sonos._tcp.local.",
    "_ssh._tcp.local.",
    "_workstation._tcp.local.",
    "_companion-link._tcp.local.",
    "_mediaremotetv._tcp.local.",
    "_touch-able._tcp.local.",
]


class MDNSCollector:
    """Collects mDNS service announcements and resolves hostnames/properties."""

    def __init__(self):
        self.devices_by_ip: Dict[str, Dict] = {}

    def on_service_state_change(
        self,
        zeroconf: Zeroconf,
        service_type: str,
        name: str,
        state_change: ServiceStateChange,
    ) -> None:
        if state_change is not ServiceStateChange.Added:
            return

        try:
            info = zeroconf.get_service_info(service_type, name)
            if not info or not info.addresses:
                return

            # Extract IPv4 address
            ipv4_addrs = [
                socket.inet_ntoa(addr)
                for addr in info.addresses
                if len(addr) == 4
            ]
            if not ipv4_addrs:
                return

            ip = ipv4_addrs[0]

            # Decode TXT records properties
            properties = {}
            if info.properties:
                for k, v in info.properties.items():
                    key_str = k.decode("utf-8", errors="ignore") if isinstance(k, bytes) else str(k)
                    val_str = v.decode("utf-8", errors="ignore") if isinstance(v, bytes) else str(v)
                    properties[key_str] = val_str

            clean_server = info.server.rstrip(".") if info.server else ""
            clean_name = name.replace(f".{service_type}", "")

            if ip not in self.devices_by_ip:
                self.devices_by_ip[ip] = {
                    "ip": ip,
                    "mdns_name": clean_name,
                    "server": clean_server,
                    "services": set(),
                    "properties": {},
                    "port": info.port,
                }

            self.devices_by_ip[ip]["services"].add(service_type.replace(".local.", ""))
            self.devices_by_ip[ip]["properties"].update(properties)
            if clean_server and not self.devices_by_ip[ip]["server"]:
                self.devices_by_ip[ip]["server"] = clean_server

        except Exception:
            pass


async def scan_mdns(timeout: float = 3.0) -> Dict[str, Dict]:
    """Passively listen for mDNS services on the LAN for specified duration."""
    collector = MDNSCollector()
    aiozc = AsyncZeroconf(ip_version=IPVersion.V4Only)

    try:
        browser = AsyncServiceBrowser(
            aiozc.zeroconf,
            COMMON_SERVICES,
            handlers=[collector.on_service_state_change]
        )
        await asyncio.sleep(timeout)
        await browser.async_cancel()
    except Exception:
        pass
    finally:
        await aiozc.async_close()

    # Convert sets to lists for JSON serialization
    results = {}
    for ip, data in collector.devices_by_ip.items():
        results[ip] = {
            "ip": data["ip"],
            "mdns_name": data["mdns_name"],
            "server": data["server"],
            "services": sorted(list(data["services"])),
            "properties": data["properties"],
            "port": data["port"],
        }
    return results


if __name__ == "__main__":
    async def main():
        print("Listening for mDNS devices (3s)...")
        results = await scan_mdns(timeout=3.0)
        print(f"Discovered {len(results)} hosts via mDNS:")
        for ip, d in results.items():
            print(f" - {ip}: {d['mdns_name']} (Server: {d['server']}) Services: {d['services']}")
    asyncio.run(main())
