"""ARP table reader and non-intrusive subnet sweep."""

import asyncio
import ipaddress
import platform
import re
import socket
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
from lanscanner.core.oui import normalize_mac


def parse_arp_table(target_network: Optional[str] = None) -> List[Dict[str, str]]:
    """Parse local system ARP table via /proc/net/arp (Linux) or arp -a command, optionally filtering by target network CIDR."""
    results: List[Dict[str, str]] = []

    net_filter = None
    if target_network:
        try:
            net_filter = ipaddress.IPv4Network(target_network, strict=False)
        except Exception:
            pass

    # Method 1: On Linux systems/containers, /proc/net/arp provides direct kernel access with 0 latency
    proc_arp = Path("/proc/net/arp")
    if proc_arp.exists():
        try:
            with open(proc_arp, "r") as f:
                lines = f.readlines()[1:]  # Skip header
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        raw_mac = parts[3]
                        mac = normalize_mac(raw_mac)
                        if not mac or mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                            continue
                        if net_filter:
                            try:
                                if ipaddress.IPv4Address(ip) not in net_filter:
                                    continue
                            except Exception:
                                continue
                        results.append({
                            "ip": ip,
                            "mac": mac,
                            "type": "dynamic"
                        })
            if results:
                seen = {}
                for r in results:
                    seen[r["ip"]] = r
                return list(seen.values())
        except Exception:
            pass

    # Method 2: Standard arp -a command (Windows and Linux fallback)
    try:
        output = subprocess.check_output(
            ["arp", "-a"], text=True, stderr=subprocess.DEVNULL, errors="ignore"
        )
    except Exception:
        return results

    # Regular expression for matching IP and MAC
    ip_mac_pattern = re.compile(
        r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
        r"[\s\(\)]+"
        r"([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})"
    )

    for line in output.splitlines():
        match = ip_mac_pattern.search(line)
        if match:
            ip = match.group(1)
            raw_mac = match.group(2)
            mac = normalize_mac(raw_mac)

            # Skip multicast, broadcast, and virtual VPN dummy MACs (e.g. NordVPN/Wireguard 02:50:41:00:00:02)
            if not mac or mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00", "02:50:41:00:00:02"):
                continue
            if mac.startswith("02:50:41"):  # Virtual VPN TAP dummy MAC
                continue
            if ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255"):
                continue

            # Subnet filter if provided
            if net_filter:
                try:
                    if ipaddress.IPv4Address(ip) not in net_filter:
                        continue
                except Exception:
                    continue

            results.append({
                "ip": ip,
                "mac": mac,
                "type": "dynamic" if "dynamic" in line.lower() else "static"
            })

    # Deduplicate by IP keeping latest MAC
    seen = {}
    for r in results:
        seen[r["ip"]] = r
    return list(seen.values())


async def _probe_single_host(ip: str, port: int = 80, timeout: float = 0.25):
    """Attempt a quick, non-intrusive TCP connection probe to trigger OS ARP cache resolution."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
    except Exception:
        # We don't care if the port is closed or connection times out;
        # the OS kernel sends an ARP Request packet regardless!
        pass


async def sweep_subnet(cidr: str, concurrency: int = 40):
    """Perform a gentle, asynchronous subnet sweep to populate OS ARP table."""
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
        hosts = [str(h) for h in network.hosts()]
    except Exception:
        return

    # Limit to maximum 256 hosts for home LAN to be fast and gentle
    if len(hosts) > 512:
        hosts = hosts[:512]

    semaphore = asyncio.Semaphore(concurrency)

    async def worker(ip: str):
        async with semaphore:
            # Probe standard HTTP, HTTPS and Smart TV / Google Cast ports
            await _probe_single_host(ip, port=80, timeout=0.20)
            await _probe_single_host(ip, port=8008, timeout=0.20)
            await _probe_single_host(ip, port=443, timeout=0.15)

    await asyncio.gather(*(worker(ip) for ip in hosts), return_exceptions=True)


async def discover_arp_devices(cidr: str, active_sweep: bool = True) -> List[Dict[str, str]]:
    """Discover devices by running gentle sweep and reading ARP table."""
    if active_sweep:
        await sweep_subnet(cidr)
        # Small delay to let kernel process ARP replies
        await asyncio.sleep(0.3)

    return parse_arp_table(target_network=cidr)


if __name__ == "__main__":
    async def main():
        from lanscanner.core.network import detect_network
        net = detect_network()
        print(f"Sweeping {net['cidr']}...")
        devs = await discover_arp_devices(net['cidr'])
        print(f"Found {len(devs)} devices via ARP:")
        for d in devs:
            print(f" - {d['ip']} ({d['mac']})")
    asyncio.run(main())
