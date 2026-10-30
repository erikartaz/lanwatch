"""NetBIOS Name Service (NBNS) Node Status Query (UDP 137)."""

import asyncio
import socket
from typing import Dict, Optional
from lanscanner.core.oui import normalize_mac

# Standard NetBIOS wildcard query for '*'
# Transaction ID: 0x9999, Flags: 0x0000 (Query), Questions: 1
# Encoded name '*' (CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
# Type: 0x0021 (NBSTAT), Class: 0x0001 (IN)
NBNS_QUERY_PACKET = bytes.fromhex(
    "99990000000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001"
)


def _parse_nbns_response(data: bytes) -> Optional[Dict[str, any]]:
    """Parse NetBIOS Node Status response payload."""
    try:
        # Minimum packet size
        if len(data) < 56:
            return None

        # Number of names is at offset 56
        num_names = data[56]
        offset = 57

        computer_name = None
        workgroup = None
        user_name = None
        mac_addr = None

        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            raw_name = data[offset : offset + 15].decode("ascii", errors="ignore").strip()
            name_type = data[offset + 15]
            flags = int.from_bytes(data[offset + 16 : offset + 18], "big")
            is_group = bool(flags & 0x8000)

            if not is_group and name_type == 0x00 and not computer_name:
                computer_name = raw_name
            elif is_group and name_type == 0x00 and not workgroup:
                workgroup = raw_name
            elif not is_group and name_type == 0x03 and not user_name:
                user_name = raw_name

            offset += 18

        # Following names, 6 bytes are the MAC address
        if offset + 6 <= len(data):
            raw_mac = ":".join(f"{b:02X}" for b in data[offset : offset + 6])
            mac_addr = normalize_mac(raw_mac)

        return {
            "computer_name": computer_name,
            "workgroup": workgroup,
            "user_name": user_name,
            "netbios_mac": mac_addr,
        }
    except Exception:
        return None


async def query_netbios(ip: str, timeout: float = 0.5) -> Optional[Dict[str, any]]:
    """Query a single IP for NetBIOS node status."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)

    try:
        sock.sendto(NBNS_QUERY_PACKET, (ip, 137))
        data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 1024), timeout=timeout)
        return _parse_nbns_response(data)
    except Exception:
        return None
    finally:
        sock.close()


async def scan_netbios_hosts(ips: list[str], concurrency: int = 30) -> Dict[str, Dict]:
    """Query NetBIOS status for a list of IPs concurrently."""
    results = {}
    sem = asyncio.Semaphore(concurrency)

    async def worker(ip: str):
        async with sem:
            res = await query_netbios(ip, timeout=0.6)
            if res and (res.get("computer_name") or res.get("workgroup")):
                results[ip] = res

    await asyncio.gather(*(worker(ip) for ip in ips), return_exceptions=True)
    return results


if __name__ == "__main__":
    async def main():
        from lanscanner.core.network import detect_network
        from lanscanner.core.arp import discover_arp_devices
        net = detect_network()
        devs = await discover_arp_devices(net["cidr"], active_sweep=False)
        ips = [d["ip"] for d in devs]
        print(f"Querying NetBIOS for {len(ips)} hosts...")
        res = await scan_netbios_hosts(ips)
        print(f"Discovered {len(res)} hosts with NetBIOS:")
        for ip, d in res.items():
            print(f" - {ip}: Computer='{d['computer_name']}', Workgroup='{d['workgroup']}'")
    asyncio.run(main())
