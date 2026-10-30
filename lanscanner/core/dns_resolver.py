"""Reverse DNS (PTR) and hostname resolver."""

import asyncio
import socket
from typing import Dict, List, Optional


async def resolve_ptr(ip: str, timeout: float = 0.8) -> Optional[str]:
    """Resolve reverse DNS hostname for an IP address asynchronously."""
    def _lookup():
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            return name
        except Exception:
            return None

    try:
        return await asyncio.wait_for(asyncio.to_thread(_lookup), timeout=timeout)
    except Exception:
        return None


async def resolve_hostnames(ips: List[str], concurrency: int = 25) -> Dict[str, Optional[str]]:
    """Resolve hostnames for a list of IPs concurrently."""
    results = {}
    sem = asyncio.Semaphore(concurrency)

    async def worker(ip: str):
        async with sem:
            name = await resolve_ptr(ip)
            if name:
                results[ip] = name

    await asyncio.gather(*(worker(ip) for ip in ips), return_exceptions=True)
    return results


if __name__ == "__main__":
    async def main():
        test_ips = ["192.168.1.254", "192.168.1.82", "192.168.1.51"]
        res = await resolve_hostnames(test_ips)
        print("Reverse DNS results:")
        for ip, name in res.items():
            print(f" - {ip} -> {name}")
    asyncio.run(main())
