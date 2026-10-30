"""Network interface and subnet detection utilities."""

import ipaddress
import platform
import re
import socket
import subprocess
from typing import Dict, List, Optional


def get_local_ip_via_routing() -> Optional[str]:
    """Determine the primary local IPv4 address by inspecting routing socket."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        # 8.8.8.8 does not need to be reachable; this triggers OS routing table lookup
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return None


def get_windows_network_info() -> Dict[str, Optional[str]]:
    """Parse Windows ipconfig /all to detect active interface, IP, mask, and gateway."""
    info: Dict[str, Optional[str]] = {
        "ip": None,
        "mask": "255.255.255.0",
        "gateway": None,
        "interface": "Unknown",
        "mac": None,
    }

    try:
        output = subprocess.check_output(
            ["ipconfig", "/all"], text=True, stderr=subprocess.DEVNULL, errors="ignore"
        )
    except Exception:
        return info

    current_adapter = "Unknown"
    found_active = False

    adapter_blocks = output.split("\n\n")
    for block in adapter_blocks:
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        if not lines:
            continue

        header_match = re.search(r"^(?:Ethernet adapter|Wireless LAN adapter|Adapter)\s+([^:]+):", lines[0])
        if header_match:
            current_adapter = header_match.group(1).strip()

        block_ip = None
        block_mask = "255.255.255.0"
        block_gw = None
        block_mac = None

        for line in lines:
            # Physical Address / MAC
            mac_match = re.search(r"Physical Address[.\s]+:\s*([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})", line)
            if mac_match:
                block_mac = mac_match.group(1).replace("-", ":").upper()

            # IPv4 Address
            ip_match = re.search(r"IPv4 Address[.\s]+:\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", line)
            if ip_match:
                candidate_ip = ip_match.group(1)
                # Ignore 127.x.x.x or 169.254.x.x (APIPA)
                if not candidate_ip.startswith("127.") and not candidate_ip.startswith("169.254."):
                    block_ip = candidate_ip

            # Subnet Mask
            mask_match = re.search(r"Subnet Mask[.\s]+:\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", line)
            if mask_match:
                block_mask = mask_match.group(1)

            # Default Gateway
            gw_match = re.search(r"Default Gateway[.\s]+:\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", line)
            if gw_match and gw_match.group(1) != "0.0.0.0":
                block_gw = gw_match.group(1)

        # If this adapter has an IP and a Default Gateway, it's our primary interface
        if block_ip and block_gw:
            info["ip"] = block_ip
            info["mask"] = block_mask
            info["gateway"] = block_gw
            info["interface"] = current_adapter
            info["mac"] = block_mac
            found_active = True
            break
        elif block_ip and not found_active:
            # Fallback if no gateway is listed yet
            info["ip"] = block_ip
            info["mask"] = block_mask
            info["interface"] = current_adapter
            info["mac"] = block_mac

    return info


def get_linux_network_info() -> Dict[str, Optional[str]]:
    """Detect interface, gateway and MAC on Linux via /proc/net/route and sysfs."""
    info: Dict[str, Optional[str]] = {
        "gateway": None,
        "interface": "eth0",
        "mac": None,
    }
    try:
        with open("/proc/net/route", "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    info["interface"] = parts[0]
                    gw_hex = parts[2]
                    gw_ip = socket.inet_ntoa(bytes.fromhex(gw_hex)[::-1])
                    info["gateway"] = gw_ip
                    break
    except Exception:
        pass

    if info["interface"]:
        try:
            with open(f"/sys/class/net/{info['interface']}/address", "r") as f:
                raw_mac = f.read().strip().upper()
                if raw_mac and len(raw_mac) == 17:
                    info["mac"] = raw_mac
        except Exception:
            pass
    return info


def detect_network() -> Dict[str, str]:
    """Detect local network configuration (IP, subnet, CIDR, gateway, interface)."""
    detected_ip = get_local_ip_via_routing()
    mask = "255.255.255.0"
    gateway = None
    interface_name = "Primary LAN"
    local_mac = None

    if platform.system().lower() == "windows":
        win_info = get_windows_network_info()
        if win_info["ip"]:
            detected_ip = win_info["ip"]
        if win_info["mask"]:
            mask = win_info["mask"]
        if win_info["gateway"]:
            gateway = win_info["gateway"]
        if win_info["interface"]:
            interface_name = win_info["interface"]
        if win_info["mac"]:
            local_mac = win_info["mac"]
    else:
        linux_info = get_linux_network_info()
        if linux_info["gateway"]:
            gateway = linux_info["gateway"]
        if linux_info["interface"]:
            interface_name = linux_info["interface"]
        if linux_info["mac"]:
            local_mac = linux_info["mac"]

    if not detected_ip:
        detected_ip = "192.168.1.100"

    # Compute network CIDR
    try:
        network = ipaddress.IPv4Network(f"{detected_ip}/{mask}", strict=False)
        cidr = str(network)
    except Exception:
        cidr = "192.168.1.0/24"

    if not gateway:
        # Default fallback: .1 or .254
        net_obj = ipaddress.IPv4Network(cidr, strict=False)
        hosts = list(net_obj.hosts())
        gateway = str(hosts[0]) if hosts else "192.168.1.1"

    return {
        "ip": detected_ip,
        "mask": mask,
        "cidr": cidr,
        "gateway": gateway,
        "interface": interface_name,
        "mac": local_mac or "Unknown",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(detect_network(), indent=2))
