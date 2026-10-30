"""Device classification, category heuristics and OS fingerprinting."""

from typing import Dict, List, Optional


def classify_device(
    ip: str,
    gateway_ip: str,
    vendor: str,
    hostname: Optional[str] = None,
    netbios: Optional[Dict] = None,
    ssdp: Optional[Dict] = None,
    mdns: Optional[Dict] = None,
    services: Optional[List[Dict]] = None,
) -> Dict[str, str]:
    """Determine device type, category, estimated OS, friendly display name, and UI icon."""
    cat = "Dispositivo Sconosciuto"
    os_name = "Sconosciuto"
    icon = "help-circle"
    inferred_name = None

    vendor_lower = (vendor or "").lower()
    host_lower = (hostname or "").lower()
    services = services or []
    open_ports = [s["port"] for s in services]

    # Aggregate HTTP titles and banners
    titles = [s["title"].lower() for s in services if s.get("title")]
    raw_titles = [s["title"] for s in services if s.get("title")]
    all_titles_text = " ".join(titles)

    banners = [s["banner"].lower() for s in services if s.get("banner")]
    all_banners_text = " ".join(banners)

    certs = [s["cert_cn"].lower() for s in services if s.get("cert_cn")]
    all_certs_text = " ".join(certs)

    upnp_info = (ssdp or {}).get("upnp_info") or {}
    model_name = (upnp_info.get("model_name") or "").lower()
    friendly_name = (upnp_info.get("friendly_name") or "").lower()
    device_type_str = (upnp_info.get("device_type") or "").lower()

    nb_comp = ((netbios or {}).get("computer_name") or "").lower()
    nb_workgroup = ((netbios or {}).get("workgroup") or "").lower()

    # --- HEURISTIC MATCHING RULES (Prioritized) ---

    # 1. Proxmox Virtual Environment
    if "proxmox" in all_titles_text or "pve" in all_titles_text or 8006 in open_ports or "proxmox" in all_certs_text:
        cat = "Virtualizzazione / Server"
        os_name = "Debian Linux (Proxmox VE)"
        icon = "server"
        inferred_name = "Proxmox Virtual Environment (PVE)"

    # 2. Shinobi / CCTV / NVR Video Surveillance
    elif "shinobi" in all_titles_text or "frigate" in all_titles_text or "motioneye" in all_titles_text:
        cat = "NVR / Videosorveglianza"
        os_name = "Linux (Shinobi CCTV/NVR)"
        icon = "video"
        inferred_name = "Shinobi NVR Videosorveglianza"

    # 3. Network Printers (HP LaserJet, DeskJet, Epson, Brother, Canon)
    elif (
        "laserjet" in all_titles_text
        or "deskjet" in all_titles_text
        or "printer" in all_titles_text
        or "mfp" in all_titles_text
        or (9100 in open_ports and "hp" in vendor_lower)
    ):
        cat = "Stampante di Rete"
        os_name = "Firmware Stampante"
        icon = "printer"
        # If raw title contains model name (e.g. 'HP LaserJet MFP M28w 192.168.1.82'), use it!
        for t in raw_titles:
            if "hp" in t.lower() or "printer" in t.lower() or "laserjet" in t.lower():
                # Clean IP from title if present
                clean_t = t.replace(ip, "").strip()
                inferred_name = clean_t
                break

    # 4. Gateway / Router (Vodafone Station, Fritz!Box, TIM, GL.iNet Mango, etc.)
    elif (
        ip == gateway_ip
        or "vodafone station" in vendor_lower
        or "fritz!box" in vendor_lower
        or "vodafone" in nb_workgroup
        or "vodafone" in friendly_name
        or "router" in host_lower
        or "gateway" in host_lower
        or "gl.inet" in vendor_lower
        or "repeater" in vendor_lower
        or "mango" in host_lower
        or "repeater" in host_lower
    ):
        cat = "Router / Gateway"
        os_name = "Firmware Router (OpenWrt / Linux Embedded)"
        icon = "router"
        if "vodafone" in vendor_lower or "vodafone" in friendly_name or "vodafone" in nb_workgroup:
            inferred_name = "Vodafone Station (Router Gateway)"
        elif "fritz" in vendor_lower:
            inferred_name = "AVM FRITZ!Box"
        elif "gl.inet" in vendor_lower or "mango" in host_lower or "repeater" in vendor_lower:
            inferred_name = "GL.iNet Repeater Wi-Fi (Mango)"

    # 5. Home Assistant / Smart Home Controllers
    elif "home assistant" in all_titles_text or 8123 in open_ports or "hass" in host_lower:
        cat = "Hub Smart Home"
        os_name = "Home Assistant OS"
        icon = "home"
        inferred_name = "Home Assistant Hub"

    # 6. NAS / Storage (Synology, QNAP, TrueNAS, OpenMediaVault)
    elif "synology" in vendor_lower or "diskstation" in all_titles_text or "qnap" in vendor_lower or "truenas" in all_titles_text:
        cat = "NAS / Storage"
        os_name = "Linux NAS (DSM/TrueNAS)"
        icon = "hard-drive"
        inferred_name = "Network Attached Storage (NAS)"

    # 7. Proxmox Virtual Machine / Container (OUI Proxmox Server Solutions)
    elif "proxmox" in vendor_lower:
        cat = "Macchina Virtuale / Container"
        os_name = "Linux (Guest VM Proxmox)"
        icon = "layers"
        # If it has an HTTP title, use it!
        for t in raw_titles:
            if t and t.lower() not in ("login", "index", "home"):
                inferred_name = f"VM Proxmox ({t})"
                break

    # 8. Mini PC / Homelab Hardware (Shenzhen Maxtang, etc.)
    elif "maxtang" in vendor_lower or "minipc" in host_lower or "homelab" in host_lower:
        cat = "Server / Homelab"
        os_name = "Linux / Windows Server"
        icon = "server"
        inferred_name = "Mini PC Homelab Server"

    # 9. Amazon Echo / Fire TV / Smart Speakers / Kindle
    elif "amazon" in vendor_lower or "echo" in host_lower or "firetv" in host_lower or "alexa" in host_lower or "kindle" in host_lower:
        if "kindle" in host_lower or "paperwhite" in host_lower:
            cat = "E-Reader / Tablet"
            os_name = "Linux (Amazon Kindle OS)"
            icon = "book-open"
            inferred_name = "Amazon Kindle"
        elif "fire" in host_lower or "tv" in host_lower:
            cat = "Smart TV / Media Player"
            os_name = "FireOS (Android-based)"
            icon = "tv"
            inferred_name = "Amazon Fire TV Stick"
        else:
            cat = "Assistente Vocale / Smart Speaker"
            os_name = "Amazon Alexa OS"
            icon = "speaker"
            inferred_name = "Amazon Echo (Alexa)"

    # 10. Smart Home / IoT (Tuya, Espressif, Shelly, Sonoff, Trolink, Seongji, Philips Hue)
    elif (
        "tuya" in vendor_lower
        or "espressif" in vendor_lower
        or "trolink" in vendor_lower
        or "seongji" in vendor_lower
        or "shelly" in vendor_lower
        or "sonoff" in vendor_lower
        or "philips lighting" in vendor_lower
        or 1883 in open_ports
    ):
        cat = "IoT / Smart Home"
        os_name = "FreeRTOS / Embedded IoT"
        icon = "cpu"
        if "tuya" in vendor_lower:
            inferred_name = "Dispositivo Smart Tuya (Presa/Interruttore)"
        elif "trolink" in vendor_lower:
            inferred_name = "Modulo IoT / Telecamera Trolink"
        elif "seongji" in vendor_lower:
            inferred_name = "Modulo Smart Home Seongji"
        elif "espressif" in vendor_lower:
            inferred_name = "Dispositivo Smart (ESP8266/ESP32)"

    # 11. Apple Devices
    elif "apple" in vendor_lower:
        if "iphone" in host_lower:
            cat = "Smartphone"
            os_name = "Apple iOS"
            icon = "smartphone"
            inferred_name = "Apple iPhone"
        elif "ipad" in host_lower:
            cat = "Tablet"
            os_name = "Apple iPadOS"
            icon = "tablet"
            inferred_name = "Apple iPad"
        elif "mac" in host_lower or "macbook" in host_lower or "imac" in host_lower:
            cat = "Computer / Laptop"
            os_name = "macOS"
            icon = "laptop"
            inferred_name = "Apple Mac"
        elif "apple tv" in host_lower or "appletv" in host_lower:
            cat = "Smart TV / Media Player"
            os_name = "Apple tvOS"
            icon = "tv"
            inferred_name = "Apple TV"
        elif "homepod" in host_lower:
            cat = "Smart Speaker"
            os_name = "Apple audioOS"
            icon = "speaker"
            inferred_name = "Apple HomePod"
        else:
            cat = "Dispositivo Apple"
            os_name = "Apple Darwin (iOS/macOS)"
            icon = "smartphone"
            inferred_name = "Dispositivo Apple"

    # 12. Smart TVs & Streaming Devices (Xiaomi Mi TV Stick, Chromecast, Fire TV, Apple TV, Smart TVs)
    elif (
        "tv" in host_lower
        or "tv" in model_name
        or "tv" in friendly_name
        or "mitv" in model_name
        or "chromecast" in model_name
        or "chromecast" in all_banners_text
        or "mediaserver" in device_type_str
        or 8008 in open_ports
        or ("samsung" in vendor_lower and ("tv" in host_lower or "tizen" in host_lower))
        or ("lg electronics" in vendor_lower and ("webos" in host_lower or "tv" in host_lower))
    ):
        cat = "Smart TV / Media Player"
        if "mitv" in model_name or "xiaomi" in friendly_name or "xiaomi" in vendor_lower or "chiavetta" in friendly_name or "chiavetta" in host_lower:
            os_name = "Android TV (Xiaomi Mi TV)"
            inferred_name = "Xiaomi Mi TV Stick"
        elif "fire" in host_lower or "fire" in friendly_name:
            os_name = "FireOS (Amazon Fire TV)"
            inferred_name = "Amazon Fire TV Stick"
        elif "chromecast" in model_name or "chromecast" in friendly_name:
            os_name = "Google Cast / Android TV"
            inferred_name = "Google Chromecast"
        else:
            os_name = "Smart TV OS (Android TV / Tizen / webOS)"
            inferred_name = friendly_name if friendly_name else "Smart TV / Media Player"
        icon = "tv"

    # 13. Mobile Devices with Randomized MAC vs Virtual/Container Interface
    elif "mac casuale" in vendor_lower or "dispositivo mobile" in vendor_lower:
        # If it hosts a web server (80, 443, 8080) with a custom title or SSH, it's a Server/Container, not a phone!
        if (80 in open_ports or 443 in open_ports or 8080 in open_ports) and (all_titles_text or "nginx" in all_banners_text or "caddy" in all_banners_text or "apache" in all_banners_text):
            cat = "Server / Container Web"
            os_name = "Linux (Virtual / Container Interface)"
            icon = "server"
            inferred_name = raw_titles[0] if raw_titles else "Server Web Locale"
        elif 22 in open_ports:
            cat = "Server / Dispositivo Linux"
            os_name = "Linux (Virtual Interface)"
            icon = "server"
            inferred_name = "Host Linux (Virtual MAC)"
        else:
            cat = "Dispositivo Mobile (Smartphone/Tablet)"
            os_name = "Android / iOS (Privacy MAC)"
            icon = "smartphone"
            inferred_name = "Smartphone / Tablet (Privacy MAC)"

    # 14. Windows PC
    elif (
        nb_workgroup
        or "desktop-" in host_lower
        or "laptop-" in host_lower
        or (445 in open_ports and "linux" not in host_lower)
    ):
        cat = "Computer / PC Desktop"
        os_name = "Microsoft Windows"
        icon = "laptop"
        inferred_name = nb_comp.upper() if nb_comp else "Computer Windows"

    # 15. IP Camera (RTSP port 554)
    elif 554 in open_ports or "camera" in host_lower or "cam" in host_lower:
        cat = "Telecamera IP / Videosorveglianza"
        os_name = "Linux Embedded (IP Cam)"
        icon = "video"
        inferred_name = "Telecamera IP RTSP"

    # 16. Fallbacks
    elif 22 in open_ports:
        cat = "Server / Dispositivo Linux"
        os_name = "Linux (SSH)"
        icon = "server"
    elif 80 in open_ports or 443 in open_ports:
        cat = "Dispositivo Web / Rete"
        os_name = "Firmware con Web Server"
        icon = "globe"

    return {
        "category": cat,
        "os_family": os_name,
        "icon": icon,
        "inferred_name": inferred_name,
    }
