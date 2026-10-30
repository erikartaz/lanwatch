"""SQLite storage for device inventory, historical events, and scan results."""

import json
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

def _resolve_db_path() -> Path:
    custom_path = os.environ.get("LANWATCH_DB_PATH")
    if custom_path:
        p = Path(custom_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
    data_dir = os.environ.get("DATA_DIR")
    if data_dir:
        p = Path(data_dir) / "lanscanner.db"
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
    return Path("lanscanner.db")

DB_PATH = _resolve_db_path()


def init_db(db_path: Path = DB_PATH):
    """Initialize database tables for devices and events."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            vendor TEXT,
            hostname TEXT,
            custom_name TEXT,
            category TEXT,
            os_family TEXT,
            icon TEXT,
            is_online INTEGER DEFAULT 1,
            security_score INTEGER DEFAULT 100,
            first_seen TEXT,
            last_seen TEXT,
            services_json TEXT,
            metadata_json TEXT,
            notes TEXT,
            is_trusted INTEGER DEFAULT 0
        )
    """)

    # Schema migration: check if is_trusted and parent_mac columns exist
    cur.execute("PRAGMA table_info(devices)")
    columns = [row[1] for row in cur.fetchall()]
    if "is_trusted" not in columns:
        cur.execute("ALTER TABLE devices ADD COLUMN is_trusted INTEGER DEFAULT 0")
    if "parent_mac" not in columns:
        cur.execute("ALTER TABLE devices ADD COLUMN parent_mac TEXT DEFAULT NULL")
    if "custom_category" not in columns:
        cur.execute("ALTER TABLE devices ADD COLUMN custom_category TEXT DEFAULT NULL")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            mac TEXT,
            ip TEXT,
            message TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            total_devices INTEGER,
            global_score INTEGER,
            findings_count INTEGER,
            summary_json TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_config (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


CATEGORY_TO_ICON = {
    "Router / Gateway": "router",
    "Virtualizzazione / Server": "server",
    "NVR / Videosorveglianza": "video",
    "Server / Container Web": "server",
    "Macchina Virtuale / Container": "layers",
    "Server / Homelab": "server",
    "Computer / PC Desktop": "monitor",
    "Computer / Laptop": "laptop",
    "Dispositivo Mobile (Smartphone/Tablet)": "smartphone",
    "Smartphone": "smartphone",
    "Tablet": "tablet",
    "Assistente Vocale / Smart Speaker": "speaker",
    "Smart Speaker": "speaker",
    "IoT / Smart Home": "cpu",
    "Telecamera IP / Videosorveglianza": "video",
    "Smart TV / Media Player": "tv",
    "Stampante di Rete": "printer",
    "NAS / Storage": "hard-drive",
}


def save_or_update_device(device_data: Dict, db_path: Path = DB_PATH) -> bool:
    """Insert or update a discovered device. Returns True if device is brand new."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    mac = device_data["mac"]
    now_iso = datetime.now().isoformat()

    cur.execute("SELECT custom_name, notes, first_seen, is_trusted, custom_category, is_online FROM devices WHERE mac = ?", (mac,))
    existing = cur.fetchone()

    is_new = False
    custom_name = None
    notes = ""
    first_seen = now_iso
    is_trusted = 0
    custom_category = None

    # Auto-trust gateway and local machine by default
    if device_data.get("is_gateway") or device_data.get("is_local"):
        is_trusted = 1

    if existing:
        custom_name = existing[0]
        notes = existing[1] or ""
        first_seen = existing[2] or now_iso
        is_trusted = existing[3] if existing[3] is not None else is_trusted
        custom_category = existing[4]
        was_online = existing[5]
        if was_online == 0:
            cur.execute(
                "INSERT INTO events (timestamp, event_type, mac, ip, message) VALUES (?, ?, ?, ?, ?)",
                (now_iso, "DEVICE_ONLINE", mac, device_data["ip"], f"Dispositivo ricollegato in LAN: {custom_name or device_data.get('hostname') or mac}")
            )
    else:
        is_new = True
        # Log event
        cur.execute(
            "INSERT INTO events (timestamp, event_type, mac, ip, message) VALUES (?, ?, ?, ?, ?)",
            (now_iso, "NEW_DEVICE", mac, device_data["ip"], f"Nuovo dispositivo connesso: {device_data.get('hostname') or device_data.get('vendor') or mac}")
        )
        try:
            from lanscanner.core.telegram_notify import notify_new_device
            notify_new_device(
                mac=mac,
                ip=device_data["ip"],
                name=device_data.get('hostname') or device_data.get('vendor') or mac,
                category=device_data.get('category', '')
            )
        except Exception:
            pass

    services_json = json.dumps(device_data.get("services", []))
    metadata_json = json.dumps({
        "ssdp": device_data.get("ssdp"),
        "netbios": device_data.get("netbios"),
        "mdns": device_data.get("mdns"),
    })

    # An IP address cannot belong to two devices simultaneously on the same LAN subnet.
    # If another device in DB previously held this IP, mark it offline so it doesn't cause duplicates.
    cur.execute("UPDATE devices SET is_online = 0 WHERE ip = ? AND mac != ?", (device_data["ip"], mac))

    effective_category = custom_category or device_data.get("category")
    effective_icon = CATEGORY_TO_ICON.get(effective_category) or device_data.get("icon")
    effective_os = "Firmware Router (OpenWrt / Linux Embedded)" if effective_category == "Router / Gateway" else device_data.get("os_family")

    cur.execute("""
        INSERT INTO devices (
            mac, ip, vendor, hostname, custom_name, category, custom_category, os_family, icon,
            is_online, security_score, first_seen, last_seen, services_json, metadata_json, notes, is_trusted
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(mac) DO UPDATE SET
            ip = excluded.ip,
            vendor = COALESCE(excluded.vendor, devices.vendor),
            hostname = COALESCE(excluded.hostname, devices.hostname),
            category = COALESCE(devices.custom_category, excluded.category),
            os_family = CASE 
                WHEN devices.custom_category = 'Router / Gateway' THEN 'Firmware Router (OpenWrt / Linux Embedded)'
                WHEN devices.custom_category IS NOT NULL AND devices.os_family IS NOT NULL THEN devices.os_family 
                ELSE excluded.os_family 
            END,
            icon = CASE 
                WHEN devices.custom_category = 'Router / Gateway' THEN 'router'
                WHEN devices.custom_category = 'Virtualizzazione / Server' THEN 'server'
                WHEN devices.custom_category = 'Server / Homelab' THEN 'server'
                WHEN devices.custom_category = 'Stampante di Rete' THEN 'printer'
                WHEN devices.custom_category = 'Smart TV / Media Player' THEN 'tv'
                WHEN devices.custom_category = 'IoT / Smart Home' THEN 'cpu'
                WHEN devices.custom_category IS NOT NULL AND devices.icon IS NOT NULL THEN devices.icon 
                ELSE excluded.icon 
            END,
            is_online = 1,
            security_score = excluded.security_score,
            last_seen = excluded.last_seen,
            services_json = excluded.services_json,
            metadata_json = excluded.metadata_json
    """, (
        mac,
        device_data["ip"],
        device_data.get("vendor"),
        device_data.get("hostname"),
        custom_name or device_data.get("custom_name"),
        effective_category,
        custom_category,
        effective_os,
        effective_icon,
        1,
        device_data.get("security_score", 100),
        first_seen,
        now_iso,
        services_json,
        metadata_json,
        notes,
        is_trusted,
    ))

    conn.commit()
    conn.close()
    return is_new


def get_all_devices(db_path: Path = DB_PATH) -> List[Dict]:
    """Retrieve all devices from the database ordered by IP address."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM devices ORDER BY is_online DESC, last_seen DESC")
    rows = cur.fetchall()

    results = []
    for r in rows:
        d = dict(r)
        d["services"] = json.loads(d["services_json"]) if d.get("services_json") else []
        d["metadata"] = json.loads(d["metadata_json"]) if d.get("metadata_json") else {}
        results.append(d)

    conn.close()
    return results


def get_device_by_mac(mac: str, db_path: Path = DB_PATH) -> Optional[Dict]:
    """Retrieve a single device by MAC address."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM devices WHERE mac = ?", (mac,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return None

    d = dict(row)
    d["services"] = json.loads(d["services_json"]) if d.get("services_json") else []
    d["metadata"] = json.loads(d["metadata_json"]) if d.get("metadata_json") else {}
    return d


def set_device_trusted(mac: str, is_trusted: bool, db_path: Path = DB_PATH) -> bool:
    """Set or toggle trusted status for a device."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("UPDATE devices SET is_trusted = ? WHERE mac = ?", (1 if is_trusted else 0, mac))
    changed = cur.rowcount > 0
    conn.commit()
    conn.close()
    return changed


def update_device_customization(
    mac: str,
    custom_name: Optional[str] = None,
    update_name: bool = True,
    category: Optional[str] = None,
    update_category: bool = True,
    notes: Optional[str] = None,
    update_notes: bool = True,
    parent_mac: Optional[str] = None,
    update_parent: bool = False,
    db_path: Path = DB_PATH
):
    """Allow user to set or clear a friendly custom name, category override, notes, or topology parent node."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    updates = []
    params = []

    if update_name:
        updates.append("custom_name = ?")
        # If custom_name is empty string, whitespace, or None, explicitly clear it (store NULL)
        clean_name = custom_name.strip() if (custom_name and isinstance(custom_name, str)) else None
        params.append(clean_name if clean_name else None)

    if update_category:
        updates.append("category = ?")
        updates.append("custom_category = ?")
        clean_cat = category.strip() if (category and isinstance(category, str)) else None
        params.append(clean_cat)
        params.append(clean_cat)
        if clean_cat:
            icon_for_cat = CATEGORY_TO_ICON.get(clean_cat)
            if icon_for_cat:
                updates.append("icon = ?")
                params.append(icon_for_cat)
            if clean_cat == "Router / Gateway":
                updates.append("os_family = ?")
                params.append("Firmware Router (OpenWrt / Linux Embedded)")

    if update_notes:
        updates.append("notes = ?")
        params.append(notes.strip() if notes else "")

    if update_parent:
        updates.append("parent_mac = ?")
        clean_parent = parent_mac.strip().upper() if (parent_mac and isinstance(parent_mac, str) and parent_mac.strip().lower() != "auto") else None
        params.append(clean_parent)

    if updates:
        params.append(mac)
        cur.execute(f"UPDATE devices SET {', '.join(updates)} WHERE mac = ?", params)
        conn.commit()

    conn.close()


def save_scan_history(total_devices: int, global_score: int, findings_count: int, summary: Dict, db_path: Path = DB_PATH):
    """Save record of completed scan and assessment."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO scan_history (timestamp, total_devices, global_score, findings_count, summary_json)
        VALUES (?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        total_devices,
        global_score,
        findings_count,
        json.dumps(summary)
    ))
    conn.commit()
    conn.close()


def get_recent_events(limit: int = 50, db_path: Path = DB_PATH) -> List[Dict]:
    """Retrieve recent network events."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_device_presence_history(mac: str, hours: int = 24, db_path: Path = DB_PATH) -> List[Dict]:
    """Retrieve events for a specific device in the last N hours."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    cur.execute(
        "SELECT * FROM events WHERE mac = ? AND timestamp >= ? ORDER BY timestamp ASC",
        (mac, cutoff)
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def mark_offline_unseen_devices(active_macs: List[str], db_path: Path = DB_PATH):
    """Mark devices not in the active scan as offline and log event if state changed."""
    if not active_macs:
        return
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    placeholders = ",".join("?" for _ in active_macs)
    now_iso = datetime.now().isoformat()
    try:
        cur.execute(f"SELECT mac, ip, custom_name, hostname FROM devices WHERE is_online = 1 AND mac NOT IN ({placeholders})", active_macs)
        for row in cur.fetchall():
            d_mac, d_ip, d_custom_name, d_hostname = row
            name = d_custom_name or d_hostname or d_ip
            cur.execute(
                "INSERT INTO events (timestamp, event_type, mac, ip, message) VALUES (?, ?, ?, ?, ?)",
                (now_iso, "DEVICE_OFFLINE", d_mac, d_ip, f"Dispositivo disconnesso / fuori casa: {name}")
            )
    except Exception:
        pass

    cur.execute(f"UPDATE devices SET is_online = 0 WHERE mac NOT IN ({placeholders})", active_macs)
    conn.commit()
    conn.close()


def get_app_config(key: str, default: Optional[str] = None, db_path: Path = DB_PATH) -> Optional[str]:
    """Retrieve an application configuration value."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value TEXT)")
    cur.execute("SELECT value FROM app_config WHERE key = ?", (key,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row and row[0] is not None else default


def set_app_config(key: str, value: str, db_path: Path = DB_PATH):
    """Save or update an application configuration value."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value TEXT)")
    cur.execute("INSERT OR REPLACE INTO app_config (key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()
    conn.close()
