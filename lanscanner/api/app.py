"""FastAPI Application providing REST API and WebSockets for LANScanner."""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from lanscanner.core.diagnostics import (
    get_network_connection_health,
    measure_ping_latency,
    send_wake_on_lan,
)
from lanscanner.core.network import detect_network
from lanscanner.core.scanner import scanner_instance
from lanscanner.core.storage import (
    get_all_devices,
    get_device_by_mac,
    get_recent_events,
    init_db,
    set_device_trusted,
    update_device_customization,
)

app = FastAPI(
    title="LANWatch - Home LAN Sentinel",
    description="Web App per l'inventario tecnico dettagliato e security assessment passivo della LAN casalinga",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).parent.parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)


class DeviceUpdateRequest(BaseModel):
    custom_name: Optional[str] = None
    category: Optional[str] = None
    notes: Optional[str] = None
    parent_mac: Optional[str] = None


class DeviceTrustRequest(BaseModel):
    is_trusted: bool


class TelegramConfigRequest(BaseModel):
    bot_token: str
    chat_id: str
    enabled: bool = True


class AutoScanConfigRequest(BaseModel):
    enabled: bool = True
    interval_minutes: int = 5


class ConnectionManager:
    """Manages active WebSocket connections for live scan progress."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)


ws_manager = ConnectionManager()


async def background_auto_scanner():
    """Background sentinel running periodic LAN scans to detect new devices and changes."""
    await asyncio.sleep(8)
    while True:
        try:
            from lanscanner.core.storage import get_app_config
            enabled = get_app_config("auto_scan_enabled", "1") == "1"
            interval_min = int(get_app_config("auto_scan_interval", "5") or "5")
            if interval_min < 1:
                interval_min = 5
        except Exception:
            enabled = True
            interval_min = 5

        if enabled and not scanner_instance.is_scanning:
            try:
                def progress_cb(msg: str, percent: int):
                    asyncio.create_task(ws_manager.broadcast({
                        "type": "scan_progress",
                        "message": msg,
                        "percent": percent,
                        "is_auto": True
                    }))

                await scanner_instance.run_full_scan(progress_callback=progress_cb)

                await ws_manager.broadcast({
                    "type": "scan_complete",
                    "is_auto": True,
                    "timestamp": datetime.now().isoformat()
                })
            except Exception as err:
                print(f"[AutoScanner] Errore scansione automatica: {err}")

        total_seconds = interval_min * 60
        elapsed = 0
        while elapsed < total_seconds:
            await asyncio.sleep(5)
            elapsed += 5
            try:
                from lanscanner.core.storage import get_app_config
                cur_enabled = get_app_config("auto_scan_enabled", "1") == "1"
                cur_interval = int(get_app_config("auto_scan_interval", "5") or "5")
                if not cur_enabled:
                    await asyncio.sleep(10)
                    break
                if cur_interval != interval_min:
                    break
            except Exception:
                pass


@app.on_event("startup")
async def startup_event():
    init_db()
    asyncio.create_task(background_auto_scanner())


@app.get("/api/network")
async def get_network():
    """Retrieve current network configuration."""
    net = detect_network()
    return net


@app.get("/api/devices")
async def list_devices(
    category: Optional[str] = None,
    search: Optional[str] = None,
    online_only: bool = False,
    offline_only: bool = False,
):
    """Retrieve all devices in inventory with optional filters."""
    devices = get_all_devices()
    net = detect_network()
    gw_ip = net.get("gateway") if net else None
    for d in devices:
        d["is_gateway"] = bool((gw_ip and d.get("ip") == gw_ip) or d.get("ip") == "192.168.1.254")

    if category:
        devices = [d for d in devices if d.get("category") == category]

    if online_only:
        devices = [d for d in devices if d.get("is_online")]

    if offline_only:
        devices = [d for d in devices if not d.get("is_online")]

    if search:
        s = search.lower()
        devices = [
            d for d in devices
            if s in (d.get("ip") or "").lower()
            or s in (d.get("mac") or "").lower()
            or s in (d.get("vendor") or "").lower()
            or s in (d.get("hostname") or "").lower()
            or s in (d.get("custom_name") or "").lower()
        ]

    return devices


@app.get("/api/devices/{mac}")
async def get_device(mac: str):
    """Retrieve technical specs and assessment details for a single device."""
    dev = get_device_by_mac(mac)
    if not dev:
        raise HTTPException(status_code=404, detail="Dispositivo non trovato")
    return dev


@app.patch("/api/devices/{mac}")
async def update_device(mac: str, payload: DeviceUpdateRequest):
    """Update or clear custom name, category override, or personal notes."""
    dev = get_device_by_mac(mac)
    if not dev:
        raise HTTPException(status_code=404, detail="Dispositivo non trovato")

    fields_set = payload.model_fields_set

    update_device_customization(
        mac=mac,
        custom_name=payload.custom_name,
        update_name="custom_name" in fields_set,
        category=payload.category,
        update_category="category" in fields_set,
        notes=payload.notes,
        update_notes="notes" in fields_set,
        parent_mac=payload.parent_mac,
        update_parent="parent_mac" in fields_set,
    )
    return {"status": "updated", "mac": mac}


@app.post("/api/devices/{mac}/trust")
async def toggle_trust(mac: str, payload: DeviceTrustRequest):
    """Toggle trusted status for a device."""
    dev = get_device_by_mac(mac)
    if not dev:
        raise HTTPException(status_code=404, detail="Dispositivo non trovato")
    set_device_trusted(mac, payload.is_trusted)
    return {"status": "updated", "mac": mac, "is_trusted": payload.is_trusted}


@app.post("/api/devices/{mac}/wake")
async def wake_device(mac: str):
    """Send Wake-on-LAN magic packet to wake a device."""
    dev = get_device_by_mac(mac)
    if not dev:
        raise HTTPException(status_code=404, detail="Dispositivo non trovato")
    success = send_wake_on_lan(mac)
    if not success:
        raise HTTPException(status_code=500, detail="Impossibile inviare il pacchetto Wake-on-LAN")
    return {"status": "sent", "mac": mac, "message": "Pacchetto Magic Wake-on-LAN inviato"}


@app.get("/api/devices/{mac}/ping")
async def ping_device(mac: str):
    """Measure real-time ping latency to a device."""
    dev = get_device_by_mac(mac)
    if not dev:
        raise HTTPException(status_code=404, detail="Dispositivo non trovato")
    latency = await measure_ping_latency(dev["ip"], timeout_ms=800)
    return {
        "mac": mac,
        "ip": dev["ip"],
        "online": latency is not None,
        "latency_ms": latency,
    }


@app.get("/api/network/health")
async def get_network_health():
    """Retrieve gateway and internet latency metrics."""
    net = detect_network()
    gw_ip = net.get("gateway") or "192.168.1.1"
    health = await get_network_connection_health(gw_ip)
    return {**health, "gateway_ip": gw_ip}


@app.post("/api/scan")
async def trigger_scan():
    """Trigger a passive multi-protocol LAN scan in background."""
    if scanner_instance.is_scanning:
        return {"status": "already_scanning", "message": "Scansione già in corso"}

    async def scan_task():
        def progress_cb(msg: str, percent: int):
            asyncio.create_task(
                ws_manager.broadcast({
                    "type": "scan_progress",
                    "message": msg,
                    "percent": percent,
                })
            )

        result = await scanner_instance.run_full_scan(progress_callback=progress_cb)
        await ws_manager.broadcast({
            "type": "scan_complete",
            "data": {
                "devices_count": len(result.get("devices", [])),
                "assessment": result.get("assessment"),
            }
        })

    asyncio.create_task(scan_task())
    return {"status": "started", "message": "Scansione passiva avviata"}


@app.get("/api/security/assessment")
async def get_security_assessment():
    """Retrieve the latest passive security evaluation, synced with user custom names."""
    if scanner_instance.last_assessment:
        assessment = scanner_instance.last_assessment
    else:
        # Compute from current database
        devices = get_all_devices()
        net = detect_network()
        gw_ip = net.get("gateway") if net else None
        for d in devices:
            d["is_gateway"] = bool((gw_ip and d.get("ip") == gw_ip) or d.get("ip") == "192.168.1.254")
        from lanscanner.core.security import evaluate_security_assessment
        assessment = evaluate_security_assessment(devices, net)

    # Always ensure target_device reflects user custom_name and custom_category overrides
    db_devices_map = {d["mac"]: d for d in get_all_devices()}
    for f in assessment.get("findings", []):
        t = f.get("target_device")
        if t and isinstance(t, dict):
            dev = db_devices_map.get(t.get("mac"))
            if dev:
                if dev.get("custom_name"):
                    t["name"] = dev["custom_name"]
                if dev.get("category"):
                    t["category"] = dev["category"]

    return assessment


@app.get("/api/events")
async def list_events(limit: int = 40):
    """Retrieve recent network events."""
    return get_recent_events(limit=limit)


@app.get("/api/devices/{mac}/history")
async def get_device_history(mac: str, hours: int = 24):
    """Retrieve presence history events for a specific device."""
    from lanscanner.core.storage import get_device_presence_history
    return get_device_presence_history(mac, hours)


@app.get("/api/settings/telegram")
async def get_telegram_settings():
    """Retrieve Telegram notification configuration."""
    from lanscanner.core.telegram_notify import get_telegram_config
    token, chat_id, enabled = get_telegram_config()
    return {"configured": bool(token and chat_id), "chat_id": chat_id or "", "enabled": enabled, "has_token": bool(token)}


@app.post("/api/settings/telegram")
async def save_telegram_settings(req: TelegramConfigRequest):
    """Save and test Telegram notification configuration."""
    from lanscanner.core.telegram_notify import set_telegram_config, send_telegram_message
    set_telegram_config(req.bot_token, req.chat_id, req.enabled)
    ok = send_telegram_message("✅ <b>LANWatch</b> – Notifiche Telegram configurate correttamente!")
    return {"ok": True, "test_sent": ok}


@app.get("/api/config/autoscan")
async def get_autoscan_config():
    """Retrieve auto-scan background configuration."""
    from lanscanner.core.storage import get_app_config
    enabled = get_app_config("auto_scan_enabled", "1") == "1"
    interval = int(get_app_config("auto_scan_interval", "5") or "5")
    last_scan_iso = scanner_instance.last_scan_time.isoformat() if scanner_instance.last_scan_time else None
    return {
        "enabled": enabled,
        "interval_minutes": interval,
        "is_scanning": scanner_instance.is_scanning,
        "last_scan": last_scan_iso,
    }


@app.post("/api/config/autoscan")
async def save_autoscan_config(req: AutoScanConfigRequest):
    """Save auto-scan background configuration."""
    from lanscanner.core.storage import set_app_config
    set_app_config("auto_scan_enabled", "1" if req.enabled else "0")
    interv = max(1, min(1440, req.interval_minutes))
    set_app_config("auto_scan_interval", str(interv))
    return {"status": "saved", "enabled": req.enabled, "interval_minutes": interv}


@app.get("/api/export/report.json")
async def export_json_report():
    """Export complete inventory and security posture as JSON."""
    devices = get_all_devices()
    net = detect_network()
    gw_ip = net.get("gateway") if net else None
    for d in devices:
        d["is_gateway"] = bool((gw_ip and d.get("ip") == gw_ip) or d.get("ip") == "192.168.1.254")
    from lanscanner.core.security import evaluate_security_assessment
    assessment = evaluate_security_assessment(devices, net)

    report_data = {
        "report_title": "LANWatch Home Network Inventory & Passive Security Audit",
        "generated_at": net.get("timestamp"),
        "network_environment": net,
        "security_assessment": assessment,
        "inventory": devices,
    }
    return JSONResponse(
        content=report_data,
        headers={"Content-Disposition": 'attachment; filename="lan_security_audit.json"'},
    )


@app.get("/api/database/backup")
async def backup_database():
    """Download current SQLite database file."""
    from lanscanner.core.storage import DB_PATH
    if not DB_PATH.exists():
        raise HTTPException(status_code=404, detail="Database non trovato")
    return FileResponse(
        path=str(DB_PATH),
        filename="lanscanner.db",
        media_type="application/x-sqlite3"
    )


@app.post("/api/database/restore")
async def restore_database(request: Request):
    """Upload and restore a SQLite database file via raw octet-stream."""
    import shutil
    import sqlite3
    from lanscanner.core.storage import DB_PATH

    body = await request.body()
    if not body or len(body) < 100:
        raise HTTPException(status_code=400, detail="File database vuoto o corrotto")

    if not body.startswith(b"SQLite format 3\x00"):
        raise HTTPException(
            status_code=400,
            detail="Il file caricato non sembra essere un database SQLite valido (firma mancante)."
        )

    temp_path = DB_PATH.with_suffix(".upload_tmp")
    try:
        with open(temp_path, "wb") as f:
            f.write(body)

        # Verify it is a valid SQLite DB with the devices table
        test_conn = sqlite3.connect(temp_path)
        test_cur = test_conn.cursor()
        test_cur.execute("SELECT count(*) FROM devices")
        count = test_cur.fetchone()[0]
        test_conn.close()

        # Atomic replace
        if DB_PATH.exists():
            backup_old = DB_PATH.with_suffix(".bak")
            shutil.copy2(DB_PATH, backup_old)
        shutil.move(temp_path, DB_PATH)

        return {"status": "success", "message": f"Database ripristinato con successo! ({count} dispositivi caricati)"}
    except Exception as e:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass
        raise HTTPException(status_code=400, detail=f"File database non valido: {e}")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time websocket channel for scan progress and notifications."""
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keepalive listener
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


# Serve static web frontend
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def root():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse("<h1>LANWatch Backend is Running!</h1><p>Frontend static files loading...</p>")
