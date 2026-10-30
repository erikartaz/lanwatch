"""Telegram bot notifications for LANWatch events."""

import asyncio
import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional
import urllib.request
import urllib.parse

logger = logging.getLogger(__name__)

from lanscanner.core.storage import DB_PATH as CONFIG_DB


def get_telegram_config(db_path: Path = CONFIG_DB):
    """Retrieve Telegram config from DB."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value TEXT)")
    try:
        cur.execute("SELECT value FROM app_config WHERE key = 'telegram_bot_token'")
        r = cur.fetchone()
        token = r[0] if r else None
        cur.execute("SELECT value FROM app_config WHERE key = 'telegram_chat_id'")
        r = cur.fetchone()
        chat_id = r[0] if r else None
        cur.execute("SELECT value FROM app_config WHERE key = 'telegram_enabled'")
        r = cur.fetchone()
        enabled = (r[0] == '1') if r else False
    finally:
        conn.close()
    return token, chat_id, enabled


def set_telegram_config(bot_token: str, chat_id: str, enabled: bool = True, db_path: Path = CONFIG_DB):
    """Save Telegram config to DB."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value TEXT)")
    for k, v in [('telegram_bot_token', bot_token), ('telegram_chat_id', chat_id), ('telegram_enabled', '1' if enabled else '0')]:
        cur.execute("INSERT OR REPLACE INTO app_config (key, value) VALUES (?, ?)", (k, v))
    conn.commit()
    conn.close()


def send_telegram_message(text: str) -> bool:
    """Send a message via Telegram Bot API. Returns True on success."""
    token, chat_id, enabled = get_telegram_config()
    if not enabled or not token or not chat_id:
        return False
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = urllib.parse.urlencode({
            'chat_id': chat_id,
            'text': text,
            'parse_mode': 'HTML'
        }).encode('utf-8')
        req = urllib.request.Request(url, data=data, method='POST')
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception as e:
        logger.warning(f"Telegram notification failed: {e}")
        return False


def notify_new_device(mac: str, ip: str, name: str, category: str = ''):
    """Send notification for a newly discovered device."""
    msg = (
        f"🔔 <b>LANWatch – Nuovo Dispositivo</b>\n\n"
        f"📍 IP: <code>{ip}</code>\n"
        f"🔌 MAC: <code>{mac}</code>\n"
        f"📛 Nome: {name}\n"
        f"🏷️ Categoria: {category or 'Sconosciuta'}\n"
        f"🕐 {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}"
    )
    send_telegram_message(msg)


def notify_security_alert(title: str, severity: str, device_ip: str, description: str):
    """Send notification for a security finding."""
    emoji = {'CRITICO': '🚨', 'ALTO': '⚠️', 'MEDIO': '🔶', 'BASSO': 'ℹ️'}.get(severity, '⚠️')
    msg = (
        f"{emoji} <b>LANWatch – Alert Sicurezza</b>\n\n"
        f"<b>{title}</b> [{severity}]\n"
        f"📍 Dispositivo: <code>{device_ip}</code>\n"
        f"📝 {description}\n"
        f"🕐 {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}"
    )
    send_telegram_message(msg)
