"""Passive Security Assessment Engine for Home LAN."""

from typing import Dict, List, Optional


class SecurityRule:
    def __init__(
        self,
        rule_id: str,
        title: str,
        severity: str,
        category: str,
        score_penalty: int,
        description: str,
        risk_impact: str,
        remediation: str,
    ):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity  # "CRITICO", "ALTO", "MEDIO", "BASSO", "INFO"
        self.category = category
        self.score_penalty = score_penalty
        self.description = description
        self.risk_impact = risk_impact
        self.remediation = remediation


SECURITY_RULES = [
    SecurityRule(
        rule_id="SEC_TELNET_EXPOSED",
        title="Protocollo Telnet Non Cifrato Rilevato",
        severity="CRITICO",
        category="Protocolli Insicuri",
        score_penalty=25,
        description="È stata rilevata la porta 23 (Telnet) aperta. Telnet trasmette credenziali, comandi e dati in testo completamente in chiaro sulla LAN.",
        risk_impact="Chiunque sulla rete (o un malware su un altro host) può intercettare password e sessioni di amministrazione tramite semplice sniffing passivo dei pacchetti.",
        remediation="Disabilita il servizio Telnet sul dispositivo e utilizza esclusivamente SSH (porta 22) per l'amministrazione remota sicura con crittografia.",
    ),
    SecurityRule(
        rule_id="SEC_UPNP_IGD_ACTIVE",
        title="UPnP Internet Gateway Device (IGD) Abilitato sul Router",
        severity="ALTO",
        category="Configurazione Router",
        score_penalty=20,
        description="Il router domestico risponde agli annunci UPnP e implementa i servizi WANIPConnection/WANPPPConnection per l'apertura automatica di porte dall'interno verso Internet.",
        risk_impact="Software non autorizzati, trojan o dispositivi IoT compromessi sulla LAN possono aprire porte nel firewall del router verso l'esterno senza richiedere la password di amministrazione.",
        remediation="Accedi al pannello del tuo router (es. Vodafone Station / Fritz!Box) nella sezione Avanzate / Sicurezza e disattiva UPnP (o l'apertura automatica delle porte). Configura il port-forwarding solo manualmente per i servizi necessari.",
    ),
    SecurityRule(
        rule_id="SEC_CLEARTEXT_HTTP",
        title="Interfaccia di Gestione in Chiaro (HTTP senza HTTPS)",
        severity="MEDIO",
        category="Crittografia Web",
        score_penalty=10,
        description="Il dispositivo espone un pannello web su HTTP (porta 80 o 8080) senza forzare il reindirizzamento alla versione protetta HTTPS (porta 443).",
        risk_impact="Le credenziali di login (username e password) inserite nel browser vengono scambiate in chiaro e possono essere lette in caso di intercettazione locale.",
        remediation="Abilita l'accesso solo tramite HTTPS nelle impostazioni del dispositivo oppure non accedere al pannello di controllo se connesso a reti Wi-Fi non protette.",
    ),
    SecurityRule(
        rule_id="SEC_UNENCRYPTED_MQTT",
        title="Broker / Dispositivo IoT con MQTT Non Cifrato",
        severity="MEDIO",
        category="IoT & Domotica",
        score_penalty=12,
        description="È stato rilevato un servizio MQTT in chiaro (porta 1883) tipico dei dispositivi domotici e smart home.",
        risk_impact="I messaggi di stato dei sensori, delle prese e i comandi di accensione/spegnimento viaggiano senza crittografia e possono essere monitorati o alterati sulla rete locale.",
        remediation="Configura il broker MQTT (es. Mosquitto) per utilizzare MQTTS con crittografia TLS (porta 8883) e richiedere autenticazione con credenziali forti.",
    ),
    SecurityRule(
        rule_id="SEC_UNENCRYPTED_RTSP",
        title="Flusso Streaming RTSP di Videosorveglianza Aperto",
        severity="MEDIO",
        category="Privacy & Videosorveglianza",
        score_penalty=15,
        description="È stata rilevata la porta RTSP (554) aperta su una telecamera o dispositivo video.",
        risk_impact="Molte telecamere IP trasmettono il video in chiaro via RTSP senza autenticazione o con credenziali deboli, consentendo a terzi sulla LAN di visionare il feed delle telecamere.",
        remediation="Imposta una password robusta per l'accesso allo stream RTSP e inserisci le telecamere IP su una VLAN o Wi-Fi Guest isolata.",
    ),
    SecurityRule(
        rule_id="SEC_NETBIOS_EXPOSED",
        title="Protocollo Legacy NetBIOS / LLMNR Attivo",
        severity="BASSO",
        category="Risoluzione Nomi",
        score_penalty=8,
        description="Uno o più dispositivi rispondono a richieste NetBIOS Name Service (porta UDP 137), esponendo nome computer e gruppo di lavoro.",
        risk_impact="I protocolli broadcast storici di Windows (NetBIOS e LLMNR) sono vulnerabili ad attacchi di avvelenamento (LLMNR/NBT-NS Poisoning) tramite cui un attaccante può catturare gli hash NTLM degli utenti.",
        remediation="Su PC Windows: apri le proprietà della scheda di rete -> IPv4 -> Avanzate -> WINS e seleziona 'Disabilita NetBIOS su TCP/IP'.",
    ),
    SecurityRule(
        rule_id="SEC_IOT_FLAT_NETWORK",
        title="Mancata Segmentazione: Dispositivi IoT sulla Rete Principale",
        severity="MEDIO",
        category="Architettura di Rete",
        score_penalty=15,
        description="Sono presenti molteplici dispositivi IoT / Smart Home (lampadine, prese, speaker) sullo stesso segmento di rete dei computer personali o smartphone.",
        risk_impact="I dispositivi IoT hanno spesso firmware meno aggiornati. In caso di vulnerabilità su un singolo dispositivo smart, un attaccante potrebbe muoversi lateralmente verso i PC contenenti dati personali e documenti.",
        remediation="Crea una 'Rete Wi-Fi Ospiti' (Guest Network) sul router abilitando l'isolamento dei client e collega tutti i dispositivi IoT su quella rete, lasciando solo PC e telefoni sulla rete primaria.",
    ),
    SecurityRule(
        rule_id="SEC_FTP_EXPOSED",
        title="Server FTP Non Cifrato Rilevato",
        severity="ALTO",
        category="Trasferimento File",
        score_penalty=18,
        description="È stata rilevata la porta 21 (FTP) aperta. Il protocollo FTP classico trasferisce credenziali e file senza alcuna cifratura.",
        risk_impact="Password e file trasferiti possono essere intercettati passivamente da qualsiasi dispositivo sulla stessa rete.",
        remediation="Disabilita FTP e passa a SFTP (basato su SSH) o FTPS (FTP con crittografia SSL/TLS).",
    ),
]


def evaluate_security_assessment(devices: List[Dict], network_info: Dict) -> Dict:
    """Run passive security rules against all discovered devices and compute network posture."""
    findings = []
    total_penalty = 0

    gateway_ip = network_info.get("gateway")
    iot_count = 0
    personal_pc_count = 0

    rule_map = {r.rule_id: r for r in SECURITY_RULES}

    # Tracking per-device penalties
    device_penalties: Dict[str, int] = {d["mac"]: 0 for d in devices}
    device_findings: Dict[str, List[Dict]] = {d["mac"]: [] for d in devices}

    for d in devices:
        ip = d.get("ip") or ""
        mac = d.get("mac") or ""
        name = d.get("custom_name") or d.get("hostname") or d.get("vendor") or ip or "Dispositivo"
        category = d.get("category") or "Dispositivo"
        services = d.get("services") or []
        open_ports = [s["port"] for s in services if isinstance(s, dict) and "port" in s]
        meta = d.get("metadata") or {}
        ssdp = d.get("ssdp") or meta.get("ssdp") or {}
        upnp_info = ssdp.get("upnp_info") or {}
        netbios = d.get("netbios") or meta.get("netbios") or {}

        if category in ("IoT / Smart Home", "Assistente Vocale / Smart Speaker", "Telecamera IP / Videosorveglianza"):
            iot_count += 1
        elif category in ("Computer / Laptop", "Computer / PC Desktop", "Server / Homelab"):
            personal_pc_count += 1

        def add_finding_for_device(rule_id: str, extra_detail: str = ""):
            r = rule_map.get(rule_id)
            if not r:
                return
            device_penalties[mac] += r.score_penalty
            finding_entry = {
                "rule_id": r.rule_id,
                "title": r.title,
                "severity": r.severity,
                "category": r.category,
                "score_penalty": r.score_penalty,
                "description": r.description,
                "risk_impact": r.risk_impact,
                "remediation": r.remediation,
                "target_device": {
                    "ip": ip,
                    "mac": mac,
                    "name": name,
                    "category": category,
                },
                "extra_detail": extra_detail,
            }
            device_findings[mac].append(finding_entry)
            findings.append(finding_entry)

        # Check 1: Telnet
        if 23 in open_ports:
            add_finding_for_device("SEC_TELNET_EXPOSED", "Porta 23 aperta")

        # Check 2: FTP
        if 21 in open_ports:
            add_finding_for_device("SEC_FTP_EXPOSED", "Porta 21 aperta")

        # Check 3: Cleartext HTTP
        if (80 in open_ports or 8080 in open_ports or 8000 in open_ports) and 443 not in open_ports:
            add_finding_for_device("SEC_CLEARTEXT_HTTP", f"Porte web in chiaro rilevate: {[p for p in open_ports if p in (80, 8080, 8000)]}")

        # Check 4: Unencrypted MQTT
        if 1883 in open_ports:
            add_finding_for_device("SEC_UNENCRYPTED_MQTT", "Broker MQTT attivo sulla porta standard 1883")

        # Check 5: Unencrypted RTSP
        if 554 in open_ports:
            add_finding_for_device("SEC_UNENCRYPTED_RTSP", "Stream video RTSP accessibile sulla porta 554")

        # Check 6: UPnP IGD on Router
        if (ip == gateway_ip or "router" in (category or "").lower()) and upnp_info.get("has_upnp_igd"):
            add_finding_for_device("SEC_UPNP_IGD_ACTIVE", "Servizio WANIPConnection attivo via UPnP SSDP")

        # Check 7: NetBIOS
        if netbios and (netbios.get("computer_name") or netbios.get("workgroup")):
            add_finding_for_device("SEC_NETBIOS_EXPOSED", f"NetBIOS risponde con Workgroup: {netbios.get('workgroup')}")

    # Check 8: Network Segmentation (IoT + Workstations in same subnet)
    if iot_count >= 2 and personal_pc_count >= 1:
        r = rule_map.get("SEC_IOT_FLAT_NETWORK")
        findings.append({
            "rule_id": r.rule_id,
            "title": r.title,
            "severity": r.severity,
            "category": r.category,
            "score_penalty": r.score_penalty,
            "description": r.description,
            "risk_impact": r.risk_impact,
            "remediation": r.remediation,
            "target_device": {
                "ip": network_info.get("cidr"),
                "mac": "Broadcast Domain",
                "name": f"Subnet {network_info.get('cidr')}",
                "category": f"{iot_count} Dispositivi IoT + {personal_pc_count} PC/Server",
            },
            "extra_detail": f"Rilevati {iot_count} dispositivi IoT che condividono lo stesso dominio di broadcast dei personal computer.",
        })
        total_penalty += r.score_penalty

    # Aggregate penalties
    for p in device_penalties.values():
        total_penalty += min(p, 40)  # Cap penalty per device so a single device doesn't bring the whole score to zero

    global_score = max(10, 100 - min(total_penalty, 90))

    if global_score >= 85:
        grade = "A"
        health_label = "Ottima Sicurezza"
        color = "emerald"
    elif global_score >= 70:
        grade = "B"
        health_label = "Buona (Miglioramenti Possibili)"
        color = "blue"
    elif global_score >= 50:
        grade = "C"
        health_label = "Attenzione (Rischi Moderati)"
        color = "amber"
    else:
        grade = "D"
        health_label = "Critica (Configurazioni Insicure)"
        color = "rose"

    # Severity counts
    crit_count = sum(1 for f in findings if f["severity"] == "CRITICO")
    high_count = sum(1 for f in findings if f["severity"] == "ALTO")
    med_count = sum(1 for f in findings if f["severity"] == "MEDIO")
    low_count = sum(1 for f in findings if f["severity"] == "BASSO")

    # Calculate 5-Axis Radar Breakdown
    has_telnet = any(f["rule_id"] == "SEC_TELNET_EXPOSED" for f in findings)
    has_ftp = any(f["rule_id"] == "SEC_FTP_EXPOSED" for f in findings)
    has_upnp_igd = any(f["rule_id"] == "SEC_UPNP_IGD_ACTIVE" for f in findings)
    has_flat_iot = any(f["rule_id"] == "SEC_IOT_FLAT_NETWORK" for f in findings)
    cleartext_http_count = sum(1 for f in findings if f["rule_id"] == "SEC_CLEARTEXT_HTTP")
    netbios_count = sum(1 for f in findings if f["rule_id"] == "SEC_NETBIOS_EXPOSED")

    radar_web = max(25, 100 - (cleartext_http_count * 15))
    radar_iot = 40 if has_flat_iot else 100
    radar_gateway = 30 if has_upnp_igd else 100
    radar_remote = max(20, 100 - (50 if has_telnet else 0) - (35 if has_ftp else 0))
    radar_legacy = max(25, 100 - (netbios_count * 20))

    radar_data = {
        "labels": [
            "Crittografia Web",
            "Segmentazione IoT",
            "Sicurezza Gateway",
            "Accesso Remoto",
            "Protocolli Broadcast",
        ],
        "values": [radar_web, radar_iot, radar_gateway, radar_remote, radar_legacy],
    }

    return {
        "global_score": global_score,
        "grade": grade,
        "health_label": health_label,
        "color": color,
        "radar": radar_data,
        "counts": {
            "total": len(findings),
            "critico": crit_count,
            "alto": high_count,
            "medio": med_count,
            "basso": low_count,
        },
        "findings": findings,
        "iot_count": iot_count,
        "personal_pc_count": personal_pc_count,
        "device_scores": {
            mac: max(20, 100 - device_penalties[mac])
            for mac in device_penalties
        },
    }
