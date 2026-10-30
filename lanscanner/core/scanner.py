"""Scan orchestrator combining multi-protocol discovery and passive assessment."""

import asyncio
from datetime import datetime
from typing import Callable, Dict, List, Optional
from lanscanner.core.arp import _probe_single_host, discover_arp_devices, parse_arp_table
from lanscanner.core.dns_resolver import resolve_hostnames
from lanscanner.core.heuristics import classify_device
from lanscanner.core.netbios import scan_netbios_hosts
from lanscanner.core.network import detect_network
from lanscanner.core.oui import lookup_vendor
from lanscanner.core.security import evaluate_security_assessment
from lanscanner.core.services import scan_all_services
from lanscanner.core.ssdp import scan_ssdp
from lanscanner.core.storage import init_db, save_or_update_device, save_scan_history


class ScanCoordinator:
    def __init__(self):
        init_db()
        self.is_scanning = False
        self.last_scan_time: Optional[datetime] = None
        self.last_assessment: Optional[Dict] = None
        self.last_network_info: Optional[Dict] = None

    async def run_full_scan(self, progress_callback: Optional[Callable[[str, int], None]] = None) -> Dict:
        """Run complete passive multi-protocol discovery and security assessment."""
        if self.is_scanning:
            return {"status": "already_running"}

        self.is_scanning = True

        def report(msg: str, percent: int):
            if progress_callback:
                try:
                    progress_callback(msg, percent)
                except Exception:
                    pass

        try:
            # Step 1: Detect Network
            report("Rilevamento interfaccia e subnet...", 10)
            net_info = detect_network()
            self.last_network_info = net_info
            cidr = net_info["cidr"]
            local_ip = net_info["ip"]
            gateway_ip = net_info["gateway"]

            # Step 2: Gentle ARP Discovery Sweep
            report(f"Scansione passiva ARP sulla subnet {cidr}...", 25)
            arp_entries = await discover_arp_devices(cidr, active_sweep=True)

            # Ensure local machine and gateway are represented even if omitted by ARP table
            discovered_ips = {d["ip"] for d in arp_entries}
            if local_ip not in discovered_ips and net_info.get("mac") and net_info["mac"] != "Unknown":
                arp_entries.append({
                    "ip": local_ip,
                    "mac": net_info["mac"],
                    "type": "static"
                })

            ips = [d["ip"] for d in arp_entries]

            # Step 3: Run concurrent non-intrusive protocol discovery
            report(f"Interrogazione protocolli di rete (DNS, NetBIOS, SSDP)...", 45)
            dns_task = asyncio.create_task(resolve_hostnames(ips))
            netbios_task = asyncio.create_task(scan_netbios_hosts(ips))
            ssdp_task = asyncio.create_task(scan_ssdp(local_ip=local_ip, timeout=2.5))
            services_task = asyncio.create_task(scan_all_services(ips, max_hosts_concurrent=8))

            dns_map, netbios_map, ssdp_map, services_map = await asyncio.gather(
                dns_task, netbios_task, ssdp_task, services_task, return_exceptions=False
            )

            # If SSDP discovered active hosts on the subnet not yet in arp_entries (e.g. Wi-Fi sleeping device):
            discovered_ips = {d["ip"] for d in arp_entries}
            extra_ssdp_ips = [ip for ip in ssdp_map.keys() if ip not in discovered_ips and ip != "255.255.255.255"]
            if extra_ssdp_ips:
                for e_ip in extra_ssdp_ips:
                    await _probe_single_host(e_ip, port=8008, timeout=0.25)
                    await _probe_single_host(e_ip, port=80, timeout=0.20)
                await asyncio.sleep(0.15)
                refreshed_arp = parse_arp_table(target_network=cidr)
                refreshed_arp_map = {d["ip"]: d["mac"] for d in refreshed_arp}
                for e_ip in extra_ssdp_ips:
                    e_mac = refreshed_arp_map.get(e_ip)
                    if not e_mac:
                        # Synthetic stable MAC based on IP if bridge masks direct ARP
                        e_mac = f"02:00:{':'.join(f'{int(oct):02X}' for oct in e_ip.split('.'))}"
                    arp_entries.append({"ip": e_ip, "mac": e_mac, "type": "dynamic"})
                    extra_dns = await resolve_hostnames([e_ip])
                    dns_map.update(extra_dns)
                    extra_svcs = await scan_all_services([e_ip], max_hosts_concurrent=1)
                    services_map.update(extra_svcs)

            report("Classificazione dispositivi e fingerprinting passivo...", 75)

            # Retrieve existing customizations from DB to ensure user friendly names and category overrides persist
            from lanscanner.core.storage import get_all_devices
            db_devices_map = {d["mac"]: d for d in get_all_devices()}

            # Correlate all device data
            processed_devices: List[Dict] = []
            for arp in arp_entries:
                ip = arp["ip"]
                mac = arp["mac"]
                vendor = lookup_vendor(mac)
                hostname = dns_map.get(ip)
                nb_info = netbios_map.get(ip)
                ssdp_info = ssdp_map.get(ip)
                svcs = services_map.get(ip, [])

                db_dev = db_devices_map.get(mac, {})
                custom_name = db_dev.get("custom_name")
                custom_category = db_dev.get("custom_category")

                # If SSDP friendly name is available, refine hostname
                upnp_meta = (ssdp_info or {}).get("upnp_info") or {}
                if upnp_meta.get("friendly_name") and not hostname:
                    hostname = upnp_meta.get("friendly_name")
                elif nb_info and nb_info.get("computer_name") and not hostname:
                    hostname = nb_info.get("computer_name")

                # Device classification & OS heuristics
                classification = classify_device(
                    ip=ip,
                    gateway_ip=gateway_ip,
                    vendor=vendor,
                    hostname=hostname,
                    netbios=nb_info,
                    ssdp=ssdp_info,
                    services=svcs,
                )

                # If classification inferred a richer friendly name and hostname is generic or from an exact title/model:
                if classification.get("inferred_name"):
                    is_generic = not hostname or hostname in ("Sconosciuto", "VDSTATION", "WORKGROUP", "None")
                    is_high_confidence = classification.get("category") in (
                        "Stampante di Rete", "Virtualizzazione / Server", "NVR / Videosorveglianza"
                    )
                    if is_generic or is_high_confidence:
                        hostname = classification["inferred_name"]

                effective_category = custom_category or classification["category"]
                dev_dict = {
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "hostname": hostname or "Sconosciuto",
                    "custom_name": custom_name,
                    "category": effective_category,
                    "custom_category": custom_category,
                    "os_family": classification["os_family"],
                    "icon": classification["icon"],
                    "services": svcs,
                    "netbios": nb_info,
                    "ssdp": ssdp_info,
                    "is_gateway": (ip == gateway_ip),
                    "is_local": (ip == local_ip),
                }
                processed_devices.append(dev_dict)

            # Step 4: Run Passive Security Assessment
            report("Analisi di sicurezza passiva e calcolo postura di rischio...", 90)
            assessment = evaluate_security_assessment(processed_devices, net_info)
            self.last_assessment = assessment

            # Attach individual security scores and save to SQLite
            for dev in processed_devices:
                dev["security_score"] = assessment["device_scores"].get(dev["mac"], 100)
                save_or_update_device(dev)

            # Mark devices not seen in this active scan as offline
            from lanscanner.core.storage import mark_offline_unseen_devices
            mark_offline_unseen_devices([d["mac"] for d in processed_devices])

            # Save Scan History
            save_scan_history(
                total_devices=len(processed_devices),
                global_score=assessment["global_score"],
                findings_count=len(assessment["findings"]),
                summary=assessment["counts"],
            )

            # Proactive Telegram alerts for CRITICO or ALTO findings
            try:
                from lanscanner.core.telegram_notify import notify_security_alert
                for finding in assessment.get("findings", []):
                    if finding.get("severity") in ["CRITICO", "ALTO"]:
                        target = finding.get("target_device", {})
                        notify_security_alert(
                            title=finding.get("title", "Alert Sicurezza"),
                            severity=finding.get("severity", "ALTO"),
                            device_ip=target.get("ip", "Sconosciuto"),
                            description=finding.get("description", "")
                        )
            except Exception:
                pass

            report("Scansione e assessment completati con successo!", 100)
            self.last_scan_time = datetime.now()
            return {
                "status": "success",
                "network": net_info,
                "devices": processed_devices,
                "assessment": assessment,
            }

        finally:
            self.is_scanning = False


scanner_instance = ScanCoordinator()


if __name__ == "__main__":
    async def main():
        def prog(m, p):
            print(f"[{p}%] {m}")
        res = await scanner_instance.run_full_scan(progress_callback=prog)
        print("\n--- RISULTATO ASSESSMENT ---")
        ass = res["assessment"]
        print(f"Punteggio Globale: {ass['global_score']}/100 (Grado {ass['grade']} - {ass['health_label']})")
        print(f"Dispositivi scoperti: {len(res['devices'])}")
        print(f"Vulnerabilità passive trovate: {len(ass['findings'])}")
        for f in ass["findings"]:
            print(f" - [{f['severity']}] {f['title']} -> {f['target_device']['name']} ({f['target_device']['ip']})")
    asyncio.run(main())
