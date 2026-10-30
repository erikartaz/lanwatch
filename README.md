# LANWatch - Home LAN Sentinel & Security Assessment 🛡️

**LANWatch** è una web application progettata per monitorare tutti i dispositivi connessi alla rete locale (LAN casalinga), offrendo un inventario tecnico dettagliato e un modulo di **security assessment basato esclusivamente su indagine passiva e non invasiva** (senza inviare payload offensivi, brute-force o attacchi DoS).

---

## 🚀 Caratteristiche Principali

### 1. Inventario Tecnico Dettagliato
* **Rilevamento IP & MAC**: Mappa completa di tutti gli host sulla subnet (es. `192.168.1.0/24`).
* **Risoluzione Produttore (OUI Lookup)**: Database integrato con identificazione dei brand hardware (Vodafone Station, Apple, Samsung, Proxmox, Amazon Echo, Tuya, Espressif, Raspberry Pi, HP, ecc.).
* **Rilevamento Nomi Multi-Protocollo & Web Title Grabbing**:
  * Titoli HTML (`<title>`) e certificati TLS/SSL (es. *Proxmox VE*, *Shinobi NVR*, *HP LaserJet MFP M28w*)
  * Reverse DNS (PTR)
  * NetBIOS Name Service (Computer Name e Workgroup Windows/Samba)
  * SSDP / UPnP (Friendly Name, Modello e Produttore)
  * mDNS / Bonjour (Apple AirPlay, Google Cast, Smart Speaker)
* **Classificazione e OS Heuristics**: Assegnazione automatica della tipologia (Router, Hypervisor/Server, Smartphone, Smart Home/IoT, Stampante, Smart TV, PC) e stima del sistema operativo.
* **Scheda Dispositivo & Personalizzazione**: Assegnazione di alias (nomi personalizzati), categorie e note tecniche con salvataggio su database locale SQLite (`lanscanner.db`).

### 2. Funzionalità Avanzate & Control Room
* **🌐 Mappa Topologica Interattiva (Vis.js)**: Grafo visuale a costellazione con nodi trascinabili, zoom e raggruppamento dinamico (Gateway, cluster Homelab/Proxmox, cluster IoT, PC e smartphone).
* **⚡ Azioni Rapide a 1-Click**:
  * **Apri Web UI ↗**: link diretto verso i servizi web rilevati (Proxmox porta 8006, Shinobi porta 8080, stampanti porta 80/443).
  * **Wake-on-LAN (WoL)**: invio del Magic Packet per accendere PC o server a distanza.
  * **Test Latenza (Ping)**: misurazione in tempo reale del tempo di risposta (ms) di qualsiasi dispositivo.
* **🛡️ Sentinella Wi-Fi & Dispositivi Fidati**:
  * Sistema di categorizzazione *"Fidato"* vs *"Da Verificare"*.
  * Banner di avviso automatico quando un nuovo host sconosciuto si connette alla rete.
  * Avvisi sonori opzionali (Chime sintetizzato via Web Audio API).
* **👥 Monitoraggio Presenza "Chi è a Casa?"**: Widget che tiene traccia degli smartphone/tablet connessi in tempo reale.
* **🚦 Monitor Latenza Gateway & Internet**: Misurazione continua della salute della connessione (Ping Gateway + Ping Internet).

### 3. Security Assessment Passivo (Zero Attacchi Mirati)
* **Grafico Radar a 5 Assi**: Valutazione visuale a ragnatela di Crittografia Web, Segmentazione IoT, Sicurezza Gateway, Accesso Remoto e Protocolli Broadcast.
* **Pannelli in Chiaro (HTTP vs HTTPS)**: Identifica interfacce web di gestione che espongono credenziali senza cifratura SSL/TLS.
* **UPnP Internet Gateway Device (IGD)**: Rileva se il router permette l'apertura automatica di porte da parte di dispositivi interni o malware (port forwarding automatico).
* **Protocolli Insicuri e Obsoleti**: Identifica la presenza di servizi Telnet (porta 23), FTP (porta 21), MQTT in chiaro (porta 1883) o stream di videosorveglianza RTSP (porta 554).
* **Esposizione NetBIOS / LLMNR**: Segnala host vulnerabili ad attacchi di avvelenamento credenziali (LLMNR/NBT-NS Poisoning come Responder).
* **Valutazione Segmentazione Rete**: Misura la densità di dispositivi IoT non isolati che condividono il dominio di broadcast con PC personali o server.
* **Posture Score (0-100)**: Calcolo del punteggio di sicurezza per singolo dispositivo e per l'intera rete domestica (Grado A, B, C, D) con checklist e guide di mitigazione in italiano.
* **Esportazione & Stampa**: Report di audit scaricabile in JSON e versione ottimizzata per la stampa PDF.

---

## 📦 Avvio Rapido con `uv`

Il progetto utilizza **`uv`** per la gestione dell'ambiente Python e delle dipendenze.

### Avvio dell'Applicazione:

```bash
uv run python main.py
```

oppure:

```bash
uv run lanscanner
```

L'applicazione avvierà il server FastAPI su `http://127.0.0.1:8000` e aprirà automaticamente la dashboard nel browser predefinito!

---

## 🛠️ Tecnologie Utilizzate

* **Backend**: Python 3, FastAPI, Uvicorn, SQLite, WebSockets.
* **Discovery Engine**: Asyncio, ZeroConf (mDNS), SSDP/UPnP Multicast, NetBIOS Node Status, ARP Table Reader.
* **Frontend**: HTML5, Tailwind CSS, Lucide Icons, Chart.js (Single Page Application responsive con Dark Mode nativa).
