#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         SecureSniffer — Outil de Sniffing Réseau            ║
║   Basé sur : Python-Scapy-Packet-Sniffer (Roshan-Poudel)    ║
║   Améliorations : DNS · HTTP · ARP Spoofing · Port Scan      ║
║                   Interface Web Temps Réel (Flask-SocketIO)  ║
╚══════════════════════════════════════════════════════════════╝

Usage :
    sudo python3 app.py
    sudo python3 app.py --interface eth0 --port 5000

Puis ouvrir : http://localhost:5000
"""

import argparse
import socket
import datetime
import threading
import time
from collections import defaultdict

from flask import Flask, render_template
from flask_socketio import SocketIO

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw


# ═══════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════════

app = Flask(__name__)
app.config["SECRET_KEY"] = "securesniffer-secret"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# État global partagé entre le thread sniffer et Flask
state = {
    "running":   False,
    "interface": None,
    "stats":     {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "dns": 0, "http": 0},
    "packets":   [],          # Buffer des derniers paquets (max 500)
    "alerts":    [],          # Alertes de sécurité
    "arp_table": {},          # { ip: mac }  — pour la détection ARP
    "arp_alerts_seen": set(), # Évite le spam d'alertes ARP
    "scan_data": defaultdict(list),  # { src_ip: [(ts, port), ...] }
    "scan_alerted": set(),    # IPs déjà alertées pour port scan
    "start_time": None,
    "local_ip":  "127.0.0.1",
    "sniff_thread": None,
}

MAX_PACKETS = 500
SCAN_THRESHOLD  = 15   # ports distincts
SCAN_WINDOW     = 10   # secondes


# ═══════════════════════════════════════════════════════════════════
#  UTILITAIRES
# ═══════════════════════════════════════════════════════════════════

def get_local_ip() -> str:
    """Récupère l'IP locale (repris du projet original)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def now_str() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


def push_packet(entry: dict):
    """Ajoute un paquet au buffer et l'envoie au frontend via SocketIO."""
    state["packets"].append(entry)
    if len(state["packets"]) > MAX_PACKETS:
        state["packets"].pop(0)
    state["stats"]["total"] += 1
    socketio.emit("packet", entry)


def push_alert(level: str, message: str):
    """Envoie une alerte de sécurité au frontend."""
    alert = {"time": now_str(), "level": level, "message": message}
    state["alerts"].append(alert)
    if len(state["alerts"]) > 100:
        state["alerts"].pop(0)
    socketio.emit("alert", alert)
    socketio.emit("stats", state["stats"])


# ═══════════════════════════════════════════════════════════════════
#  ANALYSE DNS
# ═══════════════════════════════════════════════════════════════════

def analyze_dns(pkt) -> str | None:
    """Extrait les infos DNS d'un paquet UDP/DNS."""
    if not pkt.haslayer(DNS):
        return None
    dns = pkt[DNS]
    try:
        if dns.qr == 0 and dns.haslayer(DNSQR):              # Requête
            qname = dns[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
            qtypes = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 255: "ANY"}
            qtype = qtypes.get(dns[DNSQR].qtype, f"T{dns[DNSQR].qtype}")
            return f"QUERY {qtype} → {qname}"
        elif dns.qr == 1 and dns.haslayer(DNSQR):            # Réponse
            qname = dns[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
            answers, layer = [], dns
            for _ in range(5):
                if not layer.haslayer(DNSRR):
                    break
                rr = layer[DNSRR]
                if hasattr(rr, "rdata"):
                    answers.append(str(rr.rdata))
                layer = rr.payload
            ans = ", ".join(answers[:3]) if answers else "no answer"
            return f"RESPONSE {qname} → [{ans}]"
    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════════════════════
#  ANALYSE HTTP
# ═══════════════════════════════════════════════════════════════════

HTTP_METHODS = {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH"}

def analyze_http(pkt) -> str | None:
    """Extrait les infos HTTP (port 80) d'un paquet TCP."""
    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return None
    if pkt[TCP].dport not in (80, 8080) and pkt[TCP].sport not in (80, 8080):
        return None
    try:
        payload = bytes(pkt[Raw].load)
        for method in HTTP_METHODS:
            if payload.startswith(method):
                lines = payload.split(b"\r\n")
                parts = lines[0].decode("utf-8", errors="replace").split(" ")
                method_str = parts[0] if parts else "?"
                path = parts[1] if len(parts) > 1 else "/"
                host = next(
                    (l.split(b":", 1)[1].strip().decode("utf-8", errors="replace")
                     for l in lines[1:] if l.lower().startswith(b"host:")),
                    ""
                )
                url = f"http://{host}{path}" if host else path
                return f"REQUEST {method_str} {url}"
        if payload.startswith(b"HTTP/"):
            first = payload.split(b"\r\n")[0].decode("utf-8", errors="replace").split(" ", 2)
            code = first[1] if len(first) > 1 else "?"
            txt  = first[2] if len(first) > 2 else ""
            return f"RESPONSE {code} {txt}"
    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════════════════════
#  DÉTECTION ARP SPOOFING
# ═══════════════════════════════════════════════════════════════════

def check_arp(pkt):
    """Détecte les incohérences IP↔MAC dans les paquets ARP."""
    if not pkt.haslayer(ARP) or pkt[ARP].op not in (1, 2):
        return
    arp = pkt[ARP]
    src_ip, src_mac = arp.psrc, arp.hwsrc
    if src_ip in ("0.0.0.0", "") or src_mac in ("00:00:00:00:00:00", ""):
        return
    known = state["arp_table"].get(src_ip)
    if known is None:
        state["arp_table"][src_ip] = src_mac
    elif known != src_mac:
        key = (src_ip, src_mac)
        if key not in state["arp_alerts_seen"]:
            state["arp_alerts_seen"].add(key)
            push_alert("DANGER",
                f"ARP SPOOFING détecté ! IP {src_ip} : connue avec MAC {known}, "
                f"mais se présente avec {src_mac}. Possible attaque Man-in-the-Middle !")


# ═══════════════════════════════════════════════════════════════════
#  DÉTECTION PORT SCANNING
# ═══════════════════════════════════════════════════════════════════

def check_portscan(pkt):
    """Détecte un balayage de ports (SYN vers de nombreux ports distincts)."""
    if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
        return
    tcp = pkt[TCP]
    # Paquet SYN uniquement (flags & SYN, pas ACK)
    if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
        return
    src_ip = pkt[IP].src
    now = time.time()
    # Nettoyer les entrées hors fenêtre
    state["scan_data"][src_ip] = [
        (ts, p) for ts, p in state["scan_data"][src_ip]
        if now - ts <= SCAN_WINDOW
    ]
    state["scan_data"][src_ip].append((now, tcp.dport))
    ports = {p for _, p in state["scan_data"][src_ip]}
    if len(ports) >= SCAN_THRESHOLD and src_ip not in state["scan_alerted"]:
        state["scan_alerted"].add(src_ip)
        sample = sorted(ports)[:10]
        push_alert("WARNING",
            f"PORT SCAN détecté ! IP {src_ip} a contacté {len(ports)} ports "
            f"distincts en {SCAN_WINDOW}s. Échantillon : {sample}")
    elif len(ports) < SCAN_THRESHOLD // 2:
        state["scan_alerted"].discard(src_ip)


# ═══════════════════════════════════════════════════════════════════
#  CALLBACK PRINCIPAL (repris + amélioré du projet original)
# ═══════════════════════════════════════════════════════════════════

def process_packet(pkt):
    """Traite chaque paquet capturé et l'envoie au frontend."""
    if not state["running"]:
        return

    ts        = now_str()
    local_ip  = state["local_ip"]

    # ── Vérifications de sécurité ──────────────────────────────────
    check_arp(pkt)
    check_portscan(pkt)

    # ── TCP ────────────────────────────────────────────────────────
    if pkt.haslayer(TCP):
        ip_layer = IP if pkt.haslayer(IP) else (IPv6 if pkt.haslayer(IPv6) else None)
        if not ip_layer:
            return
        src, dst   = pkt[ip_layer].src, pkt[ip_layer].dst
        direction  = "IN" if dst == local_ip else "OUT"
        http_info  = analyze_http(pkt)
        proto      = "HTTP" if http_info else "TCP"
        state["stats"]["tcp"] += 1
        if http_info:
            state["stats"]["http"] += 1
        entry = {
            "time": ts, "proto": proto, "direction": direction,
            "src": src, "src_port": pkt.sport,
            "dst": dst, "dst_port": pkt.dport,
            "size": len(pkt[TCP]),
            "info": http_info or ""
        }
        push_packet(entry)

    # ── UDP ────────────────────────────────────────────────────────
    elif pkt.haslayer(UDP) and pkt.haslayer(IP):
        src, dst   = pkt[IP].src, pkt[IP].dst
        direction  = "IN" if dst == local_ip else "OUT"
        dns_info   = analyze_dns(pkt)
        proto      = "DNS" if dns_info else "UDP"
        state["stats"]["udp"] += 1
        if dns_info:
            state["stats"]["dns"] += 1
        entry = {
            "time": ts, "proto": proto, "direction": direction,
            "src": src, "src_port": pkt.sport,
            "dst": dst, "dst_port": pkt.dport,
            "size": len(pkt[UDP]),
            "info": dns_info or ""
        }
        push_packet(entry)

    # ── ICMP ───────────────────────────────────────────────────────
    elif pkt.haslayer(ICMP) and pkt.haslayer(IP):
        src, dst   = pkt[IP].src, pkt[IP].dst
        direction  = "IN" if dst == local_ip else "OUT"
        icmp_names = {0: "Echo Reply", 3: "Dest Unreachable",
                      8: "Echo Request", 11: "Time Exceeded"}
        icmp_info  = icmp_names.get(pkt[ICMP].type, f"Type={pkt[ICMP].type}")
        state["stats"]["icmp"] += 1
        entry = {
            "time": ts, "proto": "ICMP", "direction": direction,
            "src": src, "src_port": "-",
            "dst": dst, "dst_port": "-",
            "size": len(pkt[ICMP]),
            "info": icmp_info
        }
        push_packet(entry)

    # Envoyer les stats mises à jour au frontend
    socketio.emit("stats", state["stats"])


# ═══════════════════════════════════════════════════════════════════
#  THREAD DE SNIFFING
# ═══════════════════════════════════════════════════════════════════

def sniff_thread():
    """Lance Scapy sniff() dans un thread séparé."""
    sniff(
        iface=state["interface"] or None,
        prn=process_packet,
        store=False,
        stop_filter=lambda _: not state["running"]
    )


# ═══════════════════════════════════════════════════════════════════
#  ROUTES FLASK
# ═══════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


# ═══════════════════════════════════════════════════════════════════
#  ÉVÉNEMENTS SOCKETIO
# ═══════════════════════════════════════════════════════════════════

@socketio.on("connect")
def on_connect():
    """Envoie l'état actuel au nouveau client."""
    socketio.emit("init", {
        "running":    state["running"],
        "local_ip":   state["local_ip"],
        "interface":  state["interface"] or "Toutes",
        "stats":      state["stats"],
        "packets":    state["packets"][-100:],
        "alerts":     state["alerts"][-20:],
    })


@socketio.on("start")
def on_start(data):
    """Démarre le sniffing."""
    if state["running"]:
        return
    iface = data.get("interface", "").strip() or None
    state["interface"]  = iface
    state["running"]    = True
    state["start_time"] = datetime.datetime.now()
    state["local_ip"]   = get_local_ip()
    # Réinitialiser les stats
    state["stats"]      = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "dns": 0, "http": 0}
    state["packets"]    = []
    state["alerts"]     = []
    state["arp_table"]  = {}
    state["arp_alerts_seen"] = set()
    state["scan_data"]  = defaultdict(list)
    state["scan_alerted"] = set()

    t = threading.Thread(target=sniff_thread, daemon=True)
    t.start()
    state["sniff_thread"] = t
    socketio.emit("status", {"running": True, "local_ip": state["local_ip"],
                              "interface": iface or "Toutes"})
    print(f"[+] Sniffing démarré — Interface: {iface or 'Toutes'} — IP locale: {state['local_ip']}")


@socketio.on("stop")
def on_stop():
    """Arrête le sniffing."""
    state["running"] = False
    socketio.emit("status", {"running": False})
    print("[+] Sniffing arrêté.")


# ═══════════════════════════════════════════════════════════════════
#  POINT D'ENTRÉE
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecureSniffer — Interface Web")
    parser.add_argument("--interface", "-i", default=None,
                        help="Interface réseau par défaut (ex: eth0, wlan0)")
    parser.add_argument("--port", "-p", type=int, default=5000,
                        help="Port HTTP du serveur web (défaut: 5000)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Adresse du serveur web (défaut: 127.0.0.1)")
    args = parser.parse_args()

    state["interface"] = args.interface
    state["local_ip"]  = get_local_ip()

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║         SecureSniffer — Interface Web Temps Réel            ║
╠══════════════════════════════════════════════════════════════╣
║  Ouvrir dans le navigateur :                                 ║
║  → http://{args.host}:{args.port:<46}║
╚══════════════════════════════════════════════════════════════╝
""")

    socketio.run(app, host=args.host, port=args.port, debug=False, allow_unsafe_werkzeug=True)
