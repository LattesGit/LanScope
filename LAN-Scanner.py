import argparse
import csv
import errno
import ipaddress
import json
import math
import os
import platform
import random
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

SYSTEM = platform.system()
IS_WINDOWS = SYSTEM == "Windows"
IS_MAC = SYSTEM == "Darwin"
USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ

if IS_WINDOWS:
    os.system("")


def _c(code):
    return code if USE_COLOR else ""


R   = _c("\033[38;5;196m")
G   = _c("\033[38;5;82m")
Y   = _c("\033[38;5;226m")
C   = _c("\033[38;5;51m")
M   = _c("\033[38;5;201m")
DG  = _c("\033[38;5;238m")
GR  = _c("\033[38;5;245m")
W   = _c("\033[97m")
B   = _c("\033[1m")
DIM = _c("\033[2m")
RST = _c("\033[0m")

SPIN_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
LEVEL_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
RISK_COLOR = {"CRITICAL": R, "HIGH": Y, "MEDIUM": M, "LOW": GR}

DEFAULT_PORTS = {
    21:   ("FTP",       "📂"),
    22:   ("SSH",       "🔐"),
    23:   ("Telnet",    "📡"),
    25:   ("SMTP",      "📧"),
    53:   ("DNS",       "🌐"),
    80:   ("HTTP",      "🕸️ "),
    110:  ("POP3",      "📬"),
    139:  ("NetBIOS",   "🗂️ "),
    143:  ("IMAP",      "📨"),
    443:  ("HTTPS",     "🔒"),
    445:  ("SMB",       "🗂️ "),
    3306: ("MySQL",     "🗄️ "),
    3389: ("RDP",       "🖥️ "),
    5900: ("VNC",       "👁️ "),
    8080: ("HTTP-ALT",  "🌍"),
    8443: ("HTTPS-ALT", "🔏"),
}

BANNER_PROBES = {
    21:   b"",
    22:   b"",
    23:   b"",
    25:   b"",
    80:   b"HEAD / HTTP/1.0\r\n\r\n",
    110:  b"",
    143:  b"",
    3306: b"",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
}

VULN_HINTS = {
    23:   ("CRITICAL", "Telnet açık — şifresiz protokol, MITM riski"),
    21:   ("HIGH",     "FTP açık — plaintext kimlik doğrulama, anonim erişim olabilir"),
    3389: ("HIGH",     "RDP açık — brute-force ve BlueKeep (CVE-2019-0708) riski"),
    5900: ("HIGH",     "VNC açık — zayıf auth veya no-auth riski"),
    445:  ("HIGH",     "SMB açık — EternalBlue / MS17-010 riski (yama durumunu kontrol et)"),
    139:  ("MEDIUM",   "NetBIOS açık — bilgi sızıntısı riski"),
    3306: ("MEDIUM",   "MySQL açık — internete maruz kalmamalı"),
    25:   ("LOW",      "SMTP açık — open relay kontrolü yapılmalı"),
    8080: ("LOW",      "HTTP-ALT açık — yönetim paneli olabilir"),
}

TTL_RE = re.compile(r"ttl[=:\s]*(\d+)", re.I)
MAC_RE = re.compile(r"(?:[0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2}", re.I)
TCP_PING_PORTS = (80, 443, 22, 445)

print_lock = threading.Lock()


@dataclass
class Device:
    ip: str
    hostname: str = "—"
    mac: str = "—"
    ports: list = field(default_factory=list)
    banners: dict = field(default_factory=dict)
    os_type: str = "❓ Unknown"
    ttl: Optional[int] = None
    window: Optional[int] = None
    vulns: list = field(default_factory=list)
    is_me: bool = False


def tw():
    return shutil.get_terminal_size((80, 24)).columns


def clear_line():
    print("\r" + " " * (tw() - 1) + "\r", end="", flush=True)


def clear_screen():
    if sys.stdout.isatty():
        os.system("cls" if IS_WINDOWS else "clear")


def banner(args):
    clear_screen()
    width = tw()
    now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    top = f"{DG}{'─' * width}{RST}"
    print(top)
    print(f"{B}{C}  ◈  NET RECON  ◈{RST}")
    print(f"{DG}  scanner by laxent🔎  {GR}{now}{RST}")
    print(f"{DG}  FUCK I FUCKİNG LOVE EMİRA TOO MUCH  {GR}{now}{RST}")
    print(f"{DG}  workers={args.workers}  timeout={args.timeout}s  "
          f"ports={'custom' if args.ports else 'default'}  export={args.format}{RST}")
    print(top)
    print()


class Spinner:
    def __init__(self, msg=""):
        self.msg = msg
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        i = 0
        while not self._stop.is_set():
            frame = SPIN_FRAMES[i % len(SPIN_FRAMES)]
            print(f"\r  {C}{frame}{RST}  {DIM}{self.msg}{RST}", end="", flush=True)
            time.sleep(0.08)
            i += 1

    def start(self):
        self._thread.start()
        return self

    def stop(self, final_msg=None):
        self._stop.set()
        self._thread.join()
        clear_line()
        if final_msg:
            print(final_msg)


def get_local_info(prefer_subnet=None):
    candidates = []
    try:
        out = subprocess.check_output(
            ["ip", "-o", "-4", "addr", "show"],
            stderr=subprocess.DEVNULL, text=True
        )
        for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", out):
            ip, prefix = m.group(1), int(m.group(2))
            if not ip.startswith("127."):
                net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                candidates.append((ip, str(net)))
    except (OSError, subprocess.SubprocessError, ValueError):
        pass

    if not candidates:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            candidates.append((ip, str(net)))
        except OSError:
            candidates.append(("127.0.0.1", "127.0.0.0/8"))
        finally:
            s.close()

    if prefer_subnet:
        try:
            wanted = ipaddress.IPv4Network(prefer_subnet, strict=False)
            for ip, subnet in candidates:
                if ipaddress.IPv4Address(ip) in wanted:
                    return ip, subnet
        except ValueError:
            pass

    return candidates[0]


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None


def normalize_mac(raw):
    parts = re.split(r"[:-]", raw)
    return ":".join(p.zfill(2) for p in parts).upper()


def read_arp(ip):
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", encoding="utf-8") as f:
                next(f, None)
                for line in f:
                    cols = line.split()
                    if len(cols) >= 4 and cols[0] == ip and cols[3] != "00:00:00:00:00:00":
                        return normalize_mac(cols[3])
        except OSError:
            pass
        return None

    cmd = ["arp", "-a", ip] if IS_WINDOWS else ["arp", "-n", ip]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        if ip in line:
            m = MAC_RE.search(line)
            if m:
                return normalize_mac(m.group(0))
    return None


def get_mac(ip):
    mac = read_arp(ip)
    if mac:
        return mac
    if shutil.which("arping"):
        try:
            subprocess.run(
                ["arping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
            )
            return read_arp(ip)
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def ping_cmd(ip, timeout):
    if IS_WINDOWS:
        return ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    if IS_MAC:
        return ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
    return ["ping", "-c", "1", "-W", str(max(1, math.ceil(timeout))), ip]


def ping(ip, timeout=1.0):
    try:
        res = subprocess.run(
            ping_cmd(ip, timeout),
            capture_output=True, text=True, timeout=timeout + 3
        )
    except (OSError, subprocess.SubprocessError):
        return False, None
    if res.returncode != 0:
        return False, None
    m = TTL_RE.search(res.stdout)
    ttl = int(m.group(1)) if m else None
    if IS_WINDOWS and ttl is None:
        return False, None
    return True, ttl


def tcp_alive(ip, timeout=0.5):
    for port in TCP_PING_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            code = s.connect_ex((ip, port))
            if code == 0 or code == errno.ECONNREFUSED:
                return True
    return False


def ttl_os_hint(ttl):
    if ttl is None:
        return None
    if ttl > 200:
        return "🔧 Network Device (Cisco/HP)"
    if ttl > 100:
        return "🪟 Windows"
    if ttl > 50:
        return "🐧 Linux / 🍎 macOS"
    return "❓ Low TTL"


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def tcp_window(ip, my_ip, port, timeout=1.0):
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return None

    sport = random.randint(20000, 60000)
    seq = random.getrandbits(32)
    src = socket.inet_aton(my_ip)
    dst = socket.inet_aton(ip)

    def build(chk):
        return struct.pack("!HHLLBBHHH", sport, port, seq, 0, 5 << 4, 0x02, 5840, chk, 0)

    pseudo = struct.pack("!4s4sBBH", src, dst, 0, socket.IPPROTO_TCP, 20)
    packet = build(_checksum(pseudo + build(0)))

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
            s.sendto(packet, (ip, 0))
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                s.settimeout(remaining)
                data, addr = s.recvfrom(1024)
                if addr[0] != ip:
                    continue
                segment = data[(data[0] & 0xF) * 4:]
                if len(segment) < 16:
                    continue
                r_sport, r_dport = struct.unpack("!HH", segment[:4])
                flags = segment[13]
                if r_sport == port and r_dport == sport and flags & 0x12 == 0x12:
                    return struct.unpack("!H", segment[14:16])[0]
    except OSError:
        return None


def window_os_hint(window):
    if window is None:
        return None
    if window == 65535:
        return "🪟 Windows / 🍎 macOS"
    if window in (5840, 14600, 29200):
        return "🐧 Linux"
    if window == 8192:
        return "🪟 Windows (old)"
    return None


def build_port_map(extra_ports=None):
    port_map = dict(DEFAULT_PORTS)
    for p in extra_ports or []:
        if 0 < p < 65536 and p not in port_map:
            port_map[p] = ("CUSTOM", "🔌")
    return port_map


def scan_ports(ip, port_map, timeout=0.4):
    found = []
    for port, (name, emoji) in port_map.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                found.append((port, name, emoji))
    return found


def grab_banner(ip, port, timeout=2.0):
    probe = BANNER_PROBES.get(port)
    if probe is None:
        return None
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if probe:
                s.sendall(probe)
            data = s.recv(1024)
    except OSError:
        return None

    lines = [
        "".join(ch for ch in ln if ch.isprintable()).strip()
        for ln in data.decode("utf-8", errors="ignore").splitlines()
    ]
    lines = [ln for ln in lines if ln]
    if not lines:
        return None

    if probe.startswith(b"HEAD"):
        server = next((ln for ln in lines if ln.lower().startswith("server:")), None)
        if server:
            return f"{lines[0]} | {server}"[:80]
    return lines[0][:80]


def get_vulns(open_ports):
    return [
        (VULN_HINTS[port][0], VULN_HINTS[port][1], port)
        for port, _, _ in open_ports
        if port in VULN_HINTS
    ]


def guess_os(open_ports, hostname, ttl, window):
    port_nums = {p for p, _, _ in open_ports}

    if 3389 in port_nums:
        return "🖥️  Windows PC (RDP)"
    if 5900 in port_nums:
        return "🖥️  Desktop (VNC)"

    if ttl and window:
        if ttl > 100 and window == 65535:
            return "🪟 Windows (TTL+Win)"
        if 50 < ttl <= 70 and window in (5840, 14600, 29200):
            return "🐧 Linux (TTL+Win)"
        if 50 < ttl <= 70 and window == 65535:
            return "🍎 macOS (TTL+Win)"

    if 22 in port_nums and 80 in port_nums:
        return ttl_os_hint(ttl) or "🐧 Linux Server"
    if 22 in port_nums:
        return ttl_os_hint(ttl) or "🐧 Linux/Unix"
    if 445 in port_nums or 139 in port_nums:
        return "🪟 Windows (SMB)"
    if 80 in port_nums or 443 in port_nums:
        return "📡 Web Device"

    if hostname:
        hn = hostname.lower()
        if "router" in hn or "gateway" in hn:
            return "📶 Router"
        if "android" in hn:
            return "📱 Android"
        if any(x in hn for x in ("iphone", "ipad", "apple")):
            return "🍎 Apple Device"

    return ttl_os_hint(ttl) or window_os_hint(window) or "❓ Unknown"


def scan_host(ip, my_ip, port_map, timeout, grab_banners=True, tcp_ping=False):
    alive, ttl = ping(ip)
    if not alive and tcp_ping:
        alive = tcp_alive(ip)
    if not alive:
        return None

    hostname = resolve_hostname(ip)
    mac = get_mac(ip)
    ports = scan_ports(ip, port_map, timeout=timeout)
    window = tcp_window(ip, my_ip, ports[0][0]) if ports else None

    banners = {}
    if grab_banners:
        for port, _, _ in ports:
            b = grab_banner(ip, port)
            if b:
                banners[port] = b

    return Device(
        ip=ip,
        hostname=hostname or "—",
        mac=mac or "—",
        ports=ports,
        banners=banners,
        os_type=guess_os(ports, hostname, ttl, window),
        ttl=ttl,
        window=window,
        vulns=get_vulns(ports),
        is_me=(ip == my_ip),
    )


def print_device(dev, idx):
    sep = f"{DG}  {'·' * max(1, tw() - 4)}{RST}"
    me = f"  {Y}◀ BU CİHAZ{RST}" if dev.is_me else ""
    ttl_str = str(dev.ttl) if dev.ttl else "—"
    win_str = str(dev.window) if dev.window else "—"

    print(sep)
    print(f"  {B}{G}[{idx:02d}]{RST}  {B}{W}{dev.ip}{RST}{me}")
    print(f"  {DG}┌{RST}  🏷️  {GR}{dev.hostname}{RST}")
    print(f"  {DG}├{RST}  🔌  {GR}{dev.mac}{RST}")
    print(f"  {DG}├{RST}  ⏱️  TTL: {C}{ttl_str}{RST}  │  TCP Win: {C}{win_str}{RST}")
    print(f"  {DG}├{RST}  {dev.os_type}")

    for port, name, emoji in dev.ports:
        text = dev.banners.get(port, "")
        b_str = f"  {DIM}» {text[:60]}{RST}" if text else ""
        print(f"  {DG}│{RST}  🔓  {emoji} {C}{port}{RST}/{GR}{name}{RST}{b_str}")

    if dev.vulns:
        print(f"  {DG}│{RST}")
        for level, msg, port in sorted(dev.vulns, key=lambda v: LEVEL_ORDER[v[0]]):
            col = RISK_COLOR.get(level, GR)
            print(f"  {DG}│{RST}  {col}⚠  [{level}] {msg} (:{port}){RST}")

    if not dev.ports:
        print(f"  {DG}└{RST}  🔒  {DG}Açık port bulunamadı{RST}")
    else:
        print(f"  {DG}└──{RST}")
    print()


def print_summary(devices, elapsed, subnet):
    w = tw()
    print(f"{DG}{'═' * w}{RST}")
    print(f"\n  {B}{Y}!!  TARAMA TAMAMLANDI{RST}\n")
    print(f"  {DG}Subnet:  {RST}{C}{subnet}{RST}")
    print(f"  {DG}Süre:    {RST}{C}{elapsed:.1f}s{RST}")
    print(f"  {DG}Bulunan: {RST}{G}{B}{len(devices)} cihaz{RST}")

    all_ports = [p for d in devices for p in d.ports]
    if all_ports:
        print(f"\n  {B}Açık servisler:{RST}")
        for name, cnt in Counter(n for _, n, _ in all_ports).most_common():
            print(f"  {DG}  {name:<12}{RST} {G}{'█' * cnt}{RST} {DIM}{cnt}{RST}")

    all_vulns = [(d.ip, v) for d in devices for v in d.vulns]
    if all_vulns:
        print(f"\n  {B}Risk özeti:{RST}")
        for ip, (level, msg, _) in sorted(all_vulns, key=lambda x: LEVEL_ORDER[x[1][0]]):
            col = RISK_COLOR.get(level, GR)
            print(f"  {col}  ⚠  [{level}] {ip:<15} {msg}{RST}")

    print(f"\n{DG}{'═' * w}{RST}\n")


def export_results(devices, elapsed, subnet, path, fmt):
    try:
        if fmt == "json":
            data = {
                "scan_time": datetime.now().isoformat(),
                "subnet":    subnet,
                "elapsed":   round(elapsed, 2),
                "devices": [{
                    "ip": d.ip, "hostname": d.hostname, "mac": d.mac,
                    "os": d.os_type, "ttl": d.ttl, "tcp_window": d.window,
                    "ports": [
                        {"port": p, "name": n, "banner": d.banners.get(p)}
                        for p, n, _ in d.ports
                    ],
                    "vulns": [
                        {"level": lv, "msg": msg, "port": po}
                        for lv, msg, po in d.vulns
                    ],
                } for d in devices],
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

        elif fmt == "csv":
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ip", "hostname", "mac", "os", "ttl", "tcp_window",
                                 "open_ports", "banners", "vulns"])
                for d in devices:
                    writer.writerow([
                        d.ip, d.hostname, d.mac, d.os_type, d.ttl, d.window,
                        "|".join(f"{p}/{n}" for p, n, _ in d.ports),
                        "|".join(f"{p}:{b}" for p, b in d.banners.items()),
                        "|".join(f"[{lv}]{msg}" for lv, msg, _ in d.vulns),
                    ])

        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"NET RECON — {datetime.now()}\n")
                f.write(f"Subnet: {subnet} | Süre: {elapsed:.1f}s | Bulunan: {len(devices)}\n\n")
                for d in devices:
                    f.write(f"{d.ip}\t{d.hostname}\t{d.mac}\t{d.os_type}\tTTL:{d.ttl}\n")
                    for p, n, _ in d.ports:
                        b = d.banners.get(p, "")
                        f.write(f"  → {p}/{n}" + (f"  [{b}]" if b else "") + "\n")
                    for lv, msg, po in d.vulns:
                        f.write(f"  ⚠ [{lv}] {msg} (:{po})\n")
                    f.write("\n")
        return True
    except OSError as e:
        print(f"  {R}Export hatası: {e}{RST}\n")
        return False


def parse_args():
    p = argparse.ArgumentParser(description="NET RECON — by laxent")
    p.add_argument("-t", "--timeout", type=float, default=0.4,
                   help="Port timeout (s, default: 0.4)")
    p.add_argument("-w", "--workers", type=int, default=64,
                   help="Thread sayısı (default: 64)")
    p.add_argument("-p", "--ports", type=int, nargs="+",
                   help="Ekstra portlar (-p 8888 9090)")
    p.add_argument("-s", "--subnet", type=str, default=None,
                   help="Manuel subnet (192.168.1.0/24)")
    p.add_argument("-o", "--output", type=str, default=None,
                   help="Çıktı dosyası (-o out.json)")
    p.add_argument("-f", "--format", type=str, default=None,
                   choices=["txt", "json", "csv"],
                   help="Çıktı formatı (varsayılan: uzantıdan, yoksa txt)")
    p.add_argument("--no-banner", action="store_true",
                   help="Banner grabbing kapalı")
    p.add_argument("--tcp-ping", action="store_true",
                   help="ICMP'ye cevap vermeyen hostlar için TCP ile de dene")
    p.add_argument("--force", action="store_true",
                   help="1024'ten büyük subnet taramasına izin ver")

    args = p.parse_args()
    args.workers = max(1, args.workers)
    args.timeout = max(0.05, args.timeout)

    if args.format is None:
        ext = os.path.splitext(args.output or "")[1].lower().lstrip(".")
        args.format = ext if ext in ("json", "csv") else "txt"
    return args


def main():
    args = parse_args()
    banner(args)

    sp = Spinner("Yerel ağ bilgileri alınıyor...").start()
    time.sleep(0.5)
    my_ip, auto_subnet = get_local_info(args.subnet)
    subnet = args.subnet or auto_subnet
    sp.stop(f"  {G}✔{RST}  {C}{my_ip}{RST}  →  {Y}{subnet}{RST}\n")

    try:
        hosts = [str(h) for h in ipaddress.IPv4Network(subnet, strict=False).hosts()]
    except ValueError as e:
        print(f"  {R}Geçersiz subnet: {e}{RST}\n")
        return

    if len(hosts) > 1024 and not args.force:
        print(f"  {Y}⚠{RST}  {len(hosts)} adres taranacak. Devam etmek için --force kullan.\n")
        return

    port_map = build_port_map(args.ports)
    grab = not args.no_banner

    print(f"  {DIM}{len(hosts)} adres  |  {len(port_map)} port  |  {args.workers} worker  |  "
          f"timeout {args.timeout}s  |  banner {'ON' if grab else 'OFF'}{RST}\n")
    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
        print(f"  {DIM}İpucu: TCP window fingerprint için root yetkisi gerekir.{RST}\n")
    time.sleep(0.3)
    print(f"  {C}Tarama başlıyor...{RST}\n")

    start_time = time.time()
    devices = []
    completed = 0
    bar_width = max(10, tw() - 20)

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {
            ex.submit(scan_host, ip, my_ip, port_map, args.timeout, grab, args.tcp_ping): ip
            for ip in hosts
        }
        for future in as_completed(futures):
            completed += 1
            ip = futures[future]
            pct = completed / len(hosts)
            done = int(pct * bar_width)
            bar = f"{G}{'━' * done}{DG}{'╌' * (bar_width - done)}{RST}"
            print(f"\r  {bar} {Y}{int(pct * 100):3d}%{RST}  {DG}{ip}{RST}   ", end="", flush=True)

            try:
                result = future.result()
            except Exception as e:
                clear_line()
                print(f"  {R}✖{RST}  {ip}: {DIM}{e}{RST}")
                continue

            if result:
                devices.append(result)
                clear_line()
                vf = f"  {R}⚠{RST}" if result.vulns else ""
                print(f"  {G}⬡{RST}  {B}{result.ip:<15}{RST}  {result.os_type}{vf}  {G}+{RST}")

    elapsed = time.time() - start_time
    clear_line()
    print(f"\n  {G}✔{RST}  Tamamlandı🔎  {DIM}({elapsed:.1f}s){RST}\n")
    time.sleep(0.3)

    if not devices:
        print(f"  {R}Cihaz bulunamadı.{RST}\n")
        return

    devices.sort(key=lambda d: (not d.is_me, ipaddress.IPv4Address(d.ip)))

    print(f"\n  {B}{W}── CİHAZ DETAYLARI ──{RST}\n")
    for i, dev in enumerate(devices, 1):
        print_device(dev, i)

    print_summary(devices, elapsed, subnet)

    if args.output:
        if export_results(devices, elapsed, subnet, args.output, args.format):
            print(f"  {G}✔{RST}  {args.format.upper()} kaydedildi: {C}{args.output}{RST}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Y}⚠{RST}  Durduruldu.\n")
