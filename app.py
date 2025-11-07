import re
import shlex
import subprocess
from flask import Flask, render_template, request, jsonify, send_file, make_response
from io import BytesIO

app = Flask(__name__)

# ---------------------------
# Predefined Nmap command templates (100)
# Each template should include the token <target> where applicable.
# ---------------------------
NMAP_COMMANDS = [
    {"id": 1, "cmd": "nmap <target>", "desc": "Basic scan of a single host"},
    {"id": 2, "cmd": "nmap <target1> <target2> <target3>", "desc": "Scan multiple hosts"},
    {"id": 3, "cmd": "nmap <ip_range>", "desc": "Scan a range of IPs (e.g., 192.168.1.1-100)"},
    {"id": 4, "cmd": "nmap <subnet/CIDR>", "desc": "Scan a subnet (e.g., 192.168.1.0/24)"},
    {"id": 5, "cmd": "nmap -p 22,80,443 <target>", "desc": "Scan specific ports"},
    {"id": 6, "cmd": "nmap -p- <target>", "desc": "Scan all 65535 ports"},
    {"id": 7, "cmd": "nmap -F <target>", "desc": "Fast scan (top 100 ports)"},
    {"id": 8, "cmd": "nmap -sS <target>", "desc": "Stealthy SYN scan"},
    {"id": 9, "cmd": "nmap -sT <target>", "desc": "TCP connect scan"},
    {"id": 10, "cmd": "nmap -sU <target>", "desc": "UDP scan"},
    {"id": 11, "cmd": "nmap -sV <target>", "desc": "Service/version detection"},
    {"id": 12, "cmd": "nmap -O <target>", "desc": "OS detection"},
    {"id": 13, "cmd": "nmap -A <target>", "desc": "Aggressive scan (OS+version+scripts+traceroute)"},
    {"id": 14, "cmd": "nmap -T4 <target>", "desc": "Timing - faster scans"},
    {"id": 15, "cmd": "nmap -T5 <target>", "desc": "Timing - fastest (noisy)"},
    {"id": 16, "cmd": "nmap -T1 <target>", "desc": "Timing - slow/stealthy"},
    {"id": 17, "cmd": "nmap -T2 <target>", "desc": "Timing - polite"},
    {"id": 18, "cmd": "nmap -Pn <target>", "desc": "Skip host discovery (treat host as up)"},
    {"id": 19, "cmd": "nmap -n <target>", "desc": "Disable DNS resolution"},
    {"id": 20, "cmd": "nmap -R <target>", "desc": "Enable DNS resolution"},
    {"id": 21, "cmd": "nmap -v <target>", "desc": "Verbose output"},
    {"id": 22, "cmd": "nmap -vv <target>", "desc": "Very verbose output"},
    {"id": 23, "cmd": "nmap -oN out.txt <target>", "desc": "Save normal output"},
    {"id": 24, "cmd": "nmap -oX out.xml <target>", "desc": "Save XML output"},
    {"id": 25, "cmd": "nmap -oA fullscan <target>", "desc": "Save all formats"},
    {"id": 26, "cmd": "nmap -sC <target>", "desc": "Script scanning with default scripts"},
    {"id": 27, "cmd": "nmap --script=default <target>", "desc": "Run specific/default NSE scripts"},
    {"id": 28, "cmd": "nmap --script=http* <target>", "desc": "Run HTTP-related NSE scripts"},
    {"id": 29, "cmd": "nmap -p 1-1000 <target>", "desc": "Scan custom port range"},
    {"id": 30, "cmd": "nmap -f <target>", "desc": "Fragment packets"},
    {"id": 31, "cmd": "nmap --mtu 16 <target>", "desc": "Set packet fragment size"},
    {"id": 32, "cmd": "nmap --spoof-mac 0 <target>", "desc": "Spoof MAC address (0=random)"},
    {"id": 33, "cmd": "nmap -D RND:10,ME <target>", "desc": "Decoy scan"},
    {"id": 34, "cmd": "nmap --source-port 53 <target>", "desc": "Set source port"},
    {"id": 35, "cmd": "nmap -sI ZOMBIE_HOST <target>", "desc": "Idle zombie scan (advanced)"},
    {"id": 36, "cmd": "nmap -sO <target>", "desc": "IP protocol scan"},
    {"id": 37, "cmd": "nmap -sn <target>", "desc": "Ping scan only"},
    {"id": 38, "cmd": "nmap -PN <target>", "desc": "Treat host as alive (no ping)"},
    {"id": 39, "cmd": "nmap -P0 <target>", "desc": "Don't ping before scanning"},
    {"id": 40, "cmd": "nmap --traceroute <target>", "desc": "Traceroute"},
    {"id": 41, "cmd": "nmap -R <target>", "desc": "Reverse DNS resolution"},
    {"id": 42, "cmd": "nmap -n <target>", "desc": "No reverse DNS resolution"},
    {"id": 43, "cmd": "nmap --script discovery <target>", "desc": "Discovery scripts"},
    {"id": 44, "cmd": "nmap -sV --version-intensity 9 <target>", "desc": "Max version intensity"},
    {"id": 45, "cmd": "nmap --host-timeout 1800s <target>", "desc": "Host timeout"},
    {"id": 46, "cmd": "nmap --min-rate 50 <target>", "desc": "Minimum packet rate"},
    {"id": 47, "cmd": "nmap --max-rate 500 <target>", "desc": "Maximum packet rate"},
    {"id": 48, "cmd": "nmap --min-hostgroup 16 <target>", "desc": "Min hostgroup size"},
    {"id": 49, "cmd": "nmap --max-retries 2 <target>", "desc": "Max retries"},
    {"id": 50, "cmd": "nmap --scan-delay 0.2s <target>", "desc": "Scan delay"},
    {"id": 51, "cmd": "nmap --max-scan-delay 2s <target>", "desc": "Max scan delay"},
    {"id": 52, "cmd": "nmap -6 <target>", "desc": "IPv6 scan"},
    {"id": 53, "cmd": "nmap --iflist", "desc": "List interfaces (no target)"},
    {"id": 54, "cmd": "nmap -e eth0 <target>", "desc": "Use specific interface"},
    {"id": 55, "cmd": "nmap -iL targets.txt", "desc": "Read targets from file"},
    {"id": 56, "cmd": "nmap --exclude 192.168.1.10 <target>", "desc": "Exclude host"},
    {"id": 57, "cmd": "nmap --excludefile exclude.txt <target>", "desc": "Exclude file"},
    {"id": 58, "cmd": "nmap -iR 100 <target>", "desc": "Random hosts (be careful)"},
    {"id": 59, "cmd": "nmap --randomize-hosts <target>", "desc": "Randomize host order"},
    {"id": 60, "cmd": "nmap -oA --append-output out <target>", "desc": "Append output"},
    {"id": 61, "cmd": "nmap -d <target>", "desc": "Debugging"},
    {"id": 62, "cmd": "nmap -h", "desc": "Help"},
    {"id": 63, "cmd": "nmap --script=\"http-*\" <target>", "desc": "HTTP scripts"},
    {"id": 64, "cmd": "nmap --script smb-enum-users <target>", "desc": "SMB user enum"},
    {"id": 65, "cmd": "nmap --script smb-os-discovery <target>", "desc": "SMB OS discovery"},
    {"id": 66, "cmd": "nmap --script ssl-enum-ciphers <target>", "desc": "SSL/TLS ciphers"},
    {"id": 67, "cmd": "nmap --reason <target>", "desc": "Show reason"},
    {"id": 68, "cmd": "nmap --open <target>", "desc": "Show only open ports"},
    {"id": 69, "cmd": "nmap --packet-trace <target>", "desc": "Packet trace"},
    {"id": 70, "cmd": "nmap --system-dns <target>", "desc": "Use system DNS"},
    {"id": 71, "cmd": "nmap --dns-servers 8.8.8.8,1.1.1.1 <target>", "desc": "Custom DNS servers"},
    {"id": 72, "cmd": "nmap --badsum <target>", "desc": "Bad checksum"},
    {"id": 73, "cmd": "nmap -sA <target>", "desc": "ACK scan"},
    {"id": 74, "cmd": "nmap -sW <target>", "desc": "Window scan"},
    {"id": 75, "cmd": "nmap -sM <target>", "desc": "Maimon scan"},
    {"id": 76, "cmd": "nmap --scanflags SYN,ACK <target>", "desc": "Custom flags"},
    {"id": 77, "cmd": "nmap -6 -sV <target>", "desc": "IPv6 service detection"},
    {"id": 78, "cmd": "nmap --version-all <target>", "desc": "All probes version detection"},
    {"id": 79, "cmd": "nmap -sR <target>", "desc": "RPC scan"},
    {"id": 80, "cmd": "nmap --datadir /usr/share/nmap <target>", "desc": "Custom data dir"},
    {"id": 81, "cmd": "nmap --servicename ftp <target>", "desc": "Service name scan"},
    {"id": 82, "cmd": "nmap --script-timeout 60s <target>", "desc": "Script timeout"},
    {"id": 83, "cmd": "nmap --host-timeout 300s <target>", "desc": "Host timeout"},
    {"id": 84, "cmd": "nmap --scan-delay 1s <target>", "desc": "Adjust delay"},
    {"id": 85, "cmd": "nmap --max-parallelism 10 <target>", "desc": "Max parallelism"},
    {"id": 86, "cmd": "nmap --min-parallelism 2 <target>", "desc": "Min parallelism"},
    {"id": 87, "cmd": "nmap --defeat-rst-ratelimit <target>", "desc": "Defeat RST rate-limit"},
    {"id": 88, "cmd": "nmap --ttl 64 <target>", "desc": "Set TTL"},
    {"id": 89, "cmd": "nmap --data 0x414243 <target>", "desc": "Append hex payload"},
    {"id": 90, "cmd": "nmap --data-string 'Hello' <target>", "desc": "Append data string"},
    {"id": 91, "cmd": "nmap --ip-options LSRR:192.168.1.1 <target>", "desc": "IP options"},
    {"id": 92, "cmd": "nmap --spoof-host somehost <target>", "desc": "Spoof source hostname"},
    {"id": 93, "cmd": "nmap --proxies http://127.0.0.1:8080 <target>", "desc": "Use proxy"},
    {"id": 94, "cmd": "nmap --privileged <target>", "desc": "Assume privileged"},
    {"id": 95, "cmd": "nmap --unprivileged <target>", "desc": "Assume unprivileged"},
    {"id": 96, "cmd": "nmap --release-memory <target>", "desc": "Release memory"},
    {"id": 97, "cmd": "nmap --stats-every 10s <target>", "desc": "Periodic stats"},
    {"id": 98, "cmd": "nmap --resume previous_scan.xml <target>", "desc": "Resume scan"},
    {"id": 99, "cmd": "nmap -oS out.txt <target>", "desc": "Script kiddie output"},
    {"id":100, "cmd": "nmap --stylesheet /path/to/style.xsl <target>", "desc": "Set XSL stylesheet"}
]

# ---------------------------
# Validate target (very basic)
# Accept IPv4, IPv6 (presence of ':') or domain names (letters, digits, hyphen, dot)
# ---------------------------
def validate_target(target: str) -> bool:
    target = target.strip()
    if not target:
        return False
    # IPv4 quick check
    ipv4_re = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ipv4_re.match(target):
        parts = target.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    # IPv6 (basic: contains colon)
    if ':' in target:
        # basic accept — (you can add a stricter ipv6 parse if needed)
        return True
    # Domain name
    domain_re = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.-]{0,252}[A-Za-z0-9]$')
    if domain_re.match(target):
        return True
    return False

# ---------------------------
# Find command template by id
# ---------------------------
def get_command_by_id(cmd_id: int):
    for c in NMAP_COMMANDS:
        if c['id'] == cmd_id:
            return c
    return None

# ---------------------------
# Build argv safely:
# - replace <target> token in template
# - split using shlex.split (handles quoted tokens)
# ---------------------------
def build_argv(template: str, target: str):
    # If template doesn't include <target> we still run it as-is (some commands like --iflist)
    replaced = template.replace('<target>', target)
    # Use shlex.split to produce argv list (safe to pass to subprocess without shell=True)
    return shlex.split(replaced)

# ---------------------------
# Run command endpoint (AJAX)
# ---------------------------
@app.route("/run", methods=["POST"])
def run_command():
    data = request.json or {}
    try:
        cmd_id = int(data.get("cmd_id", 0))
    except Exception:
        return jsonify({"ok": False, "error": "Invalid command id"}), 400
    target = (data.get("target") or "").strip()
    cmd_template = get_command_by_id(cmd_id)
    if not cmd_template:
        return jsonify({"ok": False, "error": "Unknown command"}), 400

    # if template includes <target>, validate
    if '<target>' in cmd_template['cmd']:
        if not validate_target(target):
            return jsonify({"ok": False, "error": "Invalid target. Use IPv4/IPv6/domain."}), 400
    else:
        # no target needed; ignore provided target
        target = ""

    argv = build_argv(cmd_template['cmd'], target)
    # safety: ensure the executable is 'nmap' or a known safe exe (prevent executing arbitrary binaries)
    if not argv or argv[0] != 'nmap':
        return jsonify({"ok": False, "error": "Only nmap-based commands are allowed."}), 400

    # run command safely (no shell), with timeout and size limit
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        out = completed.stdout or ''
        err = completed.stderr or ''
        rc = completed.returncode
        return jsonify({"ok": True, "stdout": out, "stderr": err, "returncode": rc})
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "error": "Command timed out (120s)."}), 504
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ---------------------------
# Home page
# ---------------------------
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", commands=NMAP_COMMANDS)

# ---------------------------
# Download .sh generator for selected commands (ids and target)
# POST with JSON: { "ids": [1,5,8], "target": "1.2.3.4", "mode": "inline" }
# ---------------------------
@app.route("/download_script", methods=["POST"])
def download_script():
    data = request.json or {}
    ids = data.get("ids", [])
    target = (data.get("target") or "").strip()
    mode = data.get("mode", "prompt")  # "prompt" or "inline"

    templates = []
    for i in ids:
        cmd = get_command_by_id(int(i))
        if cmd:
            templates.append(cmd['cmd'])
    if not templates:
        return jsonify({"ok": False, "error": "No commands selected."}), 400

    # if any template needs target and mode inline requested, validate target
    for t in templates:
        if '<target>' in t and mode == 'inline':
            if not validate_target(target):
                return jsonify({"ok": False, "error": "Invalid inline target."}), 400

    # build script text
    lines = []
    lines.append("#!/bin/bash")
    lines.append("# MRM-generated Nmap batch script")
    lines.append('# Use only on authorized systems. You are responsible for scans.')
    lines.append("")
    if mode == 'inline' and target:
        lines.append(f'TARGET="{target}"')
    else:
        lines.append('read -p "Enter target (e.g. 192.168.1.1 or example.com): " TARGET')
    lines.append('')
    lines.append('echo "Starting MRM Nmap batch..."')
    lines.append('')

    for idx, tmpl in enumerate(templates, start=1):
        # replace <target> with "$TARGET" so shell expands variable
        cmd_line = tmpl.replace('<target>', '"$TARGET"')
        lines.append(f'echo ">>> Command {idx}: {cmd_line}"')
        lines.append(cmd_line)
        lines.append('')  # blank line

    lines.append('echo "MRM batch finished."')
    script_text = "\n".join(lines)

    # return as downloadable file
    buf = BytesIO(script_text.encode('utf-8'))
    return send_file(buf, as_attachment=True, download_name="mrm-nmap-batch.sh", mimetype="application/x-sh")

if __name__ == "__main__":
    # run on localhost only
    app.run(host="127.0.0.1", port=5000, debug=True)
