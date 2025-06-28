#!/bin/env python3

import os
import subprocess
import time
import argparse
import scapy.all as scapy
from collections import defaultdict
from colorama import Fore
import logging
import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog
import csv
from datetime import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from pathlib import Path

# Color constants
g = Fore.GREEN
r = Fore.RED
lr = Fore.LIGHTRED_EX
y = Fore.YELLOW
b = Fore.BLUE
c = Fore.CYAN
lc = Fore.LIGHTCYAN_EX
m = Fore.MAGENTA
RE = Fore.RESET

# Logging configuration
'''logging.basicConfig(filename='alerts.log', level=logging.INFO,
                   format='%(asctime)s %(levelname)s:%(message)s')'''

# Argument parsing
parser = argparse.ArgumentParser(description='MALICIOUS TRAFFIC INTERCEPTOR!', add_help=False, formatter_class=argparse.RawTextHelpFormatter)

help_text = """
X4V1ER Firewall Help:
  *Networking & Detection*
    -e,   --exclude <IPs>               Comma-separated trusted IPs to exclude from monitoring
    -d,   --destination_ip <IP>         Target IP address to protect

  *Detection Thresholds*
    -rt,  --rate_threshold <num>        Request rate limit threshold (default: 5/10sec)
    -pt,  --port_threshold <num>        Port scan detection threshold (default: 5 ports)
    -ft,  --fail_threshold <num>        Failed login attempt threshold (default: 5 attempts)
    -sw,  --scan_window <sec>           Time window for port scan detection (default: 60s)

  *Detection Mode*
    -m,   --mode                        Preset modes for detection sensitivity [default,aggressive,realistic]

  *Output Options*
    -ex,  --export <file.csv>           Export attack data in csv file
    -js,  --json-export <file.js>       Export attack data to a JSON file

  *General Options*
    -i,   --iface <interface>           Network interface to monitor (default: auto-detect)
    -g,   --gui                         Enable GUI mode
    -at,  --auto-block                  Block any attack automatically
    -st,  --send-to <email>             Receiver Email
    -v,   --version                     Version of X4V1ER
    -h,   --help                        Show this help message
"""





args_group = parser.add_argument_group('Options')
args_group.add_argument('-d', '--destination_ip',
                    help='Enter your destination IP', metavar='')
args_group.add_argument('-e', '--exclude', default='',
                    help='Trusted IP(s), comma-separated', metavar='')

args_group.add_argument('-rt', '--rate_threshold', type=int, default=5,
                    help='Rate limit threshold', metavar='')
args_group.add_argument('-pt', '--port_threshold', type=int, default=5,
                    help='Port scan threshold', metavar='')
args_group.add_argument('-ft', '--fail_threshold', type=int, default=5,
                    help='Failed login threshold', metavar='')
args_group.add_argument('-sw', '--scan_window', type=int, default=60,
                    help='Time window for port scan detection (seconds)', metavar='')

args_group.add_argument('-h', '--help', action='store_true',
                    help=argparse.SUPPRESS)
args_group.add_argument('-g', '--gui', action='store_true',help='Run the application in GUI mode')
args_group.add_argument('-i', '--iface', type=str, default=None,
                    help='Network interface to monitor', metavar='')


args_group.add_argument('-at', '--auto-block', action='store_true',
                    help='Automatically block attackers and generate reports')
args_group.add_argument('-ex', '--export', type=str, metavar='FILE.csv',
                    help='Export attack data to a readable file')
args_group.add_argument('-st', '--send-to', type=str, metavar='receiver',
                    help='Receiver email')

args_group.add_argument('-v', '--version', action='store_true',
                    help=argparse.SUPPRESS)


args_group.add_argument('-js', '--json-export', type=str, metavar='FILE.json',
                    help='Export attack data to a JSON file')

args_group.add_argument('--mode', choices=['default', 'aggressive', 'realistic'], default='default',
                    help='Preset modes for detection sensitivity')

args = parser.parse_args()

if os.name == 'posix' and os.geteuid() != 0:
    print(f"[{y}!{RE}] Please run as root")
    exit(1)

# Trusted IPs
TRUSTED_IPS = list((args.exclude).strip().split(',')) if  args.exclude.strip() else []

import socket

# Dynamically determine local IP
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # IP doesn't have to be reachable
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"  # Fallback to loopback if detection fails

LOCAL_IP = get_local_ip()

if LOCAL_IP not in TRUSTED_IPS and args.help == False and args.version == False:
    TRUSTED_IPS.append(LOCAL_IP)
    print(f"[{b}INFO{RE}] Auto-excluding detected local IP: {LOCAL_IP} to prevent self-blocking")


# Thresholds
IP_BLOCK_THRESHOLD = args.rate_threshold
PORT_SCAN_THRESHOLD = args.port_threshold
SUSPICIOUS_REQUESTS_THRESHOLD = args.fail_threshold
SCAN_TIME_WINDOW = args.scan_window

if args.mode == 'aggressive':
    IP_BLOCK_THRESHOLD = 10
    PORT_SCAN_THRESHOLD = 2
    SUSPICIOUS_REQUESTS_THRESHOLD = 2
    SCAN_TIME_WINDOW = 30
    print(f"[{m}MODE{RE}] Aggressive mode activated")
elif args.mode == 'realistic':
    IP_BLOCK_THRESHOLD = 20
    PORT_SCAN_THRESHOLD = 3
    SUSPICIOUS_REQUESTS_THRESHOLD = 3
    SCAN_TIME_WINDOW = 60
    print(f"[{m}MODE{RE}] Realistic mode activated")
else:
    if args.help == False and args.version == False:
        print(f"[{m}MODE{RE}] Default mode (manual thresholds)")


# Attack patterns
SQL_INJECTION_KEYWORDS = ['select', 'drop', 'union', 'insert', 'update', 'delete', 'or 1=1']
XSS_KEYWORDS = ['<script>', '</script>', 'javascript:', 'onerror', 'onload']

# Tracking structures
ip_request_count = defaultdict(int)
ip_ports_tried = defaultdict(lambda: {'ports': set(), 'time': time.time()})
ip_failed_requests = defaultdict(int)
ip_last_request_time = defaultdict(float)
ip_syn_count = defaultdict(int)


# Load previously blocked IPs
BLOCKED_IPS_FILE = Path("blocked_ips.txt")
BLOCKED_IPS = set()
if BLOCKED_IPS_FILE.exists():
    BLOCKED_IPS = set(BLOCKED_IPS_FILE.read_text().splitlines())

# Global flags
auto_block_enabled = False
sniff_thread = None

def generate_html_report(attacker_ip, reason, details):
    """Generate HTML report with improved styling"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    filename = f"x4v1er_report_{attacker_ip.replace('.', '_')}_{int(time.time())}.html"
    report_path = Path("reports") / filename
    report_path.parent.mkdir(parents=True, exist_ok=True)

    # Format details with proper line breaks and indentation
    formatted_details = "<br>".join([f"• {line}" for line in str(details).split('\n') if line.strip()])

    html_content = f"""   
    <html>
    <head>
      <style>
        body {{
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          background-color: #f5f5f5;
          padding: 20px;
          color: #333;
        }}
        .container {{
          background-color: white;
          padding: 25px;
          border-radius: 10px;
          max-width: 700px;
          margin: 20px auto;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .logo {{
          font-size: 28px;
          font-weight: bold;
          color: #d9534f;
          text-align: center;
          margin-bottom: 25px;
          font-family: 'Courier New', monospace;
        }}
        .section-title {{
          font-size: 18px;
          font-weight: bold;
          margin: 20px 0 10px 0;
          color: #2c3e50;
          border-bottom: 1px solid #eee;
          padding-bottom: 5px;
        }}
        .detail-item {{
          margin: 8px 0;
          line-height: 1.5;
        }}
        .details-box {{
          background-color: #f9f9f9;
          border: 1px solid #e1e1e1;
          padding: 15px;
          border-radius: 5px;
          margin-top: 15px;
          font-family: 'Consolas', monospace;
          font-size: 14px;
        }}
        .footer {{
          margin-top: 30px;
          font-size: 12px;
          color: #7f8c8d;
          text-align: center;
          border-top: 1px solid #eee;
          padding-top: 15px;
        }}
        .bullet-point {{
          color: #d9534f;
          margin-right: 8px;
        }}
      </style>
    </head>
    <body>
      <div class="container">
        <div class="logo">X4V1ER THREAT REPORT</div>
        <div class="section-title">🚨 Blocked Threat</div>
        <div class="detail-item"><strong>Blocked IP:</strong> <span style="color:#d9534f">{attacker_ip}</span></div>
        <div class="detail-item"><strong>Reason:</strong> {reason}</div>
        <div class="detail-item"><strong>Date & Time:</strong> {timestamp}</div>
        
        <div class="section-title">📊 Activity Details</div>
        <div class="details-box">
          {formatted_details}
        </div>
        
        <div class="footer">Generated by X4V1ER Firewall Protection System</div>
      </div>
    </body>
    </html>
    """

    report_path.write_text(html_content)
    print(f"[REPORT] Threat report saved: {report_path}")
    return report_path


def send_report_email():
    """Send the latest report via email using config file"""
    try:
        import json
        config_path = Path("config.json")
        if not config_path.exists():
            print("[ERROR] Email config not found in config.json")
            return

        config = json.loads(config_path.read_text())
        sender_email = config.get("sender_email")
        sender_password = config.get("sender_password")
        receiver_email = args.send_to

        if not all([sender_email, sender_password, receiver_email]):
            print("[ERROR] Config file missing required fields")
            return

        report_files = sorted(Path("reports").glob("*.html"), key=lambda f: f.stat().st_mtime, reverse=True)
        if not report_files:
            print(f"[{y}WARN{RE}] No report to send")
            return

        latest_report = report_files[0]
        html_content = latest_report.read_text()

        msg = MIMEMultipart()
        msg['Subject'] = "🚨 X4V1ER Threat Report"
        msg['From'] = sender_email
        msg['To'] = receiver_email

        msg.attach(MIMEText(html_content, 'html'))
        with open(latest_report, 'rb') as f:
            attach = MIMEApplication(f.read(), _subtype="html")
            attach.add_header('Content-Disposition', 'attachment', filename=latest_report.name)
            msg.attach(attach)

        if "gmail.com" in sender_email:
            smtp_server = "smtp.gmail.com"
        elif "outlook.com" in sender_email or "hotmail.com" in sender_email:
            smtp_server = "smtp.office365.com"
        else:
            print("[ERROR] Unsupported email provider.")
            return

        with smtplib.SMTP(smtp_server, 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())

        print(f"[EMAIL] Report sent to {receiver_email}")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")

def block_ip(ip, reason="Manual block", details="N/A"):
    """Block an IP address using system firewall"""
    if ip in TRUSTED_IPS or ip in BLOCKED_IPS:
        print(f"[{y}WARN{RE}] Attempted to block trusted IP: {ip}")
        return

    try:
        if os.name == 'posix':
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        elif os.name == 'nt':
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", 
                           f"name=Block {ip}", "dir=in", "action=block", 
                           f"remoteip={ip}"], check=True)
        
        print(f"[BLOCK] Blocked {ip} ({reason})")
        logging.warning(f"Blocked IP {ip} for {reason}. Details: {details}")
        BLOCKED_IPS.add(ip)
        BLOCKED_IPS_FILE.write_text('\n'.join(BLOCKED_IPS))
        generate_html_report(ip, reason, details)

        if args.send_to and auto_block_enabled:
            send_report_email()
    
    except subprocess.CalledProcessError as e:
        print(f"[{lr}ERROR{RE}] Failed to block IP {ip}: {e}")
        logging.error(f"Failed to block IP {ip}: {e}")

def detect_rate_limiting(ip, current_time):
    """Detect excessive request rates from an IP"""
    if ip in TRUSTED_IPS or ip in BLOCKED_IPS:
        return False

    # Reset counter if last request was more than 10 seconds ago
    if current_time - ip_last_request_time.get(ip, 0) > 10:
        ip_request_count[ip] = 0

    ip_request_count[ip] += 1
    ip_last_request_time[ip] = current_time

    if ip_request_count[ip] > IP_BLOCK_THRESHOLD:
        msg = f"Rate-limiting detected from {ip}. Requests: {ip_request_count[ip]} (threshold: {IP_BLOCK_THRESHOLD})"
        print(f"[{b}ALERT{RE}] {msg}")
        logging.warning(msg)
        return True
    return False

def detect_port_scanning(ip, current_time):
    """Detect port scanning activity from an IP"""
    if ip in TRUSTED_IPS or ip in BLOCKED_IPS:
        return False

    # Reset if outside our time window
    if current_time - ip_ports_tried[ip]['time'] > SCAN_TIME_WINDOW:
        ip_ports_tried[ip] = {'ports': set(), 'time': current_time}

    # Check if threshold reached
    if len(ip_ports_tried[ip]['ports']) > PORT_SCAN_THRESHOLD:
        ports = sorted(ip_ports_tried[ip]['ports'])
        msg = f"Port scan detected from {ip}. Ports tried: {len(ports)} (threshold: {PORT_SCAN_THRESHOLD})"
        print(f"[{b}ALERT{RE}] {msg}")
        logging.warning(f"{msg} Ports: {ports}")
        return True
    return False

def detect_brute_force(ip, current_time):
    """Detect potential brute force attempts"""
    if ip in TRUSTED_IPS or ip in BLOCKED_IPS:
        return False

    # Reset counter if last attempt was more than 5 minutes ago
    if current_time - ip_last_request_time.get(ip, 0) > 300:
        ip_failed_requests[ip] = 0

    if ip_failed_requests[ip] > SUSPICIOUS_REQUESTS_THRESHOLD:
        msg = f"Brute force detected from {ip}. Failed attempts: {ip_failed_requests[ip]} (threshold: {SUSPICIOUS_REQUESTS_THRESHOLD})"
        print(f"[{b}ALERT{RE}] {msg}")
        logging.warning(msg)
        return True
    return False

def detect_sql_injection(payload):
    """Detect SQL injection patterns"""
    payload_lower = payload.lower()
    return any(keyword in payload_lower for keyword in SQL_INJECTION_KEYWORDS)

def detect_xss(payload):
    """Detect XSS patterns"""
    payload_lower = payload.lower()
    return any(keyword in payload_lower for keyword in XSS_KEYWORDS)

def detect_syn_flood(packet, ip_src):
    """Detect SYN flood attempts"""
    if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':
        ip_syn_count[ip_src] += 1
        
        # Check for more than 10 SYN packets in 1 second
        if ip_syn_count[ip_src] > 10:
            msg = f"SYN flood detected from {ip_src}. SYN packets: {ip_syn_count[ip_src]}"
            print(f"[{b}ALERT{RE}] {msg}")
            logging.warning(msg)
            return True
    return False

def packet_callback(packet):
    """Callback function for packet processing"""
    try:
        if not packet.haslayer(scapy.IP):
            return

        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        current_time = time.time()

        print(f"DEBUG: Processing packet from {ip_src} to {ip_dst}")  # Debug line

        if ip_src in TRUSTED_IPS:
            return

        # Rate limiting detection
        if detect_rate_limiting(ip_src, current_time) and auto_block_enabled:
            block_ip(ip_src, "Rate limiting", f"{ip_request_count[ip_src]} requests in 10s")

        # Port scanning detection
        if packet.haslayer(scapy.TCP) and ip_dst == args.destination_ip:
            ip_ports_tried[ip_src]['ports'].add(packet[scapy.TCP].dport)
            if detect_port_scanning(ip_src, current_time) and auto_block_enabled:
                ports = sorted(ip_ports_tried[ip_src]['ports'])
                block_ip(ip_src, "Port scanning", f"Scanned {len(ports)} ports: {ports}")

        # Brute force detection
        if packet.haslayer(scapy.TCP) and ip_dst == args.destination_ip:
            if packet[scapy.TCP].flags & 0x04:  # RST flag
                ip_failed_requests[ip_src] += 1
                if detect_brute_force(ip_src, current_time) and auto_block_enabled:
                    block_ip(ip_src, "Brute force", f"{ip_failed_requests[ip_src]} failed attempts")

        # Application layer attacks
        if packet.haslayer(scapy.Raw) and ip_dst == args.destination_ip:
            try:
                payload = packet[scapy.Raw].load.decode(errors='ignore')
                if detect_sql_injection(payload):
                    gui_log(f"[ALERT] SQLi from {ip_src}: {payload[:100]}...")
                    if auto_block_enabled:
                        block_ip(ip_src, "SQL injection", payload[:200])
                if detect_xss(payload):
                    gui_log(f"[ALERT] XSS from {ip_src}: {payload[:100]}...")
                    if auto_block_enabled:
                        block_ip(ip_src, "XSS attempt", payload[:200])
            except Exception as e:
                pass

        # SYN flood detection
        if detect_syn_flood(packet, ip_src) and auto_block_enabled:
            block_ip(ip_src, "SYN flood", f"{ip_syn_count[ip_src]} SYN packets")

    except Exception as e:
        logging.error(f"Error processing packet: {str(e)}")
        print(f"ERROR: {str(e)}")

def start_sniffing():
    """Start packet sniffing with interface detection"""
    print(f"[{b}INF{RE}] Starting packet sniffing for {args.destination_ip}...")
    
    sniff_filter = f"host {args.destination_ip}"
    sniff_params = {
        'prn': packet_callback,
        'store': 0,
        'filter': sniff_filter,
    }
    
    if args.iface:
        sniff_params['iface'] = args.iface
        print(f"[{b}INF{RE}] Using specified interface: {args.iface}")
    else:
        print(f"[{b}INF{RE}] Using default interface")
    
    try:
        scapy.sniff(**sniff_params)
    except Exception as e:
        print(f"[{lr}ERR{RE}] Sniffing error: {e}")
        logging.error(f"Sniffing failed: {e}")
        if "Operation not permitted" in str(e):
            print(f"[{lr}ERR{RE}] Try running with sudo/administrator privileges")

# GUI Functions
def gui_log(msg):
    """Log message to both console and GUI"""
    print(msg)
    logging.info(msg)
    if 'gui_log_function' in globals():
        gui_log_function(msg)

def manage_whitelist():
    """GUI for managing trusted IPs"""
    def add_ip():
        new_ip = simpledialog.askstring("Add Trusted IP", "Enter IP to trust:")
        if new_ip and new_ip not in TRUSTED_IPS:
            TRUSTED_IPS.append(new_ip)
            update_list()

    def remove_selected():
        selected = whitelist_box.curselection()
        if not selected:
            return
        ip = whitelist_box.get(selected[0])
        TRUSTED_IPS.remove(ip)
        update_list()

    def update_list():
        whitelist_box.delete(0, tk.END)
        for ip in TRUSTED_IPS:
            whitelist_box.insert(tk.END, ip)

    wl = tk.Toplevel()
    wl.title("Manage Trusted IPs")
    whitelist_box = tk.Listbox(wl, width=40)
    whitelist_box.pack(padx=10, pady=5)
    update_list()
    tk.Button(wl, text="Add IP", command=add_ip).pack(pady=5)
    tk.Button(wl, text="Remove Selected", command=remove_selected).pack(pady=5)

def launch_gui():
    """Launch the GUI interface"""
    global auto_block_enabled, sniff_thread, gui_log_function

    def refresh_list():
        """Refresh the list of suspicious IPs"""
        listbox.delete(0, tk.END)
        current_time = time.time()
        
        for ip in set(list(ip_request_count.keys()) + 
                     list(ip_ports_tried.keys()) + 
                     list(ip_failed_requests.keys())):
            
            alerts = []
            if ip_request_count.get(ip, 0) > IP_BLOCK_THRESHOLD:
                alerts.append(f"Rate: {ip_request_count[ip]}/{IP_BLOCK_THRESHOLD}")
            
            if len(ip_ports_tried.get(ip, {}).get('ports', set())) > PORT_SCAN_THRESHOLD:
                ports = ip_ports_tried[ip]['ports']
                alerts.append(f"Ports: {len(ports)}/{PORT_SCAN_THRESHOLD}")
            
            if ip_failed_requests.get(ip, 0) > SUSPICIOUS_REQUESTS_THRESHOLD:
                alerts.append(f"Fails: {ip_failed_requests[ip]}/{SUSPICIOUS_REQUESTS_THRESHOLD}")
            
            if alerts:
                listbox.insert(tk.END, f"{ip} - {' | '.join(alerts)}")

    def block_selected_ip():
        """Block selected IP with styled details"""
        selected = listbox.curselection()
        if not selected:
            messagebox.showinfo("Info", "Select an IP to block.")
            return
        
        ip = listbox.get(selected[0]).split()[0]
        
        # Build detailed report
        details = []
        reasons = []
        
        # Rate Limiting
        if ip_request_count.get(ip, 0) > IP_BLOCK_THRESHOLD:
            reasons.append("Rate Limiting")
            details.append(f"Excessive requests: {ip_request_count[ip]} (Threshold: {IP_BLOCK_THRESHOLD})")
            details.append(f"Last request time: {datetime.fromtimestamp(ip_last_request_time[ip]).strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Port Scanning
        if len(ip_ports_tried.get(ip, {}).get('ports', set())) > PORT_SCAN_THRESHOLD:
            reasons.append("Port Scanning")
            ports = sorted(ip_ports_tried[ip]['ports'])
            details.append(f"Scanned ports: {len(ports)} (Threshold: {PORT_SCAN_THRESHOLD})")
            details.append(f"Port range: {ports[0]}-{ports[-1]}")
            details.append(f"Sample ports: {', '.join(map(str, ports[:5]))}{'...' if len(ports) > 5 else ''}")
        
        # Brute Force
        if ip_failed_requests.get(ip, 0) > SUSPICIOUS_REQUESTS_THRESHOLD:
            reasons.append("Brute Force")
            details.append(f"Failed attempts: {ip_failed_requests[ip]} (Threshold: {SUSPICIOUS_REQUESTS_THRESHOLD})")
            details.append(f"Last attempt: {datetime.fromtimestamp(ip_last_request_time[ip]).strftime('%Y-%m-%d %H:%M:%S')}")
        
        if not reasons:
            reasons = ["Manual Block"]
            details = ["Administrator manually blocked this IP"]
        
        # Format the details for GUI display
        gui_details = "\n".join([f"• {line}" for line in details])
        report_details = "\n".join(details)
        
        block_ip(ip, " | ".join(reasons), report_details)
        
        # Update GUI log with styled text
        log_message = (
            f"[BLOCKED] {ip}\n"
            f"Reason: {', '.join(reasons)}\n"
            f"Details:\n{gui_details}\n"
            f"{'-'*40}"
        )
        gui_log(log_message)
        refresh_list()

    def toggle_autoblock():
        """Toggle auto-blocking mode"""
        global auto_block_enabled
        auto_block_enabled = not auto_block_enabled
        state = "ON" if auto_block_enabled else "OFF"
        toggle_btn.config(text=f"Auto-Block: {state}")
        gui_log(f"Auto-blocking {state}")

    def export_report():
        """Export report to CSV"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")]
        )
        if not file_path:
            return
        
        with open(file_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['IP', 'Request Count', 'Ports Tried', 'Failed Attempts', 'Last Alert'])
            
            for ip in set(list(ip_request_count.keys()) + 
                         list(ip_ports_tried.keys()) + 
                         list(ip_failed_requests.keys())):
                
                writer.writerow([
                    ip,
                    ip_request_count.get(ip, 0),
                    len(ip_ports_tried.get(ip, {}).get('ports', set())),
                    ip_failed_requests.get(ip, 0),
                    datetime.fromtimestamp(ip_last_request_time.get(ip, 0)).strftime('%Y-%m-%d %H:%M:%S')
                ])
        
        messagebox.showinfo("Success", f"Report exported to {file_path}")

    def on_close():
        """Handle window close event"""
        if sniff_thread:
            sniff_thread.stop()
        root.destroy()

    # Main GUI window
    root = tk.Tk()
    root.title(f"Traffic Monitor - {args.destination_ip}")
    root.protocol("WM_DELETE_WINDOW", on_close)

    # IP Listbox
    list_frame = tk.Frame(root)
    list_frame.pack(pady=10)
    tk.Label(list_frame, text="Suspicious IPs:").pack()
    listbox = tk.Listbox(list_frame, width=80, height=15)
    listbox.pack(padx=10)

    # Button Frame
    button_frame = tk.Frame(root)
    button_frame.pack(pady=10)

    # Buttons
    tk.Button(button_frame, text="Refresh", command=refresh_list).grid(row=0, column=0, padx=5)
    tk.Button(button_frame, text="Block IP", command=block_selected_ip).grid(row=0, column=1, padx=5)
    toggle_btn = tk.Button(button_frame, text=f"Auto-Block: {'ON' if auto_block_enabled else 'OFF'}", 
                          command=toggle_autoblock)
    toggle_btn.grid(row=0, column=2, padx=5)
    tk.Button(button_frame, text="Whitelist", command=manage_whitelist).grid(row=0, column=3, padx=5)
    tk.Button(button_frame, text="Export", command=export_report).grid(row=0, column=4, padx=5)
    tk.Button(button_frame, text="Send Report", command=send_report_email).grid(row=0, column=5, padx=5)

    # Log Frame
    log_frame = tk.Frame(root)
    log_frame.pack(pady=10)
    tk.Label(log_frame, text="Event Log:").pack()
    log_text = tk.Text(log_frame, width=100, height=15, state=tk.DISABLED, bg='black', fg='white')
    log_text.pack(padx=10)

    quit_btn = tk.Button(root, text="Quit", command=on_close)
    quit_btn.pack(pady=5)

    # GUI logging function
    def gui_logger(msg):
        """Thread-safe GUI logging"""
        def append_log():
            log_text.config(state=tk.NORMAL)
            log_text.insert(tk.END, msg + "\n")
            log_text.see(tk.END)
            log_text.config(state=tk.DISABLED)
        root.after(0, append_log)

    gui_log_function = gui_logger

    # Initial refresh
    refresh_list()
    gui_log("GUI initialized. Starting monitoring...")
    root.mainloop()

def main():
    """Main function with improved interface detection"""
    print(f"\n[{b}X4V1ER MALICIOUS TRAFFIC INTERCEPTOR{RE}]")
    print(f"[{b}INF{RE}] Monitoring traffic for {args.destination_ip}")
    
    if not args.iface:
        print(f"[{y}WARN{RE}] No interface specified. Using default.")
        print(f"[{b}INF{RE}] Available interfaces:")
        print(scapy.get_if_list())
    
    print(f"[{b}CONFIG{RE}] Rate threshold: {IP_BLOCK_THRESHOLD}/10s | Port threshold: {PORT_SCAN_THRESHOLD} | Fail threshold: {SUSPICIOUS_REQUESTS_THRESHOLD}")

    global sniff_thread, auto_block_enabled
    if args.auto_block:
        auto_block_enabled = True
        print(f"[{b}INFO{RE}] Auto-block enabled")

    if args.export:
        export_file = args.export
        with open(export_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['IP', 'Request Count', 'Ports Tried', 'Failed Attempts', 'Last Alert'])
            for ip in set(list(ip_request_count.keys()) + 
                         list(ip_ports_tried.keys()) + 
                         list(ip_failed_requests.keys())):
                writer.writerow([
                    ip,
                    ip_request_count.get(ip, 0),
                    len(ip_ports_tried.get(ip, {}).get('ports', set())),
                    ip_failed_requests.get(ip, 0),
                    datetime.fromtimestamp(ip_last_request_time.get(ip, 0)).strftime('%Y-%m-%d %H:%M:%S')
                ])
        print(f"[EXPORT] Data exported to {export_file}")


    if args.gui:
        auto_block_enabled = True
        sniff_thread = scapy.AsyncSniffer(
            prn=packet_callback,
            store=0,
            filter=f"host {args.destination_ip}",
            iface=args.iface
        )
        sniff_thread.start()
        launch_gui()
    else:
        start_sniffing()

if __name__ == "__main__":
    if args.help:
        print(help_text)
        os._exit(0)
    if args.version:
        print(f"[{b}INF{RE}] X4v1er Firewall Version: v1.0")
        os._exit(0)
    if not args.destination_ip and not args.gui:
        print(f"[{lr}ERR{RE}] Error: Destination IP is required in CLI mode")
        os._exit(0)
    else:
        main()