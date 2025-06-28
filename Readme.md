![ChatGPT Image Jun 26, 2025, 01_01_57 PM](https://github.com/user-attachments/assets/b46574ba-c272-4351-b6a0-577f641a5386)
# 📘 X4V1ER Firewall Documentation

## Overview

**X4V1ER Firewall** is a Python-based network security tool designed to monitor and intercept malicious traffic in real-time. It features both a command-line interface (CLI) and a graphical user interface (GUI), offering automated attack detection, reporting, and IP blocking capabilities.

## 🔧 Features

- Real-time traffic monitoring
- Detection of:
  - Port scanning
  - Brute-force attempts
  - Rate-limiting violations
  - SQL injection (SQLi)
  - Cross-site scripting (XSS)
  - SYN flood attacks
- Automatic threat blocking with firewall rules
- HTML report generation
- Email alerting (Gmail/Outlook/Hotmail)
- Export to CSV/JSON
- GUI dashboard for IP management

## 🏁 Getting Started

```Download The Repo
  git clone https://github.com/DR4X-c0d3r/x4v1er.git \
  cd x4v1er/ 
```

### Requirements

- Python 3.x
- Root/admin privileges
- Linux or Windows
- Required libraries:
```bash
  pip install scapy colorama tkinter # If you get any error, check if you already installed pip then create virtual env with python
  # create python env
  python3 -m env firewall-env
  # reinstall libraries
  pip install -r requirements; sudo apt install python3-tk #for tkinter
  sudo apt install scapy
```

### Run It From Cmd

```bash
  sudo cp firewall.py /usr/bin/x4v1er \
  chmod +x /usr/bin/x4v1er \
  x4v1er -v #version of x4v1er
```

### Email Configuration

Create a `config.json` file:
```json
{
  "sender_email": "example@gmail.com",
  "sender_password": "your_app_password"
}
```
Use an [App Password](https://support.google.com/accounts/answer/185833) if using Gmail with 2FA.

## 🚀 Usage

### CLI Mode

```bash
sudo python3 firewall.py -d 192.168.1.1 -at -st you@example.com
```

### GUI Mode

```bash
sudo python3 firewall.py -d 192.168.1.1 -g
```

## 🧪 Command-Line Options

| Option | Description |
|--------|-------------|
| `-d, --destination_ip` | IP to protect |
| `-e, --exclude` | Comma-separated trusted IPs |
| `-rt, --rate_threshold` | Max requests per 10s (default: 5) |
| `-pt, --port_threshold` | Max port attempts (default: 5) |
| `-ft, --fail_threshold` | Max failed logins (default: 5) |
| `-sw, --scan_window` | Time window for port scan (default: 60s) |
| `-at, --auto-block` | Auto block threats |
| `-g, --gui` | Launch GUI |
| `-i, --iface` | Network interface |
| `-ex, --export` | Export attack data to CSV |
| `-js, --json-export` | Export attack data to JSON |
| `-st, --send-to` | Email report to address |
| `--mode` | Detection sensitivity: default/aggressive/realistic |
| `-v, --version` | Print version |
| `-h, --help` | Show help |

## 🛡️ Detection Methods

### 1. Rate Limiting
- > N requests per 10 seconds from a single IP

### 2. Port Scanning
- > Scans multiple ports within a time window

### 3. Brute Force
- > Excessive TCP RST flags indicate failed login attempts

### 4. SYN Flood
- > >10 SYN packets per second

### 5. SQL Injection
- > Packet contains SQL keywords

### 6. XSS
- > Packet contains suspicious HTML/script tags

## 🧰 System Components

- `firewall.py`: Core logic for packet processing, attack detection, and GUI
- `config.json`: Email configuration
- `blocked_ips.txt`: Persistent list of blocked IPs
- `reports/`: Stores HTML threat reports

## 📧 Email Reporting

- Uses `smtplib` and `email.mime`
- Supported providers: Gmail, Outlook, Hotmail

## 🖥️ GUI Highlights

- Suspicious IP list
- Manual block and auto-block toggle
- Export reports
- Whitelist management
- Event log display

## 🔐 Security Note

- Run with root or admin privileges
- Use app passwords instead of real passwords

## 📂 Example Report

HTML file includes:
- IP address
- Reason for block
- Timestamp
- Activity summary

## 📦 Future Improvements

- IPv6 support
- Remote dashboards
- Blacklist integration
- ML-based detection
