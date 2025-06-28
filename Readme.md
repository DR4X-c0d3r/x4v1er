![ChatGPT Image Jun 26, 2025, 01_01_57 PM](https://github.com/user-attachments/assets/d2ac238a-7a7a-498b-aecc-d143672d45a4)

# X4V1ER Firewall Documentation

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

## :checkered_flag: Getting Started

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
  sudo x4v1er -v #version of x4v1er and required root user
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

1. **Rate Limiting** – N requests per 10 seconds from a single IP  
2. **Port Scanning** – Multiple ports scanned in short time  
3. **Brute Force** – Excessive failed login attempts (RST packets)  
4. **SYN Flood** – SYN packets > 10/sec  
5. **SQL Injection** – Payload with suspicious SQL keywords  
6. **XSS** – Malicious HTML/script tags in packet data

## 🧰 System Components

- `firewall.py`: Core logic for packet processing, attack detection, and GUI  
- `config.json`: Email configuration  
- `blocked_ips.txt`: Persistent list of blocked IPs  
- `reports/`: Stores HTML threat reports

## 📧 Email Reporting

- Uses `smtplib` and `email.mime`  
- Supported: Gmail, Outlook, Hotmail

## 🖥️ GUI Highlights

- Suspicious IP list  
- Manual and auto-block toggle  
- Export reports  
- Whitelist management  
- Event log display

## 🔐 Security Note

- Run with root or admin privileges  
- Use app passwords for Gmail security

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

## 📸 Screenshots


### Exclude Trusted Ips And Export File Csv
![exclude_trusted_ips_and_export_file_csv](https://github.com/user-attachments/assets/8fdbf2c8-ff4a-4f1b-b5e0-10c392ff7212)

### Gui
![gui](https://github.com/user-attachments/assets/dde44c06-8dc3-43a0-a2b0-1593e7832c31)

### Help Menu
![help_menu](https://github.com/user-attachments/assets/a25d40d2-7e67-4fa0-814b-567f4d459dea)

### Modes
![modes](https://github.com/user-attachments/assets/7745f3c0-5107-4694-8f65-59365dd4fd64)

### Modes 2
![modes_2](https://github.com/user-attachments/assets/5170147a-2a61-4f22-b73a-b94bffdba56f)

### Scan With Interface And Auto Block
![scan_with_interface_and_auto_block](https://github.com/user-attachments/assets/0fc76d28-8a71-402f-9ce1-9bf34efd5547)

### Scan Without Interface
![scan_without_interface](https://github.com/user-attachments/assets/cd050c6b-9acc-44eb-adfb-76fc71154b73)

### Send Report Automatically
![send_report_automatically](https://github.com/user-attachments/assets/abca362b-6a5d-4e67-a2e1-b080d7f22135)

### Thresholds And Export File Json
![thresholds_and_export_file_json](https://github.com/user-attachments/assets/2645353f-e17f-4307-be0b-eb02eb483fa6)

**Please If Any Problem Happend Tell Me In The Server Channel =>** [https://discord.gg/Hunt3rs](https://discord.gg/Cw6YZgqGzS)

**YouTube =>** https://youtube.com/fr4nc0x1

**TryHackMe =>** https://tryhackme.com/p/DR4X

That's It For Now And I Hope This Tool Makes Your Day Awesome, Remember With Great Power Comes Great Responsibility!

![gray0_ctp_on_line](https://github.com/user-attachments/assets/666442e5-7ae5-485d-9dff-2667aa8efb7e)
