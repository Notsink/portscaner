# Port Scanner  
**A lightweight, dark-themed TCP port and ICMP sweep tool written in pure Python 3.**

![demo](https://user-images.githubusercontent.com/YOU/REPO/demo.gif)

---

| Task                | Input Example |
| ------------------- | ------------- |
| Top 20 common ports | `top-20`      |
| Custom range        | `1-1024`      |
| Single port         | `443`         |
| Subnet sweep        | `10.0.0.0/24` |

---

## Features
- **TCP Port Scanning**  
  Asynchronous, high-speed scanning with configurable port lists.
- **ICMP Ping Sweep**  
  Multi-threaded ping discovery for entire subnets.
- **Dark GUI**  
  Eye-friendly dark theme built with `tkinter` (no extra deps on Windows / macOS / Linux).
- **Zero Dependencies**  
  Uses only the Python 3 standard library.

---

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/dark-port-scanner.git
cd dark-port-scanner
python3 dark_port_scanner.py
