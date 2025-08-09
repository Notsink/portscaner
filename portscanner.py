#!/usr/bin/env python3
import asyncio
import socket
import ipaddress
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import concurrent.futures

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 8080]

BG_COLOR = "#1e1e1e"
FG_COLOR = "#c0c0c0"
ENTRY_BG = "#2b2b2b"
BUTTON_BG = "#3c3c3c"
ACCENT = "#00adb5"


def ping(ip: str, timeout: int = 1) -> bool:
    """Return True if ip answers to one ICMP echo-request."""
    param = "-n" if subprocess.os.name == "nt" else "-c"
    cmd = ["ping", param, "1", "-W" if subprocess.os.name != "nt" else "-w", str(timeout), str(ip)]
    completed = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return completed.returncode == 0


class PortScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Dark Port Scanner")
        self.geometry("700x500")
        self.configure(bg=BG_COLOR)
        self.resizable(False, False)

        style = ttk.Style(self)
        style.theme_use("clam")

        # global style settings
        style.configure("TLabel", background=BG_COLOR, foreground=FG_COLOR)
        style.configure("TEntry", fieldbackground=ENTRY_BG, foreground=FG_COLOR,
                        insertcolor=FG_COLOR, borderwidth=1)
        style.configure("TButton", background=BUTTON_BG, foreground=FG_COLOR,
                        borderwidth=1, focuscolor="none")
        style.map("TButton", background=[("active", ACCENT)])

        self.create_widgets()

    def create_widgets(self):
        # port-scan panel
        frm = ttk.Frame(self)
        frm.pack(padx=10, pady=10, fill="x")

        ttk.Label(frm, text="Target:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.target_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.target_var, width=25).grid(row=0, column=1, padx=(0, 10))

        ttk.Label(frm, text="Ports:").grid(row=0, column=2, sticky="w", padx=(0, 5))
        self.ports_var = tk.StringVar(value="top-20")
        ttk.Entry(frm, textvariable=self.ports_var, width=20).grid(row=0, column=3, padx=(0, 10))

        self.btn_scan = ttk.Button(frm, text="Scan", command=self.start_scan)
        self.btn_scan.grid(row=0, column=4)

        # ping-scan panel
        frm2 = ttk.Frame(self)
        frm2.pack(padx=10, pady=(0, 10), fill="x")

        ttk.Label(frm2, text="Subnet:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.subnet_var = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(frm2, textvariable=self.subnet_var, width=25).grid(row=0, column=1, padx=(0, 10))

        self.btn_ping = ttk.Button(frm2, text="Ping-scan", command=self.start_ping_scan)
        self.btn_ping.grid(row=0, column=2)

        # log window
        self.log = scrolledtext.ScrolledText(
            self, state="disabled", bg=ENTRY_BG, fg=FG_COLOR,
            insertbackground=FG_COLOR, wrap="word", height=20, font=("Consolas", 10)
        )
        self.log.pack(padx=10, pady=(0, 10), fill="both", expand=True)

    def log_msg(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.configure(state="disabled")
        self.log.yview("end")

    def parse_ports(self):
        val = self.ports_var.get().strip().lower()
        if val.startswith("top-"):
            n = int(val.split("-")[1])
            return COMMON_PORTS[:n]
        if "-" in val:
            a, b = map(int, val.split("-"))
            return list(range(a, b + 1))
        return [int(val)]

    async def grab_banner(self, ip, port):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(str(ip), port), timeout=3
            )
            writer.write(b"\r\n")
            await writer.drain()
            banner = await asyncio.wait_for(reader.read(512), timeout=3)
            writer.close()
            await writer.wait_closed()
            return banner.decode(errors="ignore").strip()
        except Exception:
            return None

    async def scan_port(self, ip, port, semaphore):
        async with semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(str(ip), port), timeout=3
                )
                writer.close()
                await writer.wait_closed()
                banner = await self.grab_banner(ip, port)
                return port, True, banner
            except Exception:
                return port, False, None

    async def run_scan(self, ip, ports):
        semaphore = asyncio.Semaphore(200)
        tasks = [self.scan_port(ip, p, semaphore) for p in ports]
        results = await asyncio.gather(*tasks)
        open_ports = [(p, b) for p, status, b in results if status]
        return open_ports

    def start_scan(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Specify a target!")
            return
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            try:
                ip = ipaddress.ip_address(socket.gethostbyname(target))
            except socket.gaierror:
                messagebox.showerror("Error", "Invalid IP or domain")
                return

        try:
            ports = self.parse_ports()
        except ValueError:
            messagebox.showerror("Error", "Invalid port format")
            return

        self.btn_scan.config(state="disabled")
        self.log_msg(f"🔍 Scanning {ip} ({len(ports)} ports)…")

        def runner():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                open_ports = loop.run_until_complete(self.run_scan(ip, ports))
                self.after(0, self.show_results, open_ports)
            except Exception as e:
                self.after(0, self.log_msg, f"⚠️ Error: {e}")
            finally:
                self.after(0, lambda: self.btn_scan.config(state="normal"))
                loop.close()

        threading.Thread(target=runner, daemon=True).start()

    def show_results(self, open_ports):
        if open_ports:
            self.log_msg("🔓 Open ports:")
            for port, banner in open_ports:
                self.log_msg(f"  Port {port}: OPEN")
                if banner:
                    self.log_msg(f"    Banner: {banner}")
        else:
            self.log_msg("✅ No open ports found.")

    # ---------- Ping-scan ----------
    def start_ping_scan(self):
        subnet = self.subnet_var.get().strip()
        try:
            net = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            messagebox.showerror("Error", "Invalid subnet!")
            return

        self.btn_ping.config(state="disabled")
        self.log_msg(f"🌐 Scanning subnet {net}…")

        def runner():
            alive = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=200) as exe:
                future_to_ip = {exe.submit(ping, str(ip)): ip for ip in net.hosts()}
                for fut in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[fut]
                    if fut.result():
                        alive.append(ip)
            self.after(0, self.show_ping_results, alive)

        threading.Thread(target=runner, daemon=True).start()

    def show_ping_results(self, alive):
        if alive:
            self.log_msg(f"✅ Alive hosts ({len(alive)}):")
            for ip in alive:
                self.log_msg(f"  {ip}")
        else:
            self.log_msg("❌ No alive hosts found.")
        self.btn_ping.config(state="normal")


if __name__ == "__main__":
    PortScannerGUI().mainloop()