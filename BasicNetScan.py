import asyncio
import ipaddress
import random
import time
import socket
import sys
import threading
import queue
import csv
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from icmplib import async_multiping

# --- Background Scanner Logic ---

async def port_scan_worker(task_queue, msg_queue, state, timeout):
    """Worker process that consumes targets from the queue."""
    while True:
        target = await task_queue.get()
        if target is None:
            task_queue.task_done()
            break
            
        ip, port, proto = target
        
        try:
            if proto == 'TCP':
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=timeout)
                writer.close()
                await writer.wait_closed()
                
                # Report open port to UI
                msg_queue.put({"type": "result", "ip": ip, "port": port, "proto": "TCP", "status": "Open"})
                
            elif proto == 'UDP':
                family = socket.AF_INET6 if ':' in ip else socket.AF_INET
                sock = socket.socket(family, socket.SOCK_DGRAM)
                sock.setblocking(False)
                sock.sendto(b'', (ip, port))
                await asyncio.sleep(timeout)
                sock.close()
                # Uncomment next line if you want to log UDP as well (can be noisy)
                # msg_queue.put({"type": "result", "ip": ip, "port": port, "proto": "UDP", "status": "Open|Filtered"})
                
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            pass
        except Exception:
            pass
            
        # Update progress
        state['completed'] += 1
        if state['completed'] % 100 == 0:
            msg_queue.put({"type": "progress", "val": state['completed']})
            
        task_queue.task_done()

async def run_scan(subnets, ports, scan_tcp, scan_udp, msg_queue):
    timeout = 0.75
    ping_retries = 2
    concurrency_limit = 2000

    try:
        # --- PHASE 1: ICMP Discovery ---
        msg_queue.put({"type": "status", "msg": "Phase 1: Generating IP list..."})
        all_ips = []
        for subnet_str in subnets:
            network = ipaddress.ip_network(subnet_str.strip(), strict=False)
            all_ips.extend([str(ip) for ip in network.hosts()])

        msg_queue.put({"type": "status", "msg": f"Phase 1: Pinging {len(all_ips)} hosts..."})
        
        hosts = await async_multiping(
            all_ips, count=ping_retries, timeout=timeout, 
            concurrent_tasks=1000, privileged=True 
        )

        alive_ips = [host.address for host in hosts if host.is_alive]
        
        if not alive_ips:
            msg_queue.put({"type": "status", "msg": "Scan Complete: No alive hosts found."})
            msg_queue.put({"type": "done"})
            return

        # --- PHASE 2: Port Scanning ---
        msg_queue.put({"type": "status", "msg": f"Phase 2: Generating scan targets for {len(alive_ips)} hosts..."})
        scan_targets = []
        for ip in alive_ips:
            for port in ports:
                if scan_tcp: scan_targets.append((ip, port, 'TCP'))
                if scan_udp: scan_targets.append((ip, port, 'UDP'))
                
        random.shuffle(scan_targets)
        total_probes = len(scan_targets)
        
        msg_queue.put({"type": "status", "msg": f"Phase 2: Scanning {total_probes} ports..."})
        msg_queue.put({"type": "progress_init", "total": total_probes})

        task_queue = asyncio.Queue()
        for target in scan_targets:
            task_queue.put_nowait(target)
        for _ in range(concurrency_limit):
            task_queue.put_nowait(None)

        state = {'completed': 0}
        workers = [
            asyncio.create_task(port_scan_worker(task_queue, msg_queue, state, timeout))
            for _ in range(concurrency_limit)
        ]

        await task_queue.join()
        await asyncio.gather(*workers)
        
        msg_queue.put({"type": "progress", "val": total_probes})
        msg_queue.put({"type": "status", "msg": f"Scan Complete! Scanned {total_probes} ports."})
        msg_queue.put({"type": "done"})

    except Exception as e:
        msg_queue.put({"type": "status", "msg": f"Error: {str(e)} (Did you run as Admin?)"})
        msg_queue.put({"type": "done"})

def scanner_thread(subnets, ports, scan_tcp, scan_udp, msg_queue):
    """Entry point for the background scanning thread."""
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    asyncio.run(run_scan(subnets, ports, scan_tcp, scan_udp, msg_queue))


# --- GUI Application ---

class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("High-Speed Network Scanner")
        self.geometry("650x600")
        
        self.msg_queue = queue.Queue()
        self.is_scanning = False
        
        self.create_widgets()
        self.poll_queue()

    def create_widgets(self):
        pad = {'padx': 10, 'pady': 5}
        
        # --- Config Frame ---
        config_frame = ttk.LabelFrame(self, text="Scan Configuration")
        config_frame.pack(fill="x", padx=10, pady=10)
        
        # Subnets
        ttk.Label(config_frame, text="Target Subnets/IPs (comma-separated):").grid(row=0, column=0, sticky="w", **pad)
        self.entry_subnets = ttk.Entry(config_frame, width=40)
        self.entry_subnets.insert(0, "192.168.1.0/24")
        self.entry_subnets.grid(row=0, column=1, columnspan=2, sticky="ew", **pad)
        
        # Ports
        ttk.Label(config_frame, text="Ports (e.g., 80, 443, 1000-2000):").grid(row=1, column=0, sticky="w", **pad)
        self.entry_ports = ttk.Entry(config_frame, width=40)
        self.entry_ports.insert(0, "80, 443, 3389")
        self.entry_ports.grid(row=1, column=1, sticky="ew", **pad)
        
        self.var_all_ports = tk.BooleanVar(value=False)
        chk_all_ports = ttk.Checkbutton(config_frame, text="All Ports (1-65535)", variable=self.var_all_ports, command=self.toggle_ports)
        chk_all_ports.grid(row=1, column=2, sticky="w", **pad)

        # Protocols
        ttk.Label(config_frame, text="Protocols:").grid(row=2, column=0, sticky="w", **pad)
        
        proto_frame = ttk.Frame(config_frame)
        proto_frame.grid(row=2, column=1, columnspan=2, sticky="w", **pad)
        
        self.var_tcp = tk.BooleanVar(value=True)
        self.var_udp = tk.BooleanVar(value=False)
        ttk.Checkbutton(proto_frame, text="TCP", variable=self.var_tcp).pack(side="left", padx=(0, 10))
        ttk.Checkbutton(proto_frame, text="UDP", variable=self.var_udp).pack(side="left")

        # Buttons
        btn_frame = ttk.Frame(config_frame)
        btn_frame.grid(row=3, column=0, columnspan=3, pady=10)
        
        self.btn_start = ttk.Button(btn_frame, text="Start Scan", command=self.start_scan)
        self.btn_start.pack(side="left", padx=5)
        
        self.btn_export = ttk.Button(btn_frame, text="Export to CSV", command=self.export_csv, state="disabled")
        self.btn_export.pack(side="left", padx=5)

        # --- Status & Progress ---
        status_frame = ttk.Frame(self)
        status_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.lbl_status = ttk.Label(status_frame, text="Idle", font=("Arial", 10, "italic"))
        self.lbl_status.pack(anchor="w")
        
        self.progress = ttk.Progressbar(status_frame, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", pady=5)

        # --- Results Table ---
        results_frame = ttk.Frame(self)
        results_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        cols = ("IP Address", "Port", "Protocol", "State")
        self.tree = ttk.Treeview(results_frame, columns=cols, show="headings")
        
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100, anchor="center")
            
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def toggle_ports(self):
        if self.var_all_ports.get():
            self.entry_ports.config(state="disabled")
        else:
            self.entry_ports.config(state="normal")

    def parse_ports(self):
        if self.var_all_ports.get():
            return list(range(1, 65536))
            
        port_str = self.entry_ports.get()
        ports = set()
        for part in port_str.split(','):
            part = part.strip()
            if not part: continue
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        return list(ports)

    def start_scan(self):
        subnets = [s.strip() for s in self.entry_subnets.get().split(',') if s.strip()]
        
        try:
            ports = self.parse_ports()
        except ValueError:
            messagebox.showerror("Error", "Invalid port format. Use comma separated values and hyphens (e.g., 80, 443, 1-1024)")
            return
            
        scan_tcp = self.var_tcp.get()
        scan_udp = self.var_udp.get()
        
        if not subnets or not ports:
            messagebox.showerror("Error", "Please provide targets and ports.")
            return
        if not scan_tcp and not scan_udp:
            messagebox.showerror("Error", "Select at least one protocol (TCP or UDP).")
            return

        # Prepare UI for scanning
        self.tree.delete(*self.tree.get_children())
        self.btn_start.config(state="disabled")
        self.btn_export.config(state="disabled")
        self.progress['value'] = 0
        self.is_scanning = True
        
        # Launch scanning thread
        threading.Thread(
            target=scanner_thread, 
            args=(subnets, ports, scan_tcp, scan_udp, self.msg_queue),
            daemon=True
        ).start()

    def poll_queue(self):
        """Periodically checks the queue for messages from the background thread."""
        while not self.msg_queue.empty():
            msg = self.msg_queue.get_nowait()
            
            if msg["type"] == "status":
                self.lbl_status.config(text=msg["msg"])
            
            elif msg["type"] == "progress_init":
                self.progress['maximum'] = msg["total"]
                self.progress['value'] = 0
                
            elif msg["type"] == "progress":
                self.progress['value'] = msg["val"]
                
            elif msg["type"] == "result":
                self.tree.insert("", "end", values=(msg["ip"], msg["port"], msg["proto"], msg["status"]))
                # Auto-scroll to bottom
                self.tree.yview_moveto(1)
                
            elif msg["type"] == "done":
                self.is_scanning = False
                self.btn_start.config(state="normal")
                self.btn_export.config(state="normal")
                
        # Schedule the next check in 100 milliseconds
        self.after(100, self.poll_queue)

    def export_csv(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export Results"
        )
        
        if not file_path:
            return
            
        with open(file_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Write Headers
            writer.writerow(["IP Address", "Port", "Protocol", "State"])
            # Write Data
            for row_id in self.tree.get_children():
                row_data = self.tree.item(row_id)["values"]
                writer.writerow(row_data)
                
        messagebox.showinfo("Success", f"Results exported to:\n{file_path}")


if __name__ == "__main__":
    app = ScannerApp()
    app.mainloop()
