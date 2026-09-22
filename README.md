# High-Speed Asynchronous Network Scanner

A high-performance, asynchronous Python network scanner built with a `tkinter` Graphical User Interface (GUI). It is designed to scan thousands of IPs and ports concurrently without exhausting system memory or causing state-table outages on target network equipment.

It achieves this by combining an initial high-speed ICMP host discovery phase with a randomized, queue-based `asyncio` port scanner running on the Windows I/O Completion Ports (IOCP) event loop.

## Features

* **Two-Phase Scanning:** Uses ICMP pinging to identify alive hosts before attempting TCP/UDP connections, saving millions of unnecessary network timeouts.
* **Target Randomization:** Shuffles IP and port combinations to distribute load across target subnets, preventing firewall and NAT state-table exhaustion.
* **Windows Optimized:** Natively utilizes the Windows Proactor Event Loop (IOCP) for maximum concurrency.
* **Graphical Interface:** Real-time progress bar, status updates, and a live data grid.
* **CSV Export:** Save scan results directly to a file.
* **Flexible Inputs:** Support for CIDR subnets, mixed port lists (e.g., `80, 443, 1000-2000`), and both TCP and UDP protocols.

## Dependencies & Prerequisites

This application requires **Python 3.8 or higher** (for native Windows `ProactorEventLoop` support).

The only required third-party Python package is `icmplib`, which handles high-concurrency ICMP pinging without spawning expensive OS subprocesses.

### Python Packages

* `icmplib`

*(Note: `tkinter`, `asyncio`, `ipaddress`, `socket`, `threading`, and `csv` are all part of the Python Standard Library and do not require separate installation).*

## Installation

1. Clone or download the repository containing `gui_scanner.py`.
2. Open your terminal or command prompt.
3. Install the required dependency using `pip`:

```bash
pip install icmplib

```

*(Linux users only: If your Python installation does not include `tkinter` by default, you may also need to install it via your package manager, e.g., `sudo apt install python3-tk`).*

## Important: Running the Scanner

Because this script uses raw sockets to send ICMP Echo Requests (pings) during Phase 1, **it requires elevated privileges**.

### On Windows:

You **must** run the script from a command prompt or PowerShell window that was opened using **Run as Administrator**.

```cmd
python gui_scanner.py

```

*If you do not run as Administrator, the scan will immediately fail during Phase 1 with a permissions error.*

### On Linux:

Run the script using `sudo`:

```bash
sudo python3 gui_scanner.py

```

## OS Tuning for Extreme Concurrency (Windows)

If you are scanning extremely large port ranges (e.g., 1-65535 across multiple IPs), Windows will eventually run out of ephemeral ports or throw a **`WSAENOBUFS (10055)`** error due to `TIME_WAIT` exhaustion.

To permanently fix this and allow maximum scanning speeds, open an **Administrator PowerShell** and run these commands, then **restart your computer**:

1. **Increase the ephemeral port range:**

```powershell
netsh int ipv4 set dynamicport tcp start=1025 num=64511
netsh int ipv6 set dynamicport tcp start=1025 num=64511

```

2. **Reduce TcpTimedWaitDelay to 30 seconds (down from 240):**

```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'TcpTimedWaitDelay' -Value 30 -Type DWord

```

## Usage Instructions

1. Launch the application (as Administrator).
2. **Target Subnets/IPs:** Enter comma-separated IPs or CIDR notations (e.g., `192.168.1.0/24, 10.0.0.5`).
3. **Ports:** Enter comma-separated ports or ranges (e.g., `22, 80, 443, 8000-8080`), or check **All Ports (1-65535)**.
4. **Protocols:** Select TCP, UDP, or both. *(Note: UDP scanning is connectionless and heavily reliant on ICMP timeouts; it can be noisy and slower than TCP).*
5. Click **Start Scan**.
6. When the scan finishes, click **Export to CSV** to save the discovered open ports.
