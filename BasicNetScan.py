import asyncio
import ipaddress
import random
import time
import socket
import sys
from icmplib import async_multiping

# --- Configuration ---
TARGET_SUBNETS = ['192.168.1.0/24', '2001:db8::/120']
PORTS = range(1, 65536)
CONCURRENCY_LIMIT = 2000  # Tuned down slightly for Windows stability (avoid Error 10055)
TIMEOUT = 0.75            # Seconds to wait for a port response
PING_RETRIES = 2          # ICMP packets to send per host
SCAN_UDP = True           # Set to False to skip UDP (UDP adds 65,535 probes per alive host)

async def port_scan_worker(queue):
    """Worker process that consumes targets from the queue."""
    while True:
        target = await queue.get()
        if target is None:
            # Sentinel value received, exit worker
            queue.task_done()
            break
            
        ip, port, proto = target
        
        try:
            if proto == 'TCP':
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=TIMEOUT)
                
                # Connection succeeded
                writer.close()
                await writer.wait_closed()
                print(f"[+] {ip}:{port} [TCP] Open")
                
            elif proto == 'UDP':
                # UDP is connectionless. A successful connect() just means the OS 
                # initialized the socket. We send a packet and wait for ICMP Unreachable.
                family = socket.AF_INET6 if ':' in ip else socket.AF_INET
                sock = socket.socket(family, socket.SOCK_DGRAM)
                sock.setblocking(False)
                
                sock.sendto(b'', (ip, port))
                await asyncio.sleep(TIMEOUT)
                sock.close()
                
                # Note: Because UDP doesn't handshake, lack of an error usually means 
                # Open or Filtered by a firewall. We print it, but be prepared for noise.
                # print(f"[*] {ip}:{port} [UDP] Open|Filtered")
                
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            # Port is closed, filtered, or host timed out
            pass
        except Exception:
            # Catch arbitrary OS socket limits
            pass
            
        queue.task_done()

async def main():
    start_time = time.time()
    
    # ==========================================
    # PHASE 1: ICMP Host Discovery
    # ==========================================
    print("[-] Phase 1: Generating IP list for ICMP discovery...")
    all_ips = []
    for subnet_str in TARGET_SUBNETS:
        try:
            network = ipaddress.ip_network(subnet_str, strict=False)
            all_ips.extend([str(ip) for ip in network.hosts()])
        except ValueError as e:
            print(f"[!] Invalid subnet {subnet_str}: {e}")

    print(f"[-] Pinging {len(all_ips)} hosts...")
    
    # async_multiping handles both IPv4 and IPv6 natively
    hosts = await async_multiping(
        all_ips,
        count=PING_RETRIES,
        timeout=TIMEOUT,
        concurrent_tasks=1000, 
        privileged=True       # REQUIRED on Windows (Script must be run as Administrator)
    )

    alive_ips = [host.address for host in hosts if host.is_alive]
    
    if not alive_ips:
        print("[-] No alive hosts discovered. Exiting.")
        return

    print(f"[+] Phase 1 Complete: Found {len(alive_ips)} alive hosts in {time.time() - start_time:.2f} seconds.")

    # ==========================================
    # PHASE 2: Shuffled Port Scan on Alive Hosts
    # ==========================================
    print("\n[-] Phase 2: Generating and shuffling port scan targets...")
    scan_targets = []
    for ip in alive_ips:
        for port in PORTS:
            scan_targets.append((ip, port, 'TCP'))
            if SCAN_UDP:
                scan_targets.append((ip, port, 'UDP'))
            
    # Shuffle to distribute load across network equipment
    random.shuffle(scan_targets)
    total_probes = len(scan_targets)
    print(f"[-] Beginning {total_probes} port probes...")

    # Load targets into a queue
    queue = asyncio.Queue()
    for target in scan_targets:
        queue.put_nowait(target)

    # Add sentinel values to shut down workers when the queue is empty
    for _ in range(CONCURRENCY_LIMIT):
        queue.put_nowait(None)

    scan_start = time.time()

    # Spin up fixed number of workers to prevent memory exhaustion
    workers = [
        asyncio.create_task(port_scan_worker(queue))
        for _ in range(CONCURRENCY_LIMIT)
    ]

    # Wait for the queue to be fully processed
    await queue.join()

    # Wait for workers to gracefully exit
    await asyncio.gather(*workers)

    total_time = time.time() - start_time
    print(f"\n[+] Scan completely finished in {total_time:.2f} seconds.")
    print(f"[+] Average port scan speed: {total_probes / (time.time() - scan_start):.2f} probes/sec.")

if __name__ == "__main__":
    # Ensure Windows uses the IOCP event loop (highly optimized for Windows networking)
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user.")
