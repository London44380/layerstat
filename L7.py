#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import sniff, IP, TCP, Raw, get_if_list
from collections import defaultdict, deque
import threading
import time

# CONFIGURATION

WINDOW_SECONDS = 10
CLEANUP_INTERVAL = 30
THRESH_HTTP_REQ_PER_SEC = 50

HTTP_METHODS = [b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH"]

http_times = defaultdict(lambda: deque())

lock = threading.Lock()

def print_layer_stat(ip, rate):
    print(f"[LayerStat] IP: {ip} | HTTP req/s: {rate:.1f}")

def cleanup_old_entries(deq, now, window):
    while deq and (now - deq[0]) > window:
        deq.popleft()

def compute_http_rate(ip, now):
    cleanup_old_entries(http_times[ip], now, WINDOW_SECONDS)
    return len(http_times[ip]) / WINDOW_SECONDS

def log_alert(ip, rate):
    now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print("="*60)
    print(f"[🚨 ALERT] {now_str}")
    print(f"Suspicious IP: {ip}")
    print(f"HTTP Requests / sec: {rate:.1f} (> {THRESH_HTTP_REQ_PER_SEC})")
    print("="*60)

def process_packet(pkt):
    if not (IP in pkt and TCP in pkt and Raw in pkt):
        return
    if pkt[TCP].dport != 80 and pkt[TCP].sport != 80:
        return
    payload = pkt[Raw].load
    if any(payload.startswith(method + b" ") for method in HTTP_METHODS):
        src_ip = pkt[IP].src
        now = time.time()
        with lock:
            http_times[src_ip].append(now)
            rate = compute_http_rate(src_ip, now)
            print_layer_stat(src_ip, rate)
            if rate > THRESH_HTTP_REQ_PER_SEC:
                log_alert(src_ip, rate)

def cleanup_loop():
    while True:
        time.sleep(CLEANUP_INTERVAL)
        now = time.time()
        with lock:
            to_delete = []
            for ip in http_times.keys():
                cleanup_old_entries(http_times[ip], now, WINDOW_SECONDS)
                if not http_times[ip]:
                    to_delete.append(ip)
            for ip in to_delete:
                del http_times[ip]

def select_interface():
    interfaces = get_if_list()
    print("\n=== Interface selection ===\n")
    for i, iface in enumerate(interfaces, 1):
        print(f"{i}. {iface}")
    print("0. Exit")
    while True:
        choice = input("Select an interface: ")
        if choice == '0':
            exit(0)
        try:
            idx = int(choice)-1
            if 0 <= idx < len(interfaces):
                return interfaces[idx]
        except ValueError:
            pass
        print("Invalid choice.")

def main():
    iface = select_interface()
    print(f"\nSelected interface: {iface}\nStarting capture...")
    t = threading.Thread(target=cleanup_loop, daemon=True)
    t.start()
    try:
        sniff(iface=iface, prn=process_packet, store=False, filter="tcp port 80")
    except KeyboardInterrupt:
        print("\nUser requested shutdown.")

if __name__ == "__main__":
    main()
