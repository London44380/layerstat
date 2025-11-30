#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
from collections import defaultdict, deque
import time
import threading

# CONFIGURATION

BPF_FILTER = "ip"
WINDOW_SECONDS = 10
CLEANUP_INTERVAL = 30

THRESH_PACKETS_PER_SEC = 500
THRESH_SYN_PER_SEC = 200
THRESH_UDP_PER_SEC = 500
THRESH_ICMP_PER_SEC = 200

# DATA STRUCTURES

packet_times = defaultdict(lambda: deque())
syn_times = defaultdict(lambda: deque())
udp_times = defaultdict(lambda: deque())
icmp_times = defaultdict(lambda: deque())

lock = threading.Lock()

# FUNCTIONS

def print_layer_stat(ip, pkt_rate, syn_rate, udp_rate, icmp_rate):
    print(f"[LayerStat] IP: {ip} | packets/s: {pkt_rate:.1f} | SYN/s: {syn_rate:.1f} | UDP/s: {udp_rate:.1f} | ICMP/s: {icmp_rate:.1f}")

def _cleanup_old_entries(deq, now, window):
    while deq and (now - deq[0]) > window:
        deq.popleft()

def compute_rates(ip, now):
    _cleanup_old_entries(packet_times[ip], now, WINDOW_SECONDS)
    _cleanup_old_entries(syn_times[ip], now, WINDOW_SECONDS)
    _cleanup_old_entries(udp_times[ip], now, WINDOW_SECONDS)
    _cleanup_old_entries(icmp_times[ip], now, WINDOW_SECONDS)

    pkt_rate = len(packet_times[ip]) / float(WINDOW_SECONDS)
    syn_rate = len(syn_times[ip]) / float(WINDOW_SECONDS)
    udp_rate = len(udp_times[ip]) / float(WINDOW_SECONDS)
    icmp_rate = len(icmp_times[ip]) / float(WINDOW_SECONDS)

    return pkt_rate, syn_rate, udp_rate, icmp_rate

def check_thresholds(ip, pkt_rate, syn_rate, udp_rate, icmp_rate):
    alerts = []
    if pkt_rate > THRESH_PACKETS_PER_SEC:
        alerts.append(f"TRAFFIC_FLOOD: {pkt_rate:.1f} pkts/s (> {THRESH_PACKETS_PER_SEC})")
    if syn_rate > THRESH_SYN_PER_SEC:
        alerts.append(f"SYN_FLOOD: {syn_rate:.1f} SYN/s (> {THRESH_SYN_PER_SEC})")
    if udp_rate > THRESH_UDP_PER_SEC:
        alerts.append(f"UDP_FLOOD: {udp_rate:.1f} UDP/s (> {THRESH_UDP_PER_SEC})")
    if icmp_rate > THRESH_ICMP_PER_SEC:
        alerts.append(f"ICMP_FLOOD: {icmp_rate:.1f} ICMP/s (> {THRESH_ICMP_PER_SEC})")
    return alerts

def log_alert(ip, alerts, pkt_rate, syn_rate, udp_rate, icmp_rate):
    now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print("=" * 80)
    print(f"[🚨 ALERT] {now_str}")
    print(f"Suspicious IP: {ip}")
    print(f" - packets/s : {pkt_rate:.1f}")
    print(f" - SYN/s     : {syn_rate:.1f}")
    print(f" - UDP/s     : {udp_rate:.1f}")
    print(f" - ICMP/s    : {icmp_rate:.1f}")
    print("Attack types suspected:")
    for a in alerts:
        print(f"   * {a}")
    print("=" * 80)

def process_packet(pkt):
    if IP not in pkt:
        return
    src_ip = pkt[IP].src
    now = time.time()

    with lock:
        packet_times[src_ip].append(now)
        if TCP in pkt:
            flags = pkt[TCP].flags
            if flags & 0x02:
                syn_times[src_ip].append(now)
        if UDP in pkt:
            udp_times[src_ip].append(now)
        if ICMP in pkt:
            icmp_times[src_ip].append(now)

        pkt_rate, syn_rate, udp_rate, icmp_rate = compute_rates(src_ip, now)

        # Print LayerStat details
        print_layer_stat(src_ip, pkt_rate, syn_rate, udp_rate, icmp_rate)

        alerts = check_thresholds(src_ip, pkt_rate, syn_rate, udp_rate, icmp_rate)
        if alerts:
            log_alert(src_ip, alerts, pkt_rate, syn_rate, udp_rate, icmp_rate)

def cleanup_loop():
    while True:
        time.sleep(CLEANUP_INTERVAL)
        now = time.time()
        with lock:
            to_delete = []
            for ip in list(packet_times.keys()):
                _cleanup_old_entries(packet_times[ip], now, WINDOW_SECONDS)
                _cleanup_old_entries(syn_times[ip], now, WINDOW_SECONDS)
                _cleanup_old_entries(udp_times[ip], now, WINDOW_SECONDS)
                _cleanup_old_entries(icmp_times[ip], now, WINDOW_SECONDS)
                if not packet_times[ip] and not syn_times[ip] and not udp_times[ip] and not icmp_times[ip]:
                    to_delete.append(ip)
            for ip in to_delete:
                del packet_times[ip]
                if ip in syn_times: del syn_times[ip]
                if ip in udp_times: del udp_times[ip]
                if ip in icmp_times: del icmp_times[ip]

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
    sniff(iface=iface, filter=BPF_FILTER, prn=process_packet, store=False)

if __name__ == "__main__":
    main()
