<img width="1024" height="1024" alt="generated-image" src="https://github.com/user-attachments/assets/5e6c59ec-b780-46ac-9bdd-2ee8eb4ae900" />

![Python](https://img.shields.io/badge/python-v3.7%2B-blue)

LayerStat Network Layer DDOS Detection Tool

LayerStat is an open-source Python tool designed for real-time detection of network (Layer 3/4) and application layer (Layer 7 HTTP) DDoS attacks.
It provides network traffic capture and analysis with threshold-based detection, console output of essential statistics (packets, SYN, UDP, HTTP requests), and dynamic alerts.

LayerStat suits educational or personal monitoring of common volumetric attacks such as SYN flood, UDP flood, ICMP flood, and clear-text HTTP flood.

Features
Automatic detection and selection of network interfaces for monitoring.

Sliding time window configurable for rate calculation per source IP.

Threshold-based detection with detailed textual alerts.

Layer 3/4 support: IP packets, TCP SYN flags, UDP and ICMP packets.

Layer 7 support: basic HTTP request analysis (GET, POST, etc.) on port 80 unencrypted traffic.

Smart periodic cleanup of memory data.

Simple console interface; easily extensible for integration in complex pipelines.

Usage

Launch the script and select your target network interface from the interactive menu.

Watch the console output for [LayerStat] entries showing current per-IP rates (packets/s or HTTP requests/s).

Alerts [🚨 ALERT] display when configured thresholds are exceeded.

Configuration
Thresholds, time windows, interface, and ports are configurable via global variables in the script.

Limitations
HTTP analysis works only on unencrypted traffic (port 80). HTTPS is not supported due to encryption.

Detection is simple threshold-based without machine learning or advanced behavioral analysis.

Intended for personal, educational, or research use; not a replacement for professional industrial DDoS protection.
