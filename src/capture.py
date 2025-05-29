import pyshark

# Set your network interface name here (e.g., 'Wi-Fi', 'Ethernet', etc.)
interface_name = 'Wi-Fi'  # Change this to your actual interface

# File to save the capture
output_pcap = '../data/capture_output.pcap'

# BPF capture filter for DNS (UDP port 53)
# capture_filter = 'udp port 53'
capture_filter = 'icmp'

cap = pyshark.LiveCapture(
    interface=interface_name,
    output_file=output_pcap,
    bpf_filter=capture_filter
)

# Create live capture object with output file
# cap = pyshark.LiveCapture(interface=interface_name, output_file=output_pcap)

# Capture 1000 packets
print(f"Capturing 100 packets on interface: {interface_name}...")
cap.sniff(packet_count=100)

print(f"Capture complete. Saved to: {output_pcap}")
