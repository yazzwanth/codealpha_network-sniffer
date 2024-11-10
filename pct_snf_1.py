from scapy.all import sniff

# Function to handle each captured packet
def packet_callback(packet):
    # Print a summary of the packet
    print(packet.summary())

# Start sniffing on the default interface (e.g., "eth0" or "Wi-Fi")
# Count=0 means it will run until manually stopped
sniff(prn=packet_callback, count=100)

