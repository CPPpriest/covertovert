from scapy.all import send, IP, ICMP, sniff


# Function to show captured icmp pckt
def show_pckt(pckt):
    # Check packet has ICMP layer && TTL == 1
    if pckt.haslayer(ICMP) and pckt[IP].ttl == 1:
        # Display the packet details
        pckt.show()

# Start sniffing for ICMP packets -> if icmp , then show pckt
sniff(filter="icmp", prn=show_pckt)