from scapy.all import send, IP, ICMP

# Destination hostname is "receiver" which is resolved by the DNS
dest = "receiver"

# Define IP layer with destination and TTL values
ip_layer = IP(dst=dest, ttl=1)

# Define ICMP layer
icmp_layer = ICMP()

# Send the created pckt with IP and ICMP layers stacked
send(ip_layer / icmp_layer)