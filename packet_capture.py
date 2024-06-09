import socket
import time, datetime
import os
# import threading
from scapy.all import *
from colorama import Style, Fore, Back

# TODO Fix the TCP and UDP so they don't require "type: ignore" comment

colorama.init()

def Clear() -> None:
    os.system('cls')
Clear()

# Optional until end of optional
local_ip = get_if_addr(conf.iface)

hex_str = '2f77206c696562652a203c6f3a3a53656e64496e7075742c2025206e616d65'

payload_bytes = bytes.fromhex(hex_str)

blocked_sequence_hex = "3c6f3a3a53656e64496e7075742c2025206e616d65"
blocked_sequence = bytes.fromhex(blocked_sequence_hex)

tcp_packet = IP(dst = '43.130.91.144') / TCP(dport = 62000 ) / payload_bytes  # type: ignore

# https://gateway-bs.valofe.com/

server_address = ('43.130.91.144', 62000)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    sock.connect(server_address)

    sock.sendall(payload_bytes)

    response = sock.recv(4096)
    print('Received', repr(response))

finally:
    sock.close()
# End of Optional
# The function is_sent is to determin if a packet was either sent or received so leave it
def is_sent(packet):

    return packet.haslayer(IP) and packet[IP].src == local_ip # type: ignore
# This one is kind of obvious is it not? It displays the local time of the computer in print
def current_time():

    return datetime.now().strftime('%H:%M')

def block_payload(raw_payload):
    if blocked_sequence in raw_payload:
        print('Payload blocked due to containing the forbidden sequence.')

        return True
    
    return False


# In general this is just a fucking packet handler for TCP, checking TCP port 62000
# what do you think it does? Change the port 62000 to the game of choices port
def tcp_packet_handler(packet):
    if packet.haslayer(TCP) and (packet[TCP].dport == 62000 or packet[TCP].sport == 62000): # type: ignore
        tcp_packet = packet[TCP] # type: ignore
        if tcp_packet.payload:
            try:
            #     Converts the payload_datas into a human readable language
                raw_payload = bytes(tcp_packet.payload)
                if block_payload(raw_payload):
                    
                    return
                
                payload_data = raw_payload.decode('utf-8', errors = 'ignore') # utf-8-sig
            except UnicodeDecodeError:
            #    Converts the payload_datas into hex if there is a unicode decode error
                payload_data = raw_payload.hex()
            
            if is_sent(packet):
            #    send(tcp_packet)
                print(f'{Style.BRIGHT + Fore.GREEN}[{current_time()}] {Style.BRIGHT + Fore.BLUE}Sent TCP Payload (details):{Style.DIM + Fore.RED}{packet.summary()} | Length:{len(packet)}{Style.RESET_ALL}')
                print(f'{Style.BRIGHT + Fore.GREEN}[{current_time()}] {Style.BRIGHT + Fore.BLUE}Sent TCP Payload (bytes):{Style.RESET_ALL}{raw_payload}')
                print(f'{Style.BRIGHT + Fore.GREEN}[{current_time()}] {Style.BRIGHT + Fore.BLUE}Sent TCP Payload (decoded):{Style.RESET_ALL}\n{payload_data}')
            else:
                print(f'{Style.BRIGHT + Fore.GREEN}[{current_time()}] {Style.BRIGHT + Fore.BLUE}Received TCP Payload (details):{Style.DIM + Fore.RED}{packet.summary()} | Length:{len(packet)}{Style.RESET_ALL}')
                print(f'{Style.BRIGHT + Fore.GREEN}[{current_time()}] {Style.BRIGHT + Fore.BLUE}Received TCP Payload (byes):{Style.RESET_ALL}{raw_payload}')
                print(f'{Style.BRIGHT + Fore.GREEN}[{current_time()}] {Style.BRIGHT + Fore.BLUE}Received TCP Payload (decoded):{Style.RESET_ALL}\n{payload_data}')

            if '<o::SendInput, % name' in payload_data:
                print(f'{Style.DIM + Fore.RED}<o::SendInput, % name was detected; Blocking the payload{Style.RESET_ALL}')

                return

# This does basically the same thing as the TCP packet handler but instead for UDP 
# from port 50000 to 50201 so nothing special for other games replace the UDP ports
# with the game ports ie [50000~50201]
def udp_packet_handler(packet):
    if packet.haslayer(UDP) and packet[UDP].dport in range(50000, 50201): # type: ignore
        if is_sent(packet):
            print(f'Sent UDP Packet: {packet.summary()}')
        else:
            print(f'Received UDP Packet: {packet.summary()}')

# This literally does the functions name; sniffs the actual packets do not
# comment these as of now as they are required for the script to actually run
sniff(filter = 'tcp port 62000 or udp portrange 50000-50200', prn = lambda x: tcp_packet_handler(x), store = 0) # type: ignore
