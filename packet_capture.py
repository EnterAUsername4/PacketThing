import socket
import time, datetime
import os
import logging
# import threading
from scapy.all import *
from colorama import Style, Fore, Back

# TODO Fix the TCP and UDP so they don't require "type: ignore" comment

#!SECTION Logging Portion
log_filename = 'packet_capture.log'
logging.basicConfig(filename=log_filename, level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

#!SECTION End Of Logging Portion

colorama.init()

def Clear() -> None:
    os.system('cls')
Clear()

# Optional until end of optional
local_ip = get_if_addr(conf.iface)

hex_str = '2f77206c696562652a203c6f3a3a53656e64496e7075742c2025206e616d65'

search_string = b"\x00\x00\x00<\x00o\x00:\x00:\x00 \x00%\x00 \x00n\x00a\x00m\x00e\x00"
search_string2 = b"\x00\x00\x00<\x00o\x00:\x00:\x00%\x00n\x00"

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

def block_packet(packet):
    if TCP in packet and Raw in packet and search_string in bytes(packet[TCP].payload): # type: ignore
        print(f'{Style.DIM + Fore.RED}Blocking packet with search string: {packet.summary()}{Style.RESET_ALL}')

        ip_layer = IP(dst = packet[IP].src, src = packet[IP].dst) # type: ignore

        rst_packet = TCP(dport = packet[TCP].sport, sport = packet[TCP].dport, flags = 'R', seq = packet[TCP].ack, ack = packet[TCP].seq + len(packet[TCP].payload)) # type: ignore

        response_packet = ip_layer / rst_packet

        send(response_packet)
    if TCP in packet and Raw in packet and search_string2 in bytes(packet[TCP].payload): # type: ignore
        print(f'{Style.DIM + Fore.RED}Blocking packet with search string: {packet.summary()}{Style.RESET_ALL}')

        ip_layer = IP(dst = packet[IP].src, src = packet[IP].dst) # type: ignore

        rst_packet = TCP(dport = packet[TCP].sport, sport = packet[TCP].dport, flags = 'R', seq = packet[TCP].ack, ack = packet[TCP].seq + len(packet[TCP].payload)) # type: ignore

        response_packet = ip_layer / rst_packet

        send(response_packet)

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
            
            if search_string in raw_payload:
                block_packet(packet)
                return

            if search_string2 in raw_payload:
                block_packet(packet)
                return

            if is_sent(packet):
            #    send(tcp_packet)
                print(f'{Style.BRIGHT + Fore.GREEN}[{current_time()}] {Style.BRIGHT + Fore.BLUE}Sent TCP Payload (details):{Style.DIM + Fore.RED}{packet.summary()} | Length:{len(packet)}{Style.RESET_ALL}')
                print(f'{Style.BRIGHT + Fore.GREEN}[{current_time()}] {Style.BRIGHT + Fore.BLUE}Sent TCP Payload (bytes):{Style.RESET_ALL}{raw_payload}')
                print(f'{Style.BRIGHT + Fore.GREEN}[{current_time()}] {Style.BRIGHT + Fore.BLUE}Sent TCP Payload (decoded):{Style.RESET_ALL}\n{payload_data}')
                logging.info('Received TCP Payload (details): %s | Length: %d', packet.summary(), len(packet))
                logging.debug('Sent TCP Payload (bytes): %s', raw_payload)
                logging.debug('Sent TCP Payload (decoded): %s', payload_data)
            else:
                print(f'{Style.BRIGHT + Fore.GREEN}[{current_time()}] {Style.BRIGHT + Fore.BLUE}Received TCP Payload (details):{Style.DIM + Fore.RED}{packet.summary()} | Length:{len(packet)}{Style.RESET_ALL}')
                print(f'{Style.BRIGHT + Fore.GREEN}[{current_time()}] {Style.BRIGHT + Fore.BLUE}Received TCP Payload (byes):{Style.RESET_ALL}{raw_payload}')
                print(f'{Style.BRIGHT + Fore.GREEN}[{current_time()}] {Style.BRIGHT + Fore.BLUE}Received TCP Payload (decoded):{Style.RESET_ALL}\n{payload_data}')
                logging.info('Received TCP Payload (details): %s | Length: %d', packet.summary(), len(packet))
                logging.debug('Received TCP Payload (bytes): %s', raw_payload)
                logging.debug('Received TCP Payload (decoded): %s', payload_data)

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
