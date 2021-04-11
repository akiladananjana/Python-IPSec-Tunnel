import socket
import functions
import time
import os
import sys
import struct
from fcntl import ioctl
import AES_encryption_class
from threading import Thread
import netifaces #Needs to install manually -> pip install netifaces

interface_name = input("Enter Interface Name(Tunnel Bind with this Interface): ")
dst_host_ip = input("Enter Destination Host IP(Tunnel will connect to this IP): ")
tuntap_int_name = input("Enter Virtual Interface(TUN/TAP) Name: ")
AES_key = input("Enter AES Encryption Key: ")

#For debugging
#interface_name = 'ens33'
#dst_host_ip = '192.168.1.20'
#tuntap_int_name = 'asa0'
#AES_key = 'nibm2020'

#Get Interface IP using netifaces module
interface_ip = netifaces.ifaddresses(interface_name)[2][0]['addr'] 

#Create a RAW Socket for send the traffic
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)

#Raw socket for recv the traffic
recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
recv_sock.bind((interface_name, 0))

IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUNMODE = IFF_TUN
TUNSETIFF = 0x400454ca


#Get a file descriptor of the tun/tap interface
def tun_open(devname):
	fd = os.open("/dev/net/tun", os.O_RDWR)
	ifr = struct.pack('16sH', devname, IFF_TUN | IFF_NO_PI)
	ifs = ioctl(fd, TUNSETIFF, ifr)
	return fd

fd = tun_open(tuntap_int_name.encode())


#Read via file descriptor
def read_from_fd(fd):
    packet = os.read(fd, 1024)    
    return packet


#Write to file descriptor
def write_to_fd(fd, packet_from_socket):
    os.write(fd, packet_from_socket)


#Create a class for AES Encryption & Decryption-> AES Key = 'nibm2020' for debugging
crypto_class = AES_encryption_class.AES_Cipher(AES_key)


#This function use to send packets to dst machine
def send_socket(fd):

    ip_class = functions.IP_Header(interface_ip, dst_host_ip) #Build IP Header
    ip_packet = ip_class.ip_packet

    packet_from_fd = read_from_fd(fd) #Read packets from fd

    while(packet_from_fd):
        #print(packet_from_fd)
        encrypted_packet = crypto_class.encrypt(packet_from_fd) #Encrypt the packet read via fd
        esp_class = functions.ESP_Header() 
        esp_payload = esp_class.get_esp_packet(encrypted_packet) #Build ESP header + Encrypted Payload
 
        packet = (ip_packet + esp_payload) #Build final IP Packet
        #sock.send(packet) #Send the packet
        sock.sendto(packet, (dst_host_ip , 0 ))
        #print("SENT!")
        packet_from_fd = read_from_fd(fd)



#This function use to recv packets from dst machine
def recv_socket(fd):
    packet_from_socket = recv_sock.recv(2048)

    while (packet_from_socket):
        ip_packet = functions.Unpack_IP_Header(packet_from_socket[14:35]) #Get IP header proto number
        if(ip_packet.proto_number==50): # Check if packet has a ESP Header
            decrypted_packet = crypto_class.decrypt(packet_from_socket[42:]) # If packet has a ESP header then Decrypt only the payload section of the ESP header
            write_to_fd(fd, decrypted_packet) #write decrypted_packet to fd
        
        packet_from_socket = recv_sock.recv(2048)


t1 = Thread(target=send_socket, args=(fd, ))
t2 = Thread(target=recv_socket, args=(fd, ))

#Start all threads as daemon mode, then we can close them all when the main program(main thread) ends! 
#To keep alive main program added a infinite while loop at end of the program. Then Its possible to catch the keyboard interrupt using that loop. 

t1.setDaemon(True)
t1.start()
t2.setDaemon(True)
t2.start()


#To keep alive the main thread and catch the KeyboardInterrupt exception using the following infinite while loop
def generate_slash_ani():
    print(f"\nIPsec Tunnel is Running ", end='')
    while (True):
        for x in "|/—\\":
            sys.stdout.write(x)
            sys.stdout.flush()
            time.sleep(0.2)
            sys.stdout.write('\b')

try:
    generate_slash_ani()
        
except KeyboardInterrupt as key_intrrupt:
    print('\n')
    sys.exit(1)
