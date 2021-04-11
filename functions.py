import binascii
import struct
import socket
from ctypes import *


#Pack Headers==============================================================================================================================================================

class Eth_header:

    def __init__(self, source_mac, dst_mac):
        dst_mac     = binascii.unhexlify(dst_mac) #Convert str mac to bytes
        src_mac     = binascii.unhexlify(source_mac)
        eth_type    = binascii.unhexlify('0800')

        self.eth_packet = struct.pack("!6s6s2s", dst_mac, src_mac, eth_type) #dst_mac, src_mac and eth_type should be in bytes data type

def eth_packet_creater(src_mac, dst_mac):
    eth_packet = Eth_header(src_mac, dst_mac)
    return eth_packet.eth_packet

class IP_Header:

    def __init__(self, ip_src, ip_dst):
        
        ip_ver  =   4
        ip_hlen =   5
        ip_tos  =   0
        ip_tlen =   50
        ip_id   =   0
        ip_flag =   0
        ip_fofs =   0
        ip_ttl  =   128
        ip_prot =   50 #50 for ESP
        ip_cksum=   0
        ip_src  =   socket.inet_aton(str(ip_src))
        ip_dst  =   socket.inet_aton(str(ip_dst))

        ip_ver_hlen = (ip_ver << 4) + ip_hlen
        ip_flag_offset = (ip_flag << 13) + ip_fofs
        self.ip_packet   = struct.pack("!BBHHHBBH4s4s", ip_ver_hlen, ip_tos, ip_tlen, ip_id, ip_flag_offset, ip_ttl, ip_prot, ip_cksum, ip_src, ip_dst)

        

class ESP_Header:
    
    def get_esp_packet(self, ipsec_encrypted_payload):
        spi = socket.inet_aton('0.0.0.0') #4bytes
        seq = 1 #4bytes
        payload = ipsec_encrypted_payload #size varies
        esp_part1 = struct.pack("4sI", spi, seq)
        esp_payload_part2 = payload
        

        return esp_part1 + esp_payload_part2 



#Unpack Headers==============================================================================================================================================================

class Unpack_IP_Header(Structure):
    _fields_ = [
        ("version", c_ubyte, 4),
        ("ihl", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32)
        ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # map protocol constants to their names
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
        self.src_address = socket.inet_ntoa(struct.pack("@I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I", self.dst))
        self.ttl_val = self.ttl
        self.proto_number = self.protocol_num

        #human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)
































