----
#!/usr/bin/python3
# For building the socket
import socket
# For system level commands
import sys
# For doing an array in the TCP checksum
import array
# For establishing the packet structure (Used later on), this will allow direct access to the methods and functions in the struct module
from struct import pack
# For encoding
import base64    # base64 module
import binascii    # binascii module
# Create a raw socket.
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error as msg:
    print(msg)
    sys.exit() 
# 0 or IPPROTO_TCP for STREAM and 0 or IPPROTO_UDP for DGRAM. (man ip7). For SOCK_RAW you may specify a valid IANA IP protocol defined in RFC 1700 assigned numbers.
# IPPROTO_IP creates a socket that sends/receives raw data for IPv4-based protocols (TCP, UDP, etc). It will handle the IP headers for you, but you are responsible for processing/creating additional protocol data inside the IP payload.
# IPPROTO_RAW creates a socket that sends/receives raw data for any kind of protocol. It will not handle any headers for you, you are responsible for processing/creating all payload data, including IP and additional headers. (link)

src_ip = "127.0.0.1"
dst_ip = "127.0.0.1"

##################
##Build Packet Header##
##################
# Lets add the IPv4 header information
# This is normally 0x45 or 69 for Version and Internet Header Length
ip_ver_ihl =
# This combines the DSCP and ECN feilds.  Type of service/QoS
ip_tos =
# The kernel will fill in the actually length of the packet
ip_len = 0
# This sets the IP Identification for the packet. 1-65535
ip_id =
# This sets the RES/DF/MF flags and fragmentation offset
ip_frag =
# This determines the TTL of the packet when leaving the machine. 1-255
ip_ttl =
# This sets the IP protocol to 16 (CHAOS) (reference IANA) Any other protocol it will expect additional headers to be created.
ip_proto =
# The kernel will fill in the checksum for the packet
ip_check = 0
# inet_aton(string) will convert an IP address to a 32 bit binary number
ip_srcadd = socket.inet_aton(src_ip)
ip_dstadd = socket.inet_aton(dst_ip)

#################
## Pack the IP Header ##
#################
# This portion creates the header by packing the above variables into a structure. The ! in the string means 'Big-Endian' network order, while the code following specifies how to store the info. Endian explained. Refer to link for character meaning.

ip_header = pack('!BBHHHBBH4s4s' , ip_ver_ihl, ip_tos, ip_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_check, ip_srcadd, ip_dstadd)

################
##Build TCP Header##
################
# source port. 1-65535
tcp_src =
# destination port. 1-65535
tcp_dst =
# sequence number. 1-4294967296
tcp_seq =
# tcp ack sequence number. 1-4294967296
tcp_ack_seq =
# can optionaly set the value of the offset and reserve. Offset is from 5 to 15. RES is normally 0.
#tcp_off_res =
# data offset specifying the size of tcp header * 4 which is 20
tcp_data_off =
# the 3 reserve bits + ns flag in reserve field
tcp_reserve =
# Combine the left shifted 4 bit tcp offset and the reserve field
tcp_off_res = (tcp_data_off << 4) + tcp_reserve   
# can optionally just set the value of the TCP flags
#tcp_flags =
# Tcp flags by bit starting from right to left
tcp_fin = 0                    # Finished
tcp_syn = 0                    # Synchronization
tcp_rst = 0                    # Reset
tcp_psh = 0                    # Push
tcp_ack = 0                    # Acknowledgement
tcp_urg = 0                    # Urgent
tcp_ece = 0                    # Explicit Congestion Notification Echo
tcp_cwr = 0                    # Congestion Window Reduced
# Combine the tcp flags by left shifting the bit locations and adding the bits together
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5) + (tcp_ece << 6) + (tcp_cwr << 7)
# maximum allowed window size reordered to network order. 1-65535 (socket.htons is deprecated)
tcp_win =
# tcp checksum which will be calculated later on
tcp_chk =
# urgent pointer only if urg flag is set
tcp_urg_ptr =

# The ! in the pack format string means network order
tcp_hdr = pack('!HHLLBBHHH', tcp_src, tcp_dst, tcp_seq, tcp_ack_seq, tcp_off_res, tcp_flags, tcp_win, tcp_chk, tcp_urg_ptr)

##########
##Message##
##########

# Your custom protocol fields or data. We are going to just insert data here.
# Ensure you obfuscate it though...don't want any clear text messages being spotted!
# You can encode various data encodings. Base64, binascii

message = b'last_name'                                    # This should be the student's last name per the prompt
hidden_msg = base64.b64encode(message)                    # base64.b64encode will encode the message to Base 64

######################
##Create the Pseudo Header##
######################

# After you create the tcp header, create the pseudo header for the tcp checksum.

src_address = socket.inet_aton(src_ip)
dst_address = socket.inet_aton(dst_ip)
reserved = 0
protocol = socket.IPPROTO_TCP
tcp_length = len(tcp_hdr) + len(hidden_msg)

#####################
##Pack the Pseudo Header##
#####################

ps_hdr = pack('!4s4sBBH', src_address, dst_address, reserved, protocol, tcp_length)
ps_hdr = ps_hdr + tcp_hdr + hidden_msg

#########################
##Define the Checksum Function##
#########################

def checksum(data):
        if len(data) % 2 != 0:
                data += b'\0'
        res = sum(array.array("H", data))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16
        return (~res) & 0xffff

tcp_chk = checksum(ps_hdr)

##############
##Final TCP Pack##
##############

# Pack the tcp header to fill in the correct checksum - remember checksum is NOT in network byte order
tcp_hdr = pack('!HHLLBBH', tcp_src, tcp_dst, tcp_seq, tcp_ack_seq, tcp_off_res, tcp_flags, tcp_win) + pack('H', tcp_chk) + pack('!H', tcp_urg_ptr)

# Combine all of the headers and the user data
packet = ip_header + tcp_hdr + hidden_msg

# s.connect((dst_ip, port)) # typically used for TCP
# s.send(packet)

# Send the packet. Sendto is used when we do not already have a socket connection. Sendall or send if we do.
s.sendto(packet, (dst_ip, 0))

# socket.send is a low-level method and basically just the C/syscall method send(3) / send(2). It can send fewer bytes than you requested, but returns the number of bytes sent.
#socket.sendall ﻿is a high-level Python-only method that sends the entire buffer you pass or throws an exception. It does that by calling socket.send ﻿ until everything has been sent or an error occurs.
----
