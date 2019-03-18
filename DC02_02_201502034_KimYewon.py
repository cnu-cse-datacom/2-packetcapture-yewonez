import socket
import struct

def parsing_ethernet_header(data):
	ethernet_header = struct.unpack("!6c6c2s", data)
	ether_src=convert_ethernet_address(ethernet_header[0:6])
	ether_dest=convert_ethernet_address(ethernet_header[6:12])
	ip_header = "0x" + ethernet_header[12].hex()
	
	print("==============ehthernet header================")
	print("src_mac_address:", ether_src)
	print("dest_mac_address:", ether_dest)
	print("ip_version ",ip_header)

def convert_ethernet_address(data):
	ethernet_addr = list()
	for i in data:
		ethernet_addr.append(i.hex())
	ethernet_addr=":".join(ethernet_addr)
	return ethernet_addr

def parsing_ip_header(data):
	ip_header = struct.unpack("!1c1c2s2c2c1c1c2c4c4c",data)
	ip_version_n_length = ip_version_make(ip_header[0])
	ip_type_service = ip_service_type(ip_header[1])
	ip_tot_length = ip_total_length(ip_header[2])
	ip_ID = ip_identification(ip_header[3:5])
	ip_flags = ip_flag(ip_header[5:7])
	ip_flags_bit = ip_flag_bit(ip_header[5])
	ip_ttl = get_ttl(ip_header[7])
	ip_protocol = get_protocol(ip_header[8])
	ip_checksum = get_checksum(ip_header[9:11])
	ip_src = src_dest(ip_header[11:15])
	ip_dest = src_dest(ip_header[15:19])	

#	print(ip_header)
	print("============ip header==================")
	print("ip_version : ", ip_version_n_length[0])
	print("ip_length : ", ip_version_n_length[1])
	print("differentiated_service_codepoint : 0b",ip_type_service[0])
	print("explicit_congestion_notification : 0b",ip_type_service[1])
	print("total_length : ", ip_tot_length[0])
	print("identification : ", ip_ID)
	print("flags : ",ip_flags)
	print(">>>reserved bit : ", ip_flags_bit[0])
	print(">>>fragments : ", ip_flags_bit[1])
	print(">>>fragments_offset :",ip_flags_bit[2])
	print("Time to live : ",ip_ttl)
	print("protocol : ",ip_protocol)
	print("header chekcsum : ",ip_checksum)
	print("ip_src : ", ip_src)
	print("ip_dest : ", ip_dest)

def src_dest(data):
	ip_addr = list()
	for i in data:
		numb = struct.unpack("!1B", i)
		newest = str(numb[0])
		ip_addr.append(newest)
	ip_addr=".".join(ip_addr)
	return ip_addr

def ip_version_make(data):
#	ip_version = data.hex()
#	version_n_length = [int(ip_version[0],16), int(ip_version[1],16)]
#	print("test1 : ",data[0])
	temp1 = data[0]>>4
#	print("test2 : ",temp1)
	temp2 = data[0]&0xF
	version_n_length = [temp1,temp2]
	return version_n_length

def ip_service_type(data):
	ip_type =format(int(data.hex(),16),'b')
	temp = ip_type.zfill(8)
	ip_service_type_list = list()
	ip_service_type_list.append(temp[0:len(temp)-2])
	ip_service_type_list.append(temp[len(temp)-2:])
	return ip_service_type_list

def ip_total_length(data):
	return two_byte_dec(data)
def two_byte_dec(data):
	temp = data
	decoded_number = struct.unpack("!1H",temp)
	return decoded_number


def ip_hex_return(data):
	ip_id_list = list()
	ip_id_list.append("0x")
	for i in data:
		ip_id_list.append(i.hex())
	ip_id_list = "".join(ip_id_list)
	return ip_id_list
def ip_identification(data):
	return ip_hex_return(data)

def ip_flag(data):
	return ip_hex_return(data)
def ip_flag_bit(data):
	flagbit = format(int(data.hex(),16),'b')
	temp = flagbit.zfill(4)
	flaglist = list()
	flaglist.append(temp[0])
	flaglist.append(temp[1])
	flaglist.append(temp[2])
	return flaglist
def get_ttl(data):
	temp = int("0x"+data.hex(),16)
	return temp
def get_protocol(data):
	temp = int("0x"+data.hex(),16)
	return temp
def get_checksum(data):
	return ip_hex_return(data)

def parsing_udp_header(data_udp):
	udp_header = struct.unpack("!2s2s2s2c",data_udp)
	udp_srcport = two_byte_dec(udp_header[0])
	udp_dstport = two_byte_dec(udp_header[1])
	udp_length = two_byte_dec(udp_header[2])
	udp_header_chsum = ip_hex_return(udp_header[3:4])
	print("=============udp header================")
	#print(udp_header)
	print("src_port : ", udp_srcport[0])
	print("dst_port : ", udp_dstport[0])
	print("length : ", udp_length[0])
	print("header_checksum : ", udp_header_chsum)

def parsing_tcp_header(data_tcp):	
	tcp_header = struct.unpack("!2s2s4s4s1c1c2s2s2s",data_tcp)
#	print(tcp_header)
	src_port = tcp_src_port(tcp_header[0])
	dec_port = tcp_dec_port(tcp_header[1])
	seq_num = tcp_seq_num(tcp_header[2])
	ack_num = tcp_ack_num(tcp_header[3])
	header_len = tcp_header_len(tcp_header[4])
	flags = tcp_flags(tcp_header[4:6])
	reserved = tcp_reserve(tcp_header[4])
	flags_bit = tcp_flags_bit(tcp_header[5])
	window_size_value  = tcp_window_size_value(tcp_header[6])
	checksum = tcp_checksum(tcp_header[7])
	urgent_pointer = tcp_urgent_pointer(tcp_header[8])
	print("=============tcp header================")
#	print(tcp_header)
	print("src_port : ",src_port[0])
	print("dec_port : ",dec_port[0])
	print("seq_num : ",seq_num[0])
	print("ack_num : ",ack_num[0])
	print("header_len : ",header_len)
	print("flags : ",flags)
	print(">>>reserved : ",reserved[0])
	print(">>>nonce : ",reserved[1])
	print(">>>cwr : ",flags_bit[0])
	print(">>>ECN-echo : ",flags_bit[1])
	print(">>>urgent : ",flags_bit[2])
	print(">>>ack : ",flags_bit[3])
	print(">>>push : ",flags_bit[4])
	print(">>>reset : ",flags_bit[5])
	print(">>>syn : ",flags_bit[6])
	print(">>>fin : ",flags_bit[7])
	print("window_size : ",window_size_value[0])
	print("checksum : ",checksum[0])
	print("urgent_pointer : ",urgent_pointer[0])
def tcp_window_size_value(data):
	return two_byte_dec(data)
def tcp_checksum(data):
	return two_byte_dec(data)
def tcp_urgent_pointer(data):
	return two_byte_dec(data)


def tcp_flags_bit(data):
	temp1 = format(data[0],'b')
	temp = temp1.zfill(8)
	cwr = temp[0]
	echo = temp[1]
	urgent = temp[2]
	ack = temp[3]
	push = temp[4]
	reset = temp[5]
	syn = temp[6]
	fin = temp[7]
	
	flag_list = [cwr, echo, urgent, ack, push, reset,syn,fin]
	return flag_list

def tcp_reserve(data):
#	print("reserve test : ", data[0])
	res = (data[0] >>1) & 0x7
#	print("reserve test : ", data[0]>>1)
#	print("reserve test : ",res)
	non = data[0] & 0x1
#	print("reserve : ",non)
	reserved_set = [res,non]
	return reserved_set

def tcp_flags(data):
	t1 = data[0][0]&0xF
	t2 = format(t1,'x')
	temp = "0x"+t2+data[1].hex()
#	temp = int("0x"+t1+data[1].hex(),16)
	return temp

def tcp_header_len(data):
	temp = data.hex()
	temp2 = int("0x"+temp[0],16)
	return temp2*4

def tcp_src_port(data):
	return two_byte_dec(data)

def tcp_dec_port(data):
	return two_byte_dec(data)

def tcp_seq_num(data):
	return four_byte_dec(data)

def tcp_ack_num(data):
	return four_byte_dec(data)

def four_byte_dec(data):
	temp = data
	d_n = struct.unpack("!1I",temp)
	return d_n

recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
recv_socket_udp = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.ntohs(0x0800))
#recv_socket_tcp = socket.socket(socket.AF_PACKET, socket.SOCK_STREAM, socket.ntohs(0x0800))

#SOCK_STREAM : TCP
#SOCK_DGRAM : UDP

while True:
#	print("<<<<<<<<<<Packet Captur Start>>>>>>>>>>>>>")
	data = recv_socket.recvfrom(2000)
	data_udp = recv_socket_udp.recvfrom(2000)
	temp = struct.unpack("!1c1c2s2c2c1c1c2c4c4c",data[0][14:34])
	temp_prc = get_protocol(temp[8])	
#	print("============================== :",temp_prc)
	if temp_prc == 17:
		print("<<<<<<<<<<Packet Capture Start>>>>>>>>>>>>>")
		parsing_ethernet_header(data[0][0:14])
#		parsing_ip_header(data[0][14:34])
		parsing_ip_header(data_udp[0][0:20])
		parsing_udp_header(data_udp[0][20:28])
	elif temp_prc == 6:
		print("<<<<<<<<<<Packet Capture Start>>>>>>>>>>>>>")
		parsing_ethernet_header(data[0][0:14])
		parsing_ip_header(data[0][14:34])
		parsing_tcp_header(data[0][34:54])
		

