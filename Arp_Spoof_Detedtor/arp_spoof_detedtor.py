import scapy.all as scapy
import os
import argparse

def get_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('-i', '--interface', help='interface')
	args = parser.parse_args()
	return args.interface

def sniffer(interface):
	print(f'[+] On gaurd {interface}')
	scapy.sniff(store= False ,iface= interface ,prn= processed_sniffed_pkt)


def get_mac(ip):
	arp_pkt = scapy.ARP(pdst=ip)
	ether_pkt = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff')
	broadcast_pkt = ether_pkt/arp_pkt
	res = scapy.srp(broadcast_pkt ,timeout= 1, verbose= False)[0]
	return res[0][1].hwsrc


def processed_sniffed_pkt(pkt):
	if pkt.haslayer(scapy.ARP) and pkt[scapy.ARP].op == 2:
		# pkt.show()
		try:
			real_mac = get_mac(pkt[scapy.ARP].psrc)	
			response_mac = pkt[scapy.ARP].hwsrc
			
			if real_mac != response_mac:
				os.system('echo `tput setab 1`You are under attack`tput setab 0`')
		except IndexError:
			pass		

interface = get_args()
sniffer(interface)

