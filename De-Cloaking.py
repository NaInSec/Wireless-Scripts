#!/usr/bin/env python
# BTC - 14xMeDbjsyBCtjCLsaKBYLqw4C2Sf145o5

'''
        ######################
        ## WIRELESS SCRIPTS ##
        ######################
'''

import sys
from scapy.all import *
interface ='wlan2'
hiddenNets =[]
unhiddenNets =[]
def sniffDot11(p):
	if p.haslayer(Dot11ProbeResp):
		addr2 =p.getlayer(Dot11).addr2
		if (addr2 in hiddenNets) & (addr2 not in unhiddenNets):
			unhiddenNets.append(addr2)
			netName =p.getlayer(Dot11ProbeResp).info
			print '[+] Decloaked Hidden SSID: ' +\
			netName +' for MAC: ' + addr2.upper()
	if p.haslayer(Dot11Beacon):
		if p.getlayer(Dot11Beacon).info == '':
			addr2 = p.getlayer(Dot11).addr2
			if addr2 not in hiddenNets:
				hiddenNets.append(addr2)
				print '[+] Detected Hidden SSID | ' +\
				'with MAC: ' + addr2.upper()
sniff(iface=interface, prn=sniffDot11)
