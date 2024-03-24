#!/usr/bin/env python

# BTC - 14xMeDbjsyBCtjCLsaKBYLqw4C2Sf145o5

'''
        ######################
        ## WIRELESS SCRIPTS ##
        ######################
'''


from scapy.all import *

interface = 'wlan2'
hiddenNets=[]

def sniffDot11(p):
	if p.haslayer(Dot11Beacon):
		if p.getlayer(Dot11Beacon).info == '':
			addr2 = p.getlayer(Dot11).addr2
			if addr2 not in hiddenNets:
				hiddenNets.append(addr2)
				print '[+] Detected Hidden SSID | ' +\
				'with MAC: ' + addr2.upper()

sniff(iface=interface, prn=sniffDot11)
