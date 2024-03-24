#!/usr/bin/env python

# BTC - 14xMeDbjsyBCtjCLsaKBYLqw4C2Sf145o5

'''
        ######################
        ## WIRELESS SCRIPTS ##
        ######################
'''


#Where Have you been..

from scapy.all import *

interface = 'wlan2'
probeReqs = []
def sniffProbe(p):
	if p.haslayer(Dot11ProbeReq):
		netName = p.getlayer(Dot11ProbeReq).info
		if netName not in probeReqs:
			probeReqs.append(netName)
			print '[+] The MAC Address Of The Device: ' + p.addr2.upper()
			print '[+] Detected New Probe Request   : ' + netName
			print '------------------------------------------------------'
sniff(iface=interface, prn=sniffProbe)
