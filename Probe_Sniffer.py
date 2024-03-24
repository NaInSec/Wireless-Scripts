#!/usr/bin/env python

# BTC - 14xMeDbjsyBCtjCLsaKBYLqw4C2Sf145o5

'''
        ######################
        ## WIRELESS SCRIPTS ##
        ######################
'''


from scapy.all import *

interface = "wlan2"
probe_res = []

def probesniff(fm):
	if fm.haslayer(Dot11ProbeResp):
		client_name = fm.info
		if fm.addr2 not in probe_res:
			print "[+] New AP Detected: ", client_name
			print "[+] MAC: ", fm.addr2.upper()
			probe_res.append(fm.addr2)
sniff(iface = interface, prn=probesniff)
