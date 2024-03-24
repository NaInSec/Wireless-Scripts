#!/usr/bin/env python
# BTC - 14xMeDbjsyBCtjCLsaKBYLqw4C2Sf145o5

'''
        ######################
        ## WIRELESS SCRIPTS ##
        ######################
'''


from scapy.all import *

interface = "wlan0"
probe_req = []
ap_name = raw_input("Please enter thee AP name: ")

def probesniff(fm):
	if fm.haslayer(Dot11ProbeResp):
		client_name = fm.info
		if client_name == ap_name:
			if fm.addr2 not in probe_req:
				print "New Probe Request: ", client_name
				print "MAC ", fm.addr2.upper()
				probe_req.append(fm.addr2)
sniff(iface = interface, prn=probesniff)
