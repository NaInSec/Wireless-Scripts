#!/usr/bin/env python

# BTC - 14xMeDbjsyBCtjCLsaKBYLqw4C2Sf145o5

'''
        ######################
        ## WIRELESS SCRIPTS ##
        ######################
'''


from scapy.all import *

interface='wlan2'
dpkt = 1

def detecter(fm):
	if fm.haslayer(Dot11):
		if (fm.haslayer(Dot11Deauth)):
			global dpkt
			print "Deauth Detected: ", dpkt
			dpkt = dpkt + 1

sniff(iface=interface, prn=detecter)

