#!/usr/bin/env python

# BTC - 14xMeDbjsyBCtjCLsaKBYLqw4C2Sf145o5

'''
        ######################
        ## WIRELESS SCRIPTS ##
        ######################
'''


from scapy.all import *
import struct

ap_list = []
def info(fm):
	if fm.haslayer(Dot11):
		if ((fm.type == 0) & (fm.subtype == 8)):
			if fm.addr2 not in ap_list:
					ap_list.append(fm.addr2)
					print "SSID --> ", fm.info, "-- BSSID --> ", fm.addr2.upper(),\
					"-- Channel --> ", ord(fm[Dot11Elt:3].info)

sniff(iface='wlan2', prn=info)
