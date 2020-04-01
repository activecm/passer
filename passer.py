#!/usr/bin/python
"""Passer learns, by watching network traffic, about the servers and clients on your network."""
#Copyright 2008-2018, William Stearns <william.l.stearns@gmail.com>
#Passer is a PASsive SERvice sniffer.
#Home site http://www.stearns.org/passer/
#Github repository https://github.com/organizations/activecm/passer/
#Dedicated to Mae Anne Laroche.

#Released under the GPL version 3:
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <https://www.gnu.org/licenses/>.


#======== Imports ========
import os
import ipaddress
import sys
import re
import json
import binascii		#converting hex text to raw bytes
import signal		#For catching Ctrl-C
import string		#Needed for python 2.5.2?
import warnings		#Needed for p0f?
import unicodedata	#Needed for removing control characters
import pytz
import __main__		#Needed to access variables in __main__ from functions without implicit/explicit globals

try:
	#from scapy.all import p0f
	#from scapy.all import ARP, CookedLinux, DHCP, DNS, DNSQR, DNSRR, Dot11, Dot11AssoReq, Dot11AssoResp, Dot11Auth, Dot11Beacon, Dot11Deauth, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, Dot11WEP, Dot3, ESP, Ether, GRE, ICMP, ICMPerror, ICMPv6DestUnreach, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6MLDone, ICMPv6MLQuery, ICMPv6MLReport, ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6ND_RA, ICMPv6ND_RS, ICMPv6ND_Redirect, ICMPv6NDOptDstLLAddr, ICMPv6NDOptPrefixInfo, ICMPv6NDOptRDNSS, ICMPv6NDOptSrcLLAddr, ICMPv6PacketTooBig, ICMPv6TimeExceeded, IP, IPerror, IPerror6, IPv6, IPv6ExtHdrHopByHop, ISAKMP, LLC, LLMNRQuery, NBNSQueryRequest, NBNSQueryResponse, NBTDatagram, NTPControl, NTPPrivate, PcapWriter, RadioTap, Radius, Raw, SNMP, SNMPget, SNMPbulk, SNMPvarbind, SNMPresponse, TCP, TCPerror, TFTP, UDP, UDPerror, conf, ls, sniff
	#When running pylint, comment out the following line and uncomment the above, revert when done with pylint
	from scapy.all import * #Required for Scapy 2.0 and above
	use_scapy_all = True
except:
	from scapy import * #Scapy 1.0
	use_scapy_all = False

if use_scapy_all:
	try:
		from scapy.all import NTPHeader
		has_advanced_ntp_headers = True						#V2.2.0 and below don't have NTPHeader
	except ImportError:
		has_advanced_ntp_headers = False
else:
	has_advanced_ntp_headers = False

sys.path.insert(0, '.')			#Allows us to load from the current directory (There was one claim that we need to create an empty file __init__.py , but this does not appear to be required.)
from passer_lib import *		#Support functions for this script
try:
	if not passer_lib_version:
		sys.stderr.write('Unable to load passer_lib , exiting.\n')
		quit()
except NameError:
	sys.stderr.write('Unable to load passer_lib , exiting.\n')
	quit()


#Note, to get p0f working, one must:
#sudo hack /usr/lib/python2.6/site-packages/scapy/modules/p0f.py
#and add:
#from scapy.all import *
#And:
#def p0f_correl(x,y):
#    d = 0
#    # wwww can be "*" or "%nn"
#    #d += (x[0] == y[0] or y[0] == "*" or (y[0][0] == "%" and x[0].isdigit() and (int(x[0]) % int(y[0][1:])) == 0))
#Change above line to:
#    d += (x[0] == y[0] or y[0] == "*" or (y[0][0] == "%" and str(x[0]).isdigit() and (int(x[0]) % int(y[0][1:])) == 0))

if os.path.isfile("/etc/p0f/p0f.fp") or os.path.exists("/opt/local/share/p0f/p0f.fp") or os.path.exists("/usr/share/p0f/p0f.fp"):
	load_module("p0f")
else:
	sys.stderr.write("/etc/p0f/p0f.fp not found; please install p0f version 2 to enable OS fingerprinting.\n")
	sys.stderr.flush




#======== Global arrays ========
#These two are used to discover servers.  If we've seen a SYN go to a port, and a SYN/ACK back from it,
#that's a pretty good sign it's a server.  Not truly stateful, but a generally good guess.



botnet_warning_list = {}	#Dictionary of "IP,proto_port": ['warning1', 'warning2'] entries that say if you see that trio, that IP should get this/these warnings.
				#If we see syn/ack coming back from tcp C&C's, tag the host as 'bot_candc' and the dest IP of the syn/ack as 'bot'
				#For UDP, just use any data heading _to_ the CandC to tag both ends (source is 'bot', dest os 'bot_candc')
				#FIXME - implement


must_stop = False		#Set to true if exit requested by signal



#======== Port lists ========

#From 122.224.158.195, payload is "8'\x82\xd7\x8fZ\xdbc\xfe\x00\x00\x00\x00\x00"
fenull_scan_names = {"21": "udp-21", "22": "udp-22", "23": "udp-23", "25": "udp-25", "49": "udp-49", "80": "udp-80", "102": "udp-102", "110": "udp-110", "143": "udp-143", "636": "udp-636", "992": "udp-992", "993": "udp-993", "995": "udp-995"}
empty_payload_ports = ('1', '17', '19', '18895', '50174', '50597', '50902', '52498', '52576', '52620', '52775', '52956', '55180', '56089', '57347', '57563', '57694', '58034', '58153', '58861', '59024', '59413', '60463', '60799', '61016', '61651', '62473', '62915', '63137', '63556', '63571', '63878', '64727', '65154', '65251')
halflife_altport = ("1265", "2303", "20100", "21025", "21550", "27000", "27017", "27018", "27019", "27022", "27030", "27035", "27050", "27078", "27080", "28015", "28100", "45081")

#For all of the following, see if the payload contains snmp.
### IPv4/UDPv4/21 22 23 25 tacacs=49 http=80 iso-tsap=102 110 143 igmpv3lite=465 ldaps=636 omirr=808 992 993 995 client
snmp_altport = ("21", "22", "23", "25", "49", "80", "102", "110", "143", "465", "636", "808", "992", "993", "995")

meet_ports = ('19302', '19303', '19304', '19305', '19306', '19307', '19308', '19309')				#https://support.google.com/a/answer/7582935?hl=en
qualys_udp_scan_port_names = {"7": "echo", "13": "daytime", "17": "qotd", "19": "chargen", "37": "time", "111": "sunrpc", "123": "ntp", "177": "xdmcp", "407": "timbuktu", "443": "udp443", "464": "kpasswd", "517": "talk", "518": "ntalk", "520": "rip", "623": "asf-rmcp", "1194": "openvpn", "1434": "mssql", "1645": "sightline", "1701": "l2f", "1812": "radius", "1978": "unisql", "2002": "globe", "2049": "nfs", "4000": "terabase"}
skype_ports = ('21105', '21546', '22795', '23353', '24484', '26079', '27252', '27944')
zmap_host_www_ports = ("80", "563", "655", "830", "898", "989", "990", "991", "992", "995", "1293", "1707", "1900", "2484", "3269", "3544", "4843", "5000", "5031", "6379", "6619", "9899", "11214", "11215", "18091", "18092", "37215")
www163com_ports = ("21", "22", "23", "25", "49", "80", "102", "110", "143", "636", "992", "993", "995")

#======== IP address lists ========
SteamFriendsServers = ("69.28.148.250", "69.28.156.250", "72.165.61.161", "72.165.61.185", "72.165.61.186", "72.165.61.188", "68.142.64.164", "68.142.64.165", "68.142.64.166")
meet_hosts = (
		'2607:f8b0:4002:c08::7f', '2607:f8b0:400c:c00::7f', '2a00:1450:4013:c03::7f', '2a00:1450:400c:c08::7f', '2800:3f0:4003:c00::7f', '2a00:1450:400c:c08::7f', '2607:f8b0:4002:c07::7f', '2a00:1450:4010:c01::7f', '2607:f8b0:400d:c0d::7f', "2a00:1450:400c:c06::7f", '2404:6800:4003:c00::7f', '2607:f8b0:400d:c09::7f', '2a00:1450:400c:c06::7f', '2a00:1450:4010:c08::7f',
		'2607:f8b0:4002:0c08:0000:0000:0000:007f', '2607:f8b0:400c:0c00:0000:0000:0000:007f', '2a00:1450:4013:0c03:0000:0000:0000:007f', '2a00:1450:400c:0c08:0000:0000:0000:007f', '2800:3f0:4003:0c00:0000:0000:0000:007f', '2a00:1450:400c:0c08:0000:0000:0000:007f', '2607:f8b0:4002:0c07:0000:0000:0000:007f', '2a00:1450:4010:0c01:0000:0000:0000:007f', '2607:f8b0:400d:0c0d:0000:0000:0000:007f', "2a00:1450:400c:0c06:0000:0000:0000:007f", '2404:6800:4003:c00:0000:0000:0000:7f', '2607:f8b0:400d:0c09:0000:0000:0000:007f', '2a00:1450:400c:0c06:0000:0000:0000:007f', '2a00:1450:4010:0c08:0000:0000:0000:007f',
		'64.233.165.127', '64.233.177.127', '64.233.186.127', '66.102.1.127', '74.125.134.127', '74.125.140.127', '74.125.143.127', '74.125.196.127', '74.125.200.127', '173.194.207.127', '209.85.232.127'
	     )				#Second line is the same as the first with ipv6 expanded.
skype_hosts = ('52.179.141.141', '100.112.42.45')
shodan_hosts = ('66.240.192.138', '66.240.236.119', '71.6.146.185', '80.82.77.33', '94.102.49.190')		#census8.shodan.io, census6.shodan.io, pirate.census.shodan.io, sky.census.shodan.io, flower.census.shodan.io
qualys_scan_ips = ('64.39.99.152', '64.39.111.38')
qualys_subnet_starts = ('64.39.96.', '64.39.99.', '64.39.102.', '64.39.103.', '64.39.105.', '64.39.106.', '64.39.111.')
vonage_ntp = ("216.115.23.75", "216.115.23.76", "69.59.240.75")
vonage_sip_servers = ("216.115.30.28", "69.59.227.77", "69.59.232.33", "69.59.240.84")
aol_dns_servers = ("205.188.146.72", "205.188.157.241", "205.188.157.242", "205.188.157.243", "205.188.157.244", "64.12.51.145", "64.12.51.148", "149.174.54.131")
nessus_scan_ips = ('167.88.145.12')
known_scan_ips = ('137.226.113.7')
broadcast_udp_ports = ("2223", "8082", "8600", "8097", "9034", "9035", "9036", "9500", "9999", "21327", "21328")

#======== Decodes ========
nullbyte = binascii.unhexlify('00')
twobyte = binascii.unhexlify('02')
twozero = binascii.unhexlify('0200')
fournulls = binascii.unhexlify('00000000')
fenulls = binascii.unhexlify('fe0000000000')
stream_ihs_discovery_header = binascii.unhexlify('FFFFFFFF214C5FA0')
www163com_payload = binascii.unhexlify('03') + b"www" + binascii.unhexlify('03') + b"163" + binascii.unhexlify('03') + b"com"	#\x03www\x03163\x03com
a0_string = b'A' + nullbyte
zeroone = binascii.unhexlify('0001')
zerotwo = binascii.unhexlify('0002')
eight_fs = binascii.unhexlify('FFFFFFFF')
crestron_prelude = binascii.unhexlify('14000000010400030000')
ip_start_bytes = binascii.unhexlify('4500')
two_prelude_ip_start = (binascii.unhexlify('020000004500'), binascii.unhexlify('020000004502'), binascii.unhexlify('020000004510'))
quake3_disconnect = binascii.unhexlify('FFFFFFFF') + b'disconnect'
torrent_connection_id = binascii.unhexlify('0000041727101980')
ethernetip_list_identity = binascii.unhexlify('6300')
ntp_get_monlist = binascii.unhexlify('1700032a')
cacti_payload = binascii.unhexlify('000100') + b'cacti-monitoring-system' + binascii.unhexlify('00')
ubiquiti_discover = binascii.unhexlify('01000000')

#======== Regexes ========
StoraHostnameMatch = re.compile('Hostname:<([a-zA-Z0-9_\.-]+)>')
SSDPLocationMatch = re.compile('LOCATION:([a-zA-Z0-9:,/_\. -]+)\r')
SSDPServerMatch = re.compile('[Ss][Ee][Rr][Vv][Ee][Rr]:([a-zA-Z0-9:,/_\. -]+)\r')
BrotherAnnounceMatch = re.compile('IP=([0-9][0-9\.]*):5492[56];IPv6=\[([0-9a-fA-F:][0-9a-fA-F:]*)\]:5492[56],\[([0-9a-fA-F:][0-9a-fA-F:]*)\]:5492[56];NODENAME="([0-9a-zA-Z][0-9a-zA-Z]*)"')
SyslogMatch = re.compile('^<[0-9][0-9]*>[A-Z][a-z][a-z] [ 0-9][0-9] [0-2][0-9]:[0-9][0-9]:[0-9][0-9] ([^ ][^ ]*) ([^: [][^: []*)[: []')		#Match 1 is short hostname, match 2 is process name that generated the message


#======== Misc ========
#See "Reference ID (refid)" in https://www.ietf.org/rfc/rfc5905.txt
known_ntp_refs = ('1PPS', 'ACTS', 'ATOM', 'BCS', 'CDMA', 'CHU', 'CTD', 'DCF', 'DCFP', 'DCFa', 'DCFp', 'DCFs', 'GAL', 'GCC', 'GNSS', 'GOES', 'GPS', 'GPS1', 'GPSD', 'GPSm', 'GPSs', 'GOOG', 'HBG', 'INIT', 'IRIG', 'JJY', 'kPPS', 'LOCL', 'LORC', 'MRS', 'MSF', 'MSL', 'NICT', 'NIST', 'NMC1', 'NMEA', 'NTS', 'OCXO', 'ONBR', 'PPS', 'PPS0', 'PPS1', 'PTB', 'PTP', 'PZF', 'RATE', 'ROA', 'SHM', 'SLK', 'SOCK', 'STEP', 'TAC', 'TDF', 'TRUE', 'UPPS', 'USIQ', 'USNO', 'UTC', 'WWV', 'WWVB', 'WWVH', 'XMIS', 'i', 'shm0', '', None)

botnet_domains = ('ddos.cat.')
botnet_hosts = ('magnesium.ddos.cat.')

#For my internal use to look for new service strings
#This payload logging is disabled when prefs['devel'] == False
#Quite likely a security risk, I don't recommend enabling it.
ServerPayloadDir = '/var/tmp/passer-server/'
ClientPayloadDir = '/var/tmp/passer-client/'

debug_known_layer_lists = False


known_layer_lists = [
			['802.3', 'LLC', 'Raw'],
			['802.3', 'LLC', 'SNAP', 'Raw'],
			['802.3', 'LLC', 'SNAP', 'Spanning Tree Protocol', 'Raw'],
			['802.3', 'LLC', 'Spanning Tree Protocol', 'Padding'],
			['802.3', 'Padding'],

			['cooked linux', 'IP', 'ESP'],
			['cooked linux', 'IP', 'ICMP'],
			['cooked linux', 'IP', 'ICMP', 'IP in ICMP', 'ICMP in ICMP'],
			['cooked linux', 'IP', 'ICMP', 'IP in ICMP', 'ICMP in ICMP', 'Raw'],
			['cooked linux', 'IP', 'ICMP', 'IP in ICMP', 'ICMP in ICMP', 'Raw', 'Padding'],
			['cooked linux', 'IP', 'ICMP', 'IP in ICMP', 'TCP in ICMP'],
			['cooked linux', 'IP', 'ICMP', 'IP in ICMP', 'TCP in ICMP', 'Raw'],
			['cooked linux', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP'],
			['cooked linux', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'DNS'],
			['cooked linux', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'DNS', 'Padding'],
			['cooked linux', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'Raw'],
			['cooked linux', 'IP', 'ICMP', 'Raw'],
			['cooked linux', 'IP', 'Raw'],
# p[CookedLinux].pkttype == 'unicast' will be useful
			['cooked linux', 'IP', 'TCP'],
			['cooked linux', 'IP', 'TCP', 'Raw'],
			['cooked linux', 'IP', 'UDP', 'DNS'],
			['cooked linux', 'IP', 'UDP', 'DNS', 'Raw'],
# Pull current timestamp out of this (.ref, .orig, .recv, or .sent fields of p[NTPHeader] ; see https://tools.ietf.org/html/rfc958)
			['cooked linux', 'IP', 'UDP', 'NTPHeader'],
			['cooked linux', 'IP', 'UDP', 'Private (mode 7)', 'Raw'],
			['cooked linux', 'IP', 'UDP', 'Raw'],

			['Ethernet', '802.1Q', 'ARP', 'Padding'],

			['Ethernet', '802.1Q', 'IP', 'ESP'],

			['Ethernet', '802.1Q', 'IP', 'GRE', 'IP', 'Raw'],
			['Ethernet', '802.1Q', 'IP', 'GRE', 'IP', 'TCP'],
			['Ethernet', '802.1Q', 'IP', 'GRE', 'IP', 'TCP', 'Raw'],

			['Ethernet', '802.1Q', 'IP', 'GRE', 'IP', 'UDP'],
			['Ethernet', '802.1Q', 'IP', 'GRE', 'IP', 'UDP', 'BOOTP', 'DHCP options'],
			['Ethernet', '802.1Q', 'IP', 'GRE', 'IP', 'UDP', 'DNS'],
			['Ethernet', '802.1Q', 'IP', 'GRE', 'IP', 'UDP', 'DNS', 'Raw'],
			['Ethernet', '802.1Q', 'IP', 'GRE', 'IP', 'UDP', 'ISAKMP', 'ISAKMP SA'],
			['Ethernet', '802.1Q', 'IP', 'GRE', 'IP', 'UDP', 'NBNS query request'],
			['Ethernet', '802.1Q', 'IP', 'GRE', 'IP', 'UDP', 'NTPHeader'],
			['Ethernet', '802.1Q', 'IP', 'GRE', 'IP', 'UDP', 'Private (mode 7)'],
			['Ethernet', '802.1Q', 'IP', 'GRE', 'IP', 'UDP', 'Private (mode 7)', 'Raw'],
			['Ethernet', '802.1Q', 'IP', 'GRE', 'IP', 'UDP', 'RIP header', 'RIP entry'],
			['Ethernet', '802.1Q', 'IP', 'GRE', 'IP', 'UDP', 'Raw'],
			['Ethernet', '802.1Q', 'IP', 'GRE', 'IP', 'UDP', 'SNMP'],
			['Ethernet', '802.1Q', 'IP', 'GRE', 'IP', 'UDP', 'TFTP opcode', 'TFTP Read Request'],

			['Ethernet', '802.1Q', 'IP', 'ICMP', 'IP in ICMP', 'ICMP in ICMP'],
			['Ethernet', '802.1Q', 'IP', 'ICMP', 'IP in ICMP', 'ICMP in ICMP', 'Raw'],
			['Ethernet', '802.1Q', 'IP', 'ICMP', 'IP in ICMP', 'ICMP in ICMP', 'Raw', 'Padding'],
			['Ethernet', '802.1Q', 'IP', 'ICMP', 'IP in ICMP', 'TCP in ICMP'],
			['Ethernet', '802.1Q', 'IP', 'ICMP', 'IP in ICMP', 'TCP in ICMP', 'Padding'],
			['Ethernet', '802.1Q', 'IP', 'ICMP', 'IP in ICMP', 'TCP in ICMP', 'Raw'],
			['Ethernet', '802.1Q', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP'],
			['Ethernet', '802.1Q', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'Raw'],
			['Ethernet', '802.1Q', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'DNS'],
			['Ethernet', '802.1Q', 'IP', 'ICMP', 'Padding'],
			['Ethernet', '802.1Q', 'IP', 'ICMP', 'Raw'],
			['Ethernet', '802.1Q', 'IP', 'ICMP', 'Raw', 'Padding'],

			['Ethernet', '802.1Q', 'IP', 'Raw'],
			['Ethernet', '802.1Q', 'IP', 'Raw', 'Padding'],

			['Ethernet', '802.1Q', 'IP', 'TCP'],
			['Ethernet', '802.1Q', 'IP', 'TCP', 'Padding'],
			['Ethernet', '802.1Q', 'IP', 'TCP', 'Raw'],
			['Ethernet', '802.1Q', 'IP', 'TCP', 'Raw', 'Padding'],
# Warning; Skinny layer appears to be a mis-identification
			['Ethernet', '802.1Q', 'IP', 'TCP', 'Skinny', 'Raw'],

			['Ethernet', '802.1Q', 'IP', 'UDP', 'DNS'],
			['Ethernet', '802.1Q', 'IP', 'UDP', 'DNS', 'Padding'],
			['Ethernet', '802.1Q', 'IP', 'UDP', 'DNS', 'Raw'],
			['Ethernet', '802.1Q', 'IP', 'UDP', 'DNS', 'Raw', 'Padding'],
			['Ethernet', '802.1Q', 'IP', 'UDP', 'Raw'],
			['Ethernet', '802.1Q', 'IP', 'UDP', 'Raw', 'Padding'],
			['Ethernet', '802.1Q', 'IP', 'UDP', 'SNMP'],

			['Ethernet', '802.1Q', 'IP', 'VRRP', 'Padding'],

			['Ethernet', '802.1Q', 'IPv6', 'ICMPv6 Destination Unreachable', 'IPv6 in ICMPv6', 'TCP in ICMP'],
			['Ethernet', '802.1Q', 'IPv6', 'ICMPv6 Destination Unreachable', 'IPv6 in ICMPv6', 'UDP in ICMP', 'DNS'],
			['Ethernet', '802.1Q', 'IPv6', 'ICMPv6 Destination Unreachable', 'IPv6 in ICMPv6', 'UDP in ICMP', 'Raw'],
			['Ethernet', '802.1Q', 'IPv6', 'ICMPv6 Echo Reply'],
			['Ethernet', '802.1Q', 'IPv6', 'ICMPv6 Echo Request'],
			['Ethernet', '802.1Q', 'IPv6', 'ICMPv6 Neighbor Discovery - Neighbor Advertisement'],
			['Ethernet', '802.1Q', 'IPv6', 'ICMPv6 Neighbor Discovery - Neighbor Advertisement', 'ICMPv6 Neighbor Discovery Option - Destination Link-Layer Address'],
# Grab source mac from last option
			['Ethernet', '802.1Q', 'IPv6', 'ICMPv6 Neighbor Discovery - Neighbor Solicitation', 'ICMPv6 Neighbor Discovery Option - Source Link-Layer Address'],
			['Ethernet', '802.1Q', 'IPv6', 'ICMPv6 Time Exceeded', 'IPv6 in ICMPv6', 'UDP in ICMP', 'DNS'],
#(raw contains E\x00\x00 8 bytes in)
			['Ethernet', '802.1Q', 'IPv6', 'IP', 'GRE', 'Raw'],
			['Ethernet', '802.1Q', 'IPv6', 'Padding'],
			['Ethernet', '802.1Q', 'IPv6', 'Raw'],
			['Ethernet', '802.1Q', 'IPv6', 'TCP'],
			['Ethernet', '802.1Q', 'IPv6', 'TCP', 'Raw'],
			['Ethernet', '802.1Q', 'IPv6', 'UDP', 'DNS'],
			['Ethernet', '802.1Q', 'IPv6', 'UDP', 'Raw'],

			['Ethernet', '802.1Q', 'LLC', 'SNAP', 'Spanning Tree Protocol', 'Raw'],

			['Ethernet', '802.1Q', 'Raw'],

			['Ethernet', 'ARP'],
			['Ethernet', 'ARP', 'Padding'],

			['Ethernet', 'EAPOL', 'Raw'],

			['Ethernet', 'IP', 'AH'],

			['Ethernet', 'IP', 'ICMP'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'ICMP in ICMP'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'ICMP in ICMP', 'Raw'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'ICMP in ICMP', 'Raw', 'Padding'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'Raw'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'TCP in ICMP'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'TCP in ICMP', 'Padding'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'TCP in ICMP', 'Raw'],

			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'Control message'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'DNS'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'DNS', 'Padding'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'DNS', 'Raw'],
 			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'ESP'],
 			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'ISAKMP', 'ISAKMP SA'],
 			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'ISAKMP', 'Raw'],
 			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'NBNS query request'],
 			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'NBNS query request', 'Raw'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'NBNS query response', 'Raw'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'NBT Datagram Packet', 'Raw'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'NTPHeader'],
#(happened to be malicious, and headers were misparsed))
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'NTPHeader', 'NTPv4 extensions'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'NTPHeader', 'Padding'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'NTPHeader', 'Raw'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'Padding'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'Private (mode 7)'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'Private (mode 7)', 'Raw'],
 			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'RIP header'],
 			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'RIP header', 'RIP entry'],
 			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'RIP header', 'RIP entry', 'Raw'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'Radius'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'Raw'],
			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'Raw', 'Padding'],
 			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'SNMP'],
 			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'SNMP', 'Raw'],
 			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'TFTP opcode', 'TFTP Read Request'],
 			['Ethernet', 'IP', 'ICMP', 'IP in ICMP', 'UDP in ICMP', 'TFTP opcode', 'Raw'],
			['Ethernet', 'IP', 'ICMP', 'Padding'],
			['Ethernet', 'IP', 'ICMP', 'Raw'],
			['Ethernet', 'IP', 'ICMP', 'Raw', 'Padding'],

			['Ethernet', 'IP', 'Raw'],
 			['Ethernet', 'IP', 'Raw', 'Padding'],

			['Ethernet', 'IP', 'TCP'],
			['Ethernet', 'IP', 'TCP', 'NBT Session Packet', 'SMBNegociate Protocol Request Header'],
			['Ethernet', 'IP', 'TCP', 'NBT Session Packet', 'SMBNegociate Protocol Request Header', 'SMB Negociate Protocol Request Tail'],
			['Ethernet', 'IP', 'TCP', 'NBT Session Packet', 'SMBNegociate Protocol Request Header', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail'],
			['Ethernet', 'IP', 'TCP', 'NBT Session Packet', 'SMBNegociate Protocol Request Header', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail'],
			['Ethernet', 'IP', 'TCP', 'NBT Session Packet', 'SMBNegociate Protocol Request Header', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail'],
			['Ethernet', 'IP', 'TCP', 'NBT Session Packet', 'SMBNegociate Protocol Request Header', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail'],
			['Ethernet', 'IP', 'TCP', 'NBT Session Packet', 'SMBNegociate Protocol Request Header', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail'],
			['Ethernet', 'IP', 'TCP', 'NBT Session Packet', 'SMBNegociate Protocol Request Header', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail'],
			['Ethernet', 'IP', 'TCP', 'NBT Session Packet', 'SMBNegociate Protocol Request Header', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail', 'SMB Negociate Protocol Request Tail'],
			['Ethernet', 'IP', 'TCP', 'Padding'],
			['Ethernet', 'IP', 'TCP', 'Raw'],
			['Ethernet', 'IP', 'TCP', 'Raw', 'Padding'],
			['Ethernet', 'IP', 'TCP', 'Skinny', 'Raw'],

			['Ethernet', 'IP', 'UDP', 'BOOTP', 'DHCP options'],
			['Ethernet', 'IP', 'UDP', 'BOOTP', 'DHCP options', 'Padding'],
			['Ethernet', 'IP', 'UDP', 'Control message', 'Padding'],
#DNSRR for question record, but not a formal layer, it appears
			['Ethernet', 'IP', 'UDP', 'DNS'],
			['Ethernet', 'IP', 'UDP', 'DNS', 'Padding'],
			['Ethernet', 'IP', 'UDP', 'DNS', 'Raw'],
			['Ethernet', 'IP', 'UDP', 'DNS', 'Raw', 'Padding'],
			['Ethernet', 'IP', 'UDP', 'ESP'],
			['Ethernet', 'IP', 'UDP', 'HSRP', 'HSRP MD5 Authentication', 'Raw'],
			['Ethernet', 'IP', 'UDP', 'HSRP', 'Padding'],
			['Ethernet', 'IP', 'UDP', 'ISAKMP', 'ISAKMP SA'],
			['Ethernet', 'IP', 'UDP', 'ISAKMP', 'ISAKMP SA', 'Padding'],
			['Ethernet', 'IP', 'UDP', 'ISAKMP', 'Raw'],
			['Ethernet', 'IP', 'UDP', 'Link Local Multicast Node Resolution - Query'],
			['Ethernet', 'IP', 'UDP', 'NBNS query request'],
			['Ethernet', 'IP', 'UDP', 'NBNS query request', 'Padding'],
			['Ethernet', 'IP', 'UDP', 'NBNS query request', 'Raw'],
			['Ethernet', 'IP', 'UDP', 'NBNS query response'],
			['Ethernet', 'IP', 'UDP', 'NBNS query response', 'Raw'],
			['Ethernet', 'IP', 'UDP', 'NBT Datagram Packet', 'Raw'],
			['Ethernet', 'IP', 'UDP', 'NTPHeader'],
			['Ethernet', 'IP', 'UDP', 'NTPHeader', 'Padding'],
			['Ethernet', 'IP', 'UDP', 'NTPHeader', 'NTPv4 extensions'],
			['Ethernet', 'IP', 'UDP', 'NTPHeader', 'Authenticator'],
			['Ethernet', 'IP', 'UDP', 'NTPHeader', 'Raw'],
			['Ethernet', 'IP', 'UDP', 'Padding'],
			['Ethernet', 'IP', 'UDP', 'Private (mode 7)', 'Padding'],
			['Ethernet', 'IP', 'UDP', 'Private (mode 7)', 'Raw'],
			['Ethernet', 'IP', 'UDP', 'Private (mode 7)', 'Raw', 'Padding'],
			['Ethernet', 'IP', 'UDP', 'Radius', 'Padding'],
			['Ethernet', 'IP', 'UDP', 'RIP header', 'Padding'],
			['Ethernet', 'IP', 'UDP', 'RIP header', 'RIP entry'],
			['Ethernet', 'IP', 'UDP', 'RIP header', 'RIP entry', 'Padding'],
			['Ethernet', 'IP', 'UDP', 'RIP header', 'RIP entry', 'Raw'],
			['Ethernet', 'IP', 'UDP', 'Radius'],
			['Ethernet', 'IP', 'UDP', 'Raw'],
			['Ethernet', 'IP', 'UDP', 'Raw', 'Padding'],
			['Ethernet', 'IP', 'UDP', 'SNMP'],
			['Ethernet', 'IP', 'UDP', 'SNMP', 'Padding'],
			['Ethernet', 'IP', 'UDP', 'SNMP', 'Raw'],
			['Ethernet', 'IP', 'UDP', 'TFTP opcode', 'Raw', 'Padding'],
			['Ethernet', 'IP', 'UDP', 'TFTP opcode', 'TFTP Read Request', 'Padding'],

			['Ethernet', 'IP', 'VRRP'],
			['Ethernet', 'IP', 'VRRP', 'Padding'],

			['Ethernet', 'IPv6', 'ICMPv6 Destination Unreachable', 'IPv6 in ICMPv6', 'TCP in ICMP'],
			['Ethernet', 'IPv6', 'ICMPv6 Destination Unreachable', 'IPv6 in ICMPv6', 'UDP in ICMP', 'DNS'],
			['Ethernet', 'IPv6', 'ICMPv6 Destination Unreachable', 'IPv6 in ICMPv6', 'UDP in ICMP', 'Raw'],

			['Ethernet', 'IPv6', 'ICMPv6 Echo Reply'],
			['Ethernet', 'IPv6', 'ICMPv6 Echo Request'],

			['Ethernet', 'IPv6', 'ICMPv6 Neighbor Discovery - Neighbor Advertisement'],
			['Ethernet', 'IPv6', 'ICMPv6 Neighbor Discovery - Neighbor Advertisement', 'ICMPv6 Neighbor Discovery Option - Destination Link-Layer Address'],
			['Ethernet', 'IPv6', 'ICMPv6 Neighbor Discovery - Neighbor Solicitation'],
			['Ethernet', 'IPv6', 'ICMPv6 Neighbor Discovery - Neighbor Solicitation', 'ICMPv6 Neighbor Discovery Option - Source Link-Layer Address'],
			['Ethernet', 'IPv6', 'ICMPv6 Neighbor Discovery - Neighbor Solicitation', 'Raw'],
			['Ethernet', 'IPv6', 'ICMPv6 Neighbor Discovery - Router Advertisement', 'ICMPv6 Neighbor Discovery Option - MTU', 'ICMPv6 Neighbor Discovery Option - Source Link-Layer Address'],
			['Ethernet', 'IPv6', 'ICMPv6 Neighbor Discovery - Router Advertisement', 'ICMPv6 Neighbor Discovery Option - Prefix Information'],
			['Ethernet', 'IPv6', 'ICMPv6 Neighbor Discovery - Router Advertisement', 'ICMPv6 Neighbor Discovery Option - Recursive DNS Server Option', 'ICMPv6 Neighbor Discovery Option - Prefix Information', 'ICMPv6 Neighbor Discovery Option - Route Information Option', 'ICMPv6 Neighbor Discovery Option - Source Link-Layer Address'],
			['Ethernet', 'IPv6', 'ICMPv6 Neighbor Discovery - Router Advertisement', 'ICMPv6 Neighbor Discovery Option - Recursive DNS Server Option', 'ICMPv6 Neighbor Discovery Option - Prefix Information', 'ICMPv6 Neighbor Discovery Option - Source Link-Layer Address'],
			['Ethernet', 'IPv6', 'ICMPv6 Neighbor Discovery - Router Advertisement', 'ICMPv6 Neighbor Discovery Option - Source Link-Layer Address'],
			['Ethernet', 'IPv6', 'ICMPv6 Neighbor Discovery - Router Advertisement', 'ICMPv6 Neighbor Discovery Option - Source Link-Layer Address', 'ICMPv6 Neighbor Discovery Option - MTU', 'ICMPv6 Neighbor Discovery Option - Prefix Information'],
			['Ethernet', 'IPv6', 'ICMPv6 Neighbor Discovery - Router Advertisement', 'ICMPv6 Neighbor Discovery Option - Source Link-Layer Address', 'ICMPv6 Neighbor Discovery Option - Prefix Information'],
			['Ethernet', 'IPv6', 'ICMPv6 Neighbor Discovery - Router Solicitation'],
			['Ethernet', 'IPv6', 'ICMPv6 Neighbor Discovery - Router Solicitation', 'ICMPv6 Neighbor Discovery Option - Source Link-Layer Address'],

			['Ethernet', 'IPv6', 'ICMPv6 Packet Too Big', 'IPv6 in ICMPv6', 'TCP in ICMP', 'Raw'],

			['Ethernet', 'IPv6', 'ICMPv6 Time Exceeded', 'IPv6 in ICMPv6', 'UDP in ICMP', 'DNS'],

			['Ethernet', 'IPv6', 'IPv6 Extension Header - Fragmentation header', 'TCP', 'Raw'],
			['Ethernet', 'IPv6', 'IPv6 Extension Header - Fragmentation header', 'UDP', 'Raw'],
			['Ethernet', 'IPv6', 'IPv6 Extension Header - Fragmentation header', 'UDP', 'Raw', 'Padding'],
			['Ethernet', 'IPv6', 'IPv6 Extension Header - Hop-by-Hop Options Header', 'ICMPv6 Neighbor Discovery - Neighbor Advertisement', 'ICMPv6 Neighbor Discovery Option - Destination Link-Layer Address'],
			['Ethernet', 'IPv6', 'IPv6 Extension Header - Hop-by-Hop Options Header', 'ICMPv6 Neighbor Discovery - Neighbor Solicitation'],
			['Ethernet', 'IPv6', 'IPv6 Extension Header - Hop-by-Hop Options Header', 'MLD - Multicast Listener Done'],
			['Ethernet', 'IPv6', 'IPv6 Extension Header - Hop-by-Hop Options Header', 'MLD - Multicast Listener Query'],
			['Ethernet', 'IPv6', 'IPv6 Extension Header - Hop-by-Hop Options Header', 'MLD - Multicast Listener Report'],
			['Ethernet', 'IPv6', 'IPv6 Extension Header - Hop-by-Hop Options Header', 'Raw'],

			['Ethernet', 'IPv6', 'Padding'],
			['Ethernet', 'IPv6', 'Raw'],
			['Ethernet', 'IPv6', 'TCP'],
			['Ethernet', 'IPv6', 'TCP', 'Raw'],

			['Ethernet', 'IPv6', 'UDP', 'DHCPv6 Confirm Message', 'DHCP6 Client Identifier Option', 'DHCP6 Option Request Option', 'DHCP6 Elapsed Time Option', 'DHCP6 Identity Association for Non-temporary Addresses Option'],
			['Ethernet', 'IPv6', 'UDP', 'DHCPv6 Request Message', 'DHCP6 Client Identifier Option', 'DHCP6 Option Request Option', 'DHCP6 Elapsed Time Option', 'DHCP6 Server Identifier Option', 'DHCP6 Identity Association for Non-temporary Addresses Option'],
# p[DHCP6OptClientFQDN].fqdn is an fqdn
			['Ethernet', 'IPv6', 'UDP', 'DHCPv6 Solicit Message', 'DHCP6 Client Identifier Option', 'DHCP6 Option Request Option', 'DHCP6 Elapsed Time Option', 'DHCP6 Rapid Commit Option', 'DHCP6 Option - Client FQDN', 'DHCP6 Identity Association for Non-temporary Addresses Option'],
			['Ethernet', 'IPv6', 'UDP', 'DHCPv6 Solicit Message', 'DHCP6 Client Identifier Option', 'DHCP6 Option Request Option', 'DHCP6 Elapsed Time Option', 'DHCP6 Identity Association for Non-temporary Addresses Option'],
			['Ethernet', 'IPv6', 'UDP', 'DHCPv6 Solicit Message', 'DHCP6 Elapsed Time Option', 'DHCP6 Client Identifier Option', 'DHCP6 Identity Association for Non-temporary Addresses Option', 'DHCP6 Option - Client FQDN', 'DHCP6 Vendor Class Option', 'DHCP6 Option Request Option'],
			['Ethernet', 'IPv6', 'UDP', 'DHCPv6 Solicit Message', 'DHCP6 Elapsed Time Option', 'DHCP6 Client Identifier Option', 'DHCP6 Identity Association for Non-temporary Addresses Option', 'DHCP6 Option Request Option', 'DHCP6 Option - Client FQDN'],
			['Ethernet', 'IPv6', 'UDP', 'DNS'],
			['Ethernet', 'IPv6', 'UDP', 'DNS', 'Raw'],
			['Ethernet', 'IPv6', 'UDP', 'Link Local Multicast Node Resolution - Query'],
			['Ethernet', 'IPv6', 'UDP', 'NTPHeader'],
			['Ethernet', 'IPv6', 'UDP', 'Raw'],

			['Ethernet', 'Raw'],

			['IP', 'ICMP', 'Raw'],
			['IP', 'Raw'],
			['IP', 'TCP'],
			['IP', 'TCP', 'Raw'],
			['IP', 'UDP'],
			['IP', 'UDP', 'BOOTP', 'DHCP options'],
			['IP', 'UDP', 'DNS'],
			['IP', 'UDP', 'DNS', 'Raw'],
			['IP', 'UDP', 'ISAKMP', 'ISAKMP SA'],
			['IP', 'UDP', 'NBNS query request'],
			['IP', 'UDP', 'NTPHeader'],
			['IP', 'UDP', 'Private (mode 7)'],
			['IP', 'UDP', 'Private (mode 7)', 'Raw'],
			['IP', 'UDP', 'RIP header', 'RIP entry'],
			['IP', 'UDP', 'Raw'],
			['IP', 'UDP', 'SNMP'],
			['IP', 'UDP', 'TFTP opcode', 'TFTP Read Request'],
			['Raw']
		    ]

#Following converts the label (readable string returned by ReturnLayers) to key (the string needed to find the actual layer in a packet.
#For example layer_label_to_key['Private (mode 7)' is 'NTPPrivate'
layer_label_to_key = {'802.1Q': 'Dot1Q', '802.3': 'Dot3',
                      'AH': 'AH', 'ARP': 'ARP', 'Authenticator': 'NTPAuthenticator',
                      'BOOTP': 'BOOTP',
                      'Control message': 'NTPControl',
                      'DHCP options': 'DHCP', 'DHCP6 Client Identifier Option': 'DHCP6OptClientId', 'DHCP6 Elapsed Time Option': 'DHCP6OptElapsedTime',
                      'DHCP6 Identity Association for Non-temporary Addresses Option': 'DHCP6OptIA_NA', 'DHCP6 Option - Client FQDN': 'DHCP6OptClientFQDN',
                      'DHCP6 Option Request Option': 'DHCP6OptOptReq', 'DHCP6 Rapid Commit Option': 'DHCP6OptRapidCommit',
                      'DHCP6 Server Identifier Option': 'DHCP6OptServerId', 'DHCPv6 Solicit Message': 'DHCP6_Solicit', 'DHCP6 Vendor Class Option': 'DHCP6OptVendorClass',
                      'DHCPv6 Confirm Message': 'DHCP6_Confirm', 'DHCPv6 Request Message': 'DHCP6_Request', 'DNS': 'DNS',
                      'EAPOL': 'EAPOL', 'ESP': 'ESP', 'Ethernet': 'Ethernet',
                      'GRE': 'GRE',
                      'HSRP': 'HSRP', 'HSRP MD5 Authentication': 'HSRPmd5',
                      'ICMP': 'ICMP', 'ICMP in ICMP': 'ICMPerror', 'ICMPv6 Destination Unreachable': 'ICMPv6DestUnreach', 'ICMPv6 Echo Reply': 'ICMPv6EchoReply', 'ICMPv6 Echo Request': 'ICMPv6EchoRequest',
                      'ICMPv6 Neighbor Discovery - Neighbor Advertisement': 'ICMPv6ND_NA',
                      'ICMPv6 Neighbor Discovery - Neighbor Solicitation': 'ICMPv6ND_NS',
                      'ICMPv6 Neighbor Discovery - Router Advertisement': 'ICMPv6ND_RA',
                      'ICMPv6 Neighbor Discovery - Router Solicitation': 'ICMPv6ND_RS',
                      'ICMPv6 Neighbor Discovery Option - Destination Link-Layer Address': 'ICMPv6NDOptDstLLAddr',
                      'ICMPv6 Neighbor Discovery Option - MTU': 'ICMPv6NDOptMTU',
                      'ICMPv6 Neighbor Discovery Option - Prefix Information': 'ICMPv6NDOptPrefixInfo',
                      'ICMPv6 Neighbor Discovery Option - Recursive DNS Server Option': 'ICMPv6NDOptRDNSS',
                      'ICMPv6 Neighbor Discovery Option - Route Information Option': 'ICMPv6NDOptRouteInfo',
                      'ICMPv6 Neighbor Discovery Option - Source Link-Layer Address': 'ICMPv6NDOptSrcLLAddr',
                      'ICMPv6 Packet Too Big': 'ICMPv6PacketTooBig', 'ICMPv6 Time Exceeded': 'ICMPv6TimeExceeded',
                      'IP': 'IP', 'IP in ICMP': 'IPerror', 'IPv6': 'IPv6', 'IPv6 Extension Header - Fragmentation header': 'IPv6ExtHdrFragment',
                      'IPv6 Extension Header - Hop-by-Hop Options Header': 'IPv6ExtHdrHopByHop', 'IPv6 in ICMPv6': 'IPerror6',
                      'ISAKMP': 'ISAKMP', 'ISAKMP SA': 'ISAKMP_payload_SA',
                      'LLC': 'LLC', 'Link Local Multicast Node Resolution - Query': 'LLMNRQuery',
                      'MLD - Multicast Listener Done': 'ICMPv6MLDone', 'MLD - Multicast Listener Query': 'ICMPv6MLQuery', 'MLD - Multicast Listener Report': 'ICMPv6MLReport',
                      'NBNS query request': 'NBNSQueryRequest', 'NBNS query response': 'NBNSQueryResponse', 'NBT Datagram Packet': 'NBTDatagram',
                      'NBT Session Packet': 'NBTSession', 'NTPHeader': 'NTPHeader', 'NTPv4 extensions': 'NTPExtensions', 'Padding': 'Padding',
                      'Private (mode 7)': 'NTPPrivate', 'Radius': 'Radius', 'RIP entry': 'RIPEntry', 'RIP header': 'RIP', 'Raw': 'Raw',
                      'SMBNegociate Protocol Request Header': 'SMBNegociate_Protocol_Request_Header', 'SMB Negociate Protocol Request Tail': 'SMBNegociate_Protocol_Request_Tail', 'SNAP': 'SNAP', 'SNMP': 'SNMP',
                      'Skinny': 'Skinny', 'Spanning Tree Protocol': 'STP',
                      'TCP': 'TCP', 'TCP in ICMP': 'TCPError', 'TFTP opcode': 'TFTP', 'TFTP Read Request': 'TFTP_RRQ',
                      'UDP': 'UDP', 'UDP in ICMP': 'UDPerror',
                      'VRRP': 'VRRP',
                      'cooked linux': 'CookedLinux'}
#===============================================================================================

phys_layers = set(['802.1Q', 'Ethernet', 'cooked linux'])
addr_layers = set(['IP', 'IPv6', 'IPv6 Extension Header - Fragmentation header', 'IPv6 Extension Header - Hop-by-Hop Options Header'])
task_layers = set(['BOOTP', 'Control message', 'DHCP options', 'DNS', 'GRE', 'HSRP', 'HSRP MD5 Authentication', 'ICMP', 'ICMPv6 Destination Unreachable', 'ICMPv6 Neighbor Discovery - Neighbor Solicitation', 'IP', 'IP in ICMP', 'ICMP in ICMP', 'ICMPv6 Packet Too Big', 'IPv6 in ICMPv6', 'ISAKMP', 'ISAKMP SA', 'NBNS query request', 'NBNS query response', 'NBT Datagram Packet', 'NTPHeader', 'Private (mode 7)', 'Radius', 'RIP header', 'RIP entry', 'Skinny', 'TCP', 'TCP in ICMP', 'TFTP opcode', 'TFTP Read Request', 'UDP', 'UDP in ICMP', 'SNMP', 'VRRP'])
trailer_layers = set(['Raw', 'Padding'])
special_layers = set(['802.1Q', '802.3', 'ARP', 'EAPOL', 'Ethernet', 'LLC', 'Padding', 'Raw', 'SNAP', 'Spanning Tree Protocol'])

meta = {}		#Empty dictionary - not used in this version of passer, but will be used in the next.  Fills the open space in the ShowPacket function call.

passerVersion = "2.89"


#======== Functions ========



def layer_slice(layer_l):
	"""Break a list of layers into physical, address, task, trailer, special and unknown components.  Either the first 4 will be lists
	which, when concatenated will return the original list (and unknown will be []), special will contain a the original list (and the
	rest will be []), or the first 5 will be [] and the original list will be in unknown."""

	phys_l = []
	addr_l = []
	task_l = []
	trailer_l = []
	special_l = []
	unknown_l = []
	split_ok = True

	if set(layer_l).issubset(special_layers):
		return [], [], [], [], layer_l, []

	addr_i = 0
	while addr_i < len(layer_l) and layer_l[addr_i] not in addr_layers:
		addr_i += 1

	if addr_i == len(layer_l):
		#No IP layer was found
		split_ok = False
		unknown_l = layer_l
	else:
		#IP layer was found at layer_l[addr_i]
		phys_l = layer_l[0:addr_i]
		addr_l = [layer_l[addr_i]]
		task_l = layer_l[addr_i+1:]

		while task_l and task_l[0] in addr_layers:
			#We have an additional address layer at the beginning of task - append it to addr_l
			addr_l.append(task_l[0])
			task_l = task_l[1:]

		while task_l and task_l[-1] in trailer_layers:
			#Move this junk layer to the beginning of trailer and strip from task_l.
			trailer_l.insert(0, task_l[-1])
			task_l = task_l[0:-1]
			split_ok = set(phys_l).issubset(phys_layers) and set(addr_l).issubset(addr_layers) and set(task_l).issubset(task_layers) and set(trailer_l).issubset(trailer_layers)

	if split_ok:
		return (phys_l, addr_l, task_l, trailer_l, [], [])
	else:
		return ([], [], [], [], [], layer_l)


#for X in known_layer_lists:
#	p, a, t, z, s, u = layer_slice(X)
#	if u:
#		print(str(u))
#	elif s:
#		print("Special: " + str(s))
#quit()


def signal_handler(sig, frame):
	"""_Should_ catch ctrl-C and allow graceful exit with a reporting feature on the way out.
	Unfortunately, the handler is executed in the main python thread, and most of the script
	is running inside sniff.  May have to set a flag here and exit sniff if flag set?"""
	#https://docs.python.org/3/library/signal.html
	#https://www.cybrary.it/0p3n/sniffing-inside-thread-scapy-python/ ?
	#For the moment we are _not_ stopping passer on ctrl-c.

	global must_stop

	if sig == signal.SIGINT:
		#sys.stderr.write("Ctrl-C pressed, exiting in a moment.\n")
		sys.stderr.write("Ctrl-C pressed, generating summary lines.\n")
		generate_summary_lines()
		must_stop = True
		#sys.exit(1)
	else:
		sys.stderr.write("Unhandled signal type: " + str(sig) + "\n")


def exit_now():
	"""Returns true if exit was requested.  Checks global must_stop, which is set in signal_handler."""

	sys.stderr.write("exit_now called")

	return must_stop


def exit_now_packet_param(one_packet_param):
	"""Returns true if exit was requested.  Checks global must_stop, which is set in signal_handler.  Packet handed to us is ignored."""

	sys.stderr.write("exit_now_packet_param called")

	return must_stop


def generate_summary_lines():
	"""Print any remaining lines, generally ones that are stored but not a direct result of a packet."""

	#Because this is called with no apparent way to hand down params other than the raw packet, we have to pull these two from main by hand.
	prefs = cl_args
	dests = destinations

	#These come first because they may add 'scan' to the suspicious characteristics list for one or more IPs, which will be printed by the next loop.

#FIXME
	if "ClosedUDPPortsReceived" in processpacket.__dict__:											#Cross-function variable
		for an_ip in sorted(processpacket.ClosedUDPPortsReceived):
			if len(processpacket.ClosedUDPPortsReceived[an_ip]) >= min_closed_ports_for_scanner:
				ReportId("IP", an_ip, "IP", "suspicious", 'Scanned ' + str(len(processpacket.ClosedUDPPortsReceived[an_ip])) + ' UDP closed ports.', (['scan', ]), prefs, dests)

#FIXME
	#if "ClosedTCPPortsReceived" in processpacket.__dict__:											#Cross-function variable
	#	for an_ip in sorted(processpacket.ClosedTCPPortsReceived):
	#		if len(processpacket.ClosedTCPPortsReceived[an_ip]) >= min_closed_ports_for_scanner:
	#			ReportId("IP", an_ip, "IP", "suspicious", 'Scanned ' + str(len(processpacket.ClosedTCPPortsReceived[an_ip])) + ' TCP closed ports.', (['scan', ]), prefs, dests)

	for an_ip in sorted(ReportId.NewSuspiciousIPs):												#Cross-function variable
		ReportId("IP", an_ip, "IP", "suspicious", 'Warnings:' + ':'.join(ReportId.NewSuspiciousIPs[an_ip]), ([]), prefs, dests)		#Cross-function variable

	return


def remove_control_characters(s):
	"""Strip out any control characters in the string."""

	return "".join(ch for ch in unicode(s) if unicodedata.category(ch)[0] != "C")


def packet_timestamps(pt_p):
	"""This returns the timestamp in (floating point) seconds-since-the-epoch and (string) UTC human readable formats."""
	#Add , prefs, dests to params if any debug_out statements needed

	p_timestamp = pt_p.time					#packet.time can be read from an existing packet or written to a created packet.
	p_seconds_since_epoch = float(time.mktime(datetime.fromtimestamp(p_timestamp).timetuple()))
	#debug_out(str(p_seconds_since_epoch), prefs, dests)

	p_human_readable_utc = datetime.fromtimestamp(p_seconds_since_epoch, tz=pytz.utc).strftime('%Y-%m-%d %H:%M:%S')	#This shows UTC
	#debug_out(p_human_readable, prefs, dests)

	#Not used at the moment.
	#p_human_readable_localtz = datetime.fromtimestamp(p_timestamp).strftime('%Y-%m-%d %H:%M:%S')
	#debug_out(p_human_readable_localtz, prefs, dests)	#This is the human readable timestamp in local time

	return (p_seconds_since_epoch, p_human_readable_utc)


##FIXME - remove this function
#def LogNewPayload(PayloadDir, PayloadFile, Payload):
#	"""Saves the payload from an ack packet to a file named after the server or client port involved."""
#
#	#Better yet, wrpcap("/path/to/pcap", list_of_packets)
#
#	if prefs['devel']:
#		if os.path.isdir(PayloadDir):
#			if not Payload == b'None':
#				pfile = open(PayloadFile, 'a')
#				pfile.write(Payload)
#				pfile.close()


def write_object(filename, generic_object):
	"""Write out an object to a file."""

	try:
		with open(filename, "wb") as write_h:
			write_h.write(generic_object.encode('utf-8'))
	except:
		sys.stderr.write("Problem writing " + filename + ", skipping.")
		raise

	return



#def mac_of_ipaddr(ipv6addr):
#	"""For a supplied IPv6 address in EUI-64 format, return the mac address of the system that's behind it.  For an address not in that format, return ''."""



#May be able to do this with just a dict.
#def bot_warnings(bw_ip, bw_proto, bw_port):
#	"""For the given IP, TCP/UDP, port trio, return any additional warnings if that machine may be part of a bot."""
#
#
#	bw_warnings = []
#
#
#	orig_text = ''
#
#	return




def ReportId(Type, CompressedIPAddr, Proto, State, Description, Warnings, prefs, dests):
	"""Print and log a new piece of network information."""

	#Can't use : for separator, IPv6, similarly '.' for ipv4
	#Can't use "/" because of filesystem
	#Don't want to use space because of filesystem
	#	Type,	IPAddr,	Proto		State			Optional description (may be empty)
	#	'IP',	IPaddr,	'IP',		dead or live,		p0f OS description
	#	'MA',	IPaddr, 'Ethernet',	MacAddr,		ManufDescription
	#	'TC',	IPaddr,	'TCP_'Port,	closed or open,		client description
	#	'TS',	IPaddr,	'TCP_'Port,	closed or listening,	server description
	#	'UC',	IPaddr,	'UDP_'Port,	open or closed,		udp client port description
	#	'US',	IPaddr,	'UDP_'Port,	open or closed,		udp server port description
	#	'DN',	IPaddr,	'A' or 'PTR',	hostname,		possible extra info
	#	'RO',	IPaddr, 'TTLEx',	router,			possible extra info
	#	'PC',	IPaddr, 'PROTO_'PNum	open,			protocol name
	#	'PS',	IPaddr, 'PROTO_'PNum	open,			protocol name

	#Persistent data structures - these are loaded at first entry into the function and persist for the life of the process.
	if "GenDesc" not in ReportId.__dict__:
		#Dictionary of Dictionaries of sets, replaces the specific dictionaries.  First key is 2 letter record type, second key is IP address, final value (a set) is what we have seen for that record type and IP.
		ReportId.GenDesc = {'DN': {}, 'IP': {}, 'MA': {}, 'NA': {}, 'PC': {}, 'PS': {}, 'RO': {}, 'TC': {}, 'TS': {}, 'UC': {}, 'US': {}}

	#Dictionary of lists.  Key is IP address, value is list which contains all this IP address' suspicious characteristics.
	if "SuspiciousIPs" not in ReportId.__dict__:
		ReportId.SuspiciousIPs = load_json_from_file(suspicious_ips_file)
		if ReportId.SuspiciousIPs:
			for one_trusted in __main__.TrustedIPs:
				if one_trusted in ReportId.SuspiciousIPs:
					del ReportId.SuspiciousIPs[one_trusted]
		else:
			debug_out("Problem reading/parsing " + suspicious_ips_file + ", skipping.", prefs, dests)
			ReportId.SuspiciousIPs = {}

	#Just like above, but _only_ the entries added during this session; used for printing with ctrl-c or at the end.
	if "NewSuspiciousIPs" not in ReportId.__dict__:
		ReportId.NewSuspiciousIPs = {}

	if "MacAddr" not in ReportId.__dict__:
		ReportId.MacAddr = {}			#String dictionary: For a given IP (key), what is its mac (value)?

	if "EtherManuf" not in ReportId.__dict__:
		ReportId.EtherManuf = {}			#String dictionary: for a given key of the first three uppercase octets of a mac address ("00:01:0F"), who made this card?

		ReportId.EtherManuf = MacDataDict(['/usr/share/ettercap/etter.finger.mac', '/opt/local/share/ettercap/etter.finger.mac', '/usr/share/nmap/nmap-mac-prefixes', '/opt/local/share/nmap/nmap-mac-prefixes', '/usr/share/wireshark/manuf', '/opt/local/share/wireshark/manuf', '/usr/share/ethereal/manuf', '/usr/share/arp-scan/ieee-oui.txt', '/opt/local/share/arp-scan/ieee-oui.txt'], prefs, dests)

		if len(ReportId.EtherManuf) == 0:
			debug_out("None of the default mac address listings found.  Please install ettercap, nmap, wireshark, and/or arp-scan.", cl_args, destinations)
		else:
			debug_out(str(len(ReportId.EtherManuf)) + " mac prefixes loaded.", cl_args, destinations)

	if "log_h" not in ReportId.__dict__:
		ReportId.log_h = None

		if prefs['log']:
			try:
				ReportId.log_h = open(prefs['log'], 'a')
			except:
				debug_out("Unable to append to " + prefs['log'] + ", no logging will be done.", cl_args, destinations)

	IPAddr = explode_ip(CompressedIPAddr, prefs, dests)

	Location = IPAddr + "," + Proto
	Description = Description.replace('\n', '').replace('\r', '').replace(',', ' ')

	if Warnings:		#Non-empty set of strings
		if Description:
			Description += ' '
		Description += 'Warnings:' + ':'.join(Warnings)

		if IPAddr in __main__.TrustedIPs:
			if Warnings == ['plaintext'] and Proto == 'UDP_514':
				pass
			elif Warnings == ['portpolicyviolation', ]:
				debug_out("Attempt to add trusted IP " + IPAddr + " to SuspiciousIPs because of portpolicyviolation.", prefs, dests)
			else:
				debug_out("Attempt to add trusted IP " + IPAddr + " to SuspiciousIPs.", prefs, dests)
				debug_out("Attempt to add trusted IP " + IPAddr + " to SuspiciousIPs." + '|' + str(Type) + '|' + str(Proto) + '|' + str(State) + '|' + str(Description) + '|' + str(Warnings), prefs, dests)
				#quit()
		elif 'spoofed' not in Warnings:
			#We have to add this warning to ReportId.SuspiciousIPs, the master list of _all_ warnings for all IPs....
			if IPAddr not in ReportId.SuspiciousIPs:
				ReportId.SuspiciousIPs[IPAddr] = []
			for one_warning in Warnings:
				if one_warning not in ReportId.SuspiciousIPs[IPAddr]:
					ReportId.SuspiciousIPs[IPAddr].append(one_warning)

			#....and we have to add it to ReportId.NewSuspiciousIPs, which only holds the new things we've discovered this session.
			if IPAddr not in ReportId.NewSuspiciousIPs:
				ReportId.NewSuspiciousIPs[IPAddr] = []
			for one_warning in Warnings:
				if one_warning not in ReportId.NewSuspiciousIPs[IPAddr]:
					ReportId.NewSuspiciousIPs[IPAddr].append(one_warning)


	ShouldPrint = True

	if Type not in ReportId.GenDesc:
		ReportId.GenDesc[Type] = {}

	if Type in ("TS", "US"):
		if Location not in ReportId.GenDesc[Type]:
			ReportId.GenDesc[Type][Location] = set()

		if State + ',' + Description in ReportId.GenDesc[Type][Location]:
			ShouldPrint = False			#Don't print if we've already printed it with this state + description
		else:
			ReportId.GenDesc[Type][Location].add(State + ',' + Description)
	elif Type in ("TC", "UC"):
		if Location not in ReportId.GenDesc[Type]:
			ReportId.GenDesc[Type][Location] = set()

		if State + ',' + Description in ReportId.GenDesc[Type][Location]:
			ShouldPrint = False			#Don't print if we've already printed it with this state + description
		else:
			ReportId.GenDesc[Type][Location].add(State + ',' + Description)
	elif Type in ("IP", "NA", "PC", "PS"):
		if Location not in ReportId.GenDesc[Type]:
			ReportId.GenDesc[Type][Location] = set()

		if State + ',' + Description in ReportId.GenDesc[Type][Location]:
			ShouldPrint = False			#Don't print if we've already printed it with this state + description
		else:
			ReportId.GenDesc[Type][Location].add(State + ',' + Description)
	elif Type == "DN":
		#Note that State will be the Hostname, and Proto is the Record type
		if Location not in ReportId.GenDesc[Type]:
			ReportId.GenDesc[Type][Location] = set()

		#FIXME - perhaps description could indicate low TTL?  <300?  <150?
		if Proto in ('A', 'AAAA', 'CNAME', 'PTR') and State == '':
			ShouldPrint = False
		elif State == '' and IPAddr in ('::', '0000:0000:0000:0000:0000:0000:0000:0000'):		#Not sure if this should be limited to hostnames with      and Proto in ('A', 'AAAA', 'CNAME', 'PTR')
			ShouldPrint = False
		elif State + ',' + Description in ReportId.GenDesc[Type][Location]:
			ShouldPrint = False
		else:
			ReportId.GenDesc[Type][Location].add(State + ',' + Description)		#Add this Hostname to the list
	elif Type == "RO":
		if Description == '':
			description_string = Proto		#This holds the type of packet that causes us to believe it's a router, like "RouterAdv"
		else:
			description_string = Description

		if IPAddr not in ReportId.GenDesc[Type]:			#If we ever need to test if an IP is a router, use IPAddr in ReportId.GenDesc['RO']
			ReportId.GenDesc[Type][IPAddr] = set()

		if description_string in ReportId.GenDesc[Type][IPAddr]:
			ShouldPrint = False			#Don't print if we've already printed it with this description
		else:
			ReportId.GenDesc[Type][IPAddr].add(description_string)
	elif Type == "MA":
		State = State.upper()
		if IPAddr in ('', '::', '0000:0000:0000:0000:0000:0000:0000:0000'):
			ShouldPrint = False			#Not registering :: as a null IP address
		elif (IPAddr in ReportId.MacAddr) and (ReportId.MacAddr[IPAddr] == State):
			ShouldPrint = False			#Already known, no need to reprint
		else:
			ReportId.MacAddr[IPAddr] = State
			if State[:8] in ReportId.EtherManuf:
				Description = ReportId.EtherManuf[State[:8]].replace(',', ' ')

	if ShouldPrint:
		try:
			OutString = Type + "," + IPAddr + "," + Proto + "," + State + "," + Description
			if prefs['timestamp']:
				OutString += ',' + str(processpacket.current_stamp) + ',' + processpacket.current_string
			#else:
			#	OutString += ',,'				#Future: When we're not showing the timestamps, still create the columns so logs line up
			print(OutString)
			if ReportId.log_h is not None:
				ReportId.log_h.write(OutString + '\n')
				ReportId.log_h.flush()
		except UnicodeDecodeError:
			pass


def ReportAll(output_tuple_set, prefs, dests):
	"""Wrapper function for original passer script used to accept a set of tuples generated by {LAYER}_extract functions and send them to ReportId.
	Example call: ReportAll(ARP_extract(p, meta)) ."""

	for a_tuple in output_tuple_set:
		ReportId(a_tuple[Type_e], a_tuple[IPAddr_e], a_tuple[Proto_e], a_tuple[State_e], a_tuple[Description_e], a_tuple[Warnings_e], prefs, dests)


def process_udp_ports(meta, p, prefs, dests):
	"""Process a UDP packet (ipv4 or ipv6)."""

	#Persistent variables
	#String dictionary: What server is on this "IP,Proto_Port"?  Locally found strings.
	if "UDPManualServerDescription" not in process_udp_ports.__dict__:
		process_udp_ports.UDPManualServerDescription = {}


	#Transition variables
	sIP = meta['sIP']
	dIP = meta['dIP']
	sport = meta['sport']
	dport = meta['dport']
	SrcService = meta['SrcService']
	DstService = meta['DstService']
	SrcClient = meta['SrcClient']
	FromPort = sIP + ",UDP_" + sport

	if p.getlayer(Raw):
		Payload = p.getlayer(Raw).load
	else:
		Payload = b""

	#Persistent variables
	if "SipPhoneMatch" not in process_udp_ports.__dict__:
		process_udp_ports.SipPhoneMatch = re.compile('Contact: ([0-9-]+) <sip')


	ReportAll(UDP_extract(p, meta, prefs, dests), prefs, dests)

	if dport in PolicyViolationUDPPorts:
		ReportId("UC", sIP, "UDP_" + dport, "open", '', (['portpolicyviolation', ]), prefs, dests)
	if sport in PolicyViolationUDPPorts:
		ReportId("US", sIP, "UDP_" + sport, "open", '', (['portpolicyviolation', ]), prefs, dests)

	if dport == "0":
		ReportId("UC", sIP, "UDP_" + dport, "open", 'Invalid destination port 0', (['noncompliant', ]), prefs, dests)
	if sport == "0":
		ReportId("US", sIP, "UDP_" + sport, "open", 'Invalid source port 0', (['noncompliant', ]), prefs, dests)
		process_udp_ports.UDPManualServerDescription[FromPort] = "Invalid source port 0"

	if dport == "0" and Payload == cacti_payload:
		ReportId("UC", sIP, "UDP_" + dport, "open", 'Cacti monitor', (['noncompliant', ]), prefs, dests)
### IP/UDP/qualys
	elif sIP in qualys_scan_ips and dport in qualys_udp_scan_port_names and Payload == nullbyte:
		ReportId("UC", sIP, "UDP_" + dport, "open", qualys_udp_scan_port_names[dport] + "/clientscanner qualys", (['scan', ]), prefs, dests)
	elif sIP in qualys_scan_ips:
		ReportId("UC", sIP, "UDP_" + dport, "open", "udp" + dport + "/clientscanner qualys unregistered port", (['scan', ]), prefs, dests)
	elif sIP.startswith(qualys_subnet_starts) and dport in qualys_udp_scan_port_names and Payload == nullbyte:
		ReportId("UC", sIP, "UDP_" + dport, "open", qualys_udp_scan_port_names[dport] + "/clientscanner qualys unregistered scanner IP address", (['scan', ]), prefs, dests)
	elif sIP.startswith(qualys_subnet_starts):
		ReportId("UC", sIP, "UDP_" + dport, "open", "udp" + dport + "/clientscanner qualys unregistered scanner IP address and unregistered port", (['scan', ]), prefs, dests)
#__ haslayer(DNS)
### IP/UDP/Multicast DNS, placed next to normal dns, out of numerical order
### IP/UDP/DNS=53
	elif p.haslayer(DNS) and (isinstance(p[DNS], DNS)):

		ReportAll(DNS_extract(p, meta, prefs, dests), prefs, dests)

	#FIXME - copy over to mdns and ipv6
	elif (sport == "5353") and (dport == "5353") and not p.haslayer(DNS):									#No dns layer for some reason
		UnhandledPacket(p, prefs, dests)
	elif (dport == "5353") and ((meta['ttl'] == 1) or (meta['ttl'] == 2) or (meta['ttl'] == 255)):		#2 may not be rfc-legal, but I'm seeing it on the wire.
		if dIP in ("224.0.0.251", "ff02::fb", "ff02:0000:0000:0000:0000:0000:0000:00fb"):
			ReportId("UC", sIP, "UDP_" + dport, "open", "mdns/broadcastclient", ([]), prefs, dests)
		else:
			ReportId("UC", sIP, "UDP_" + dport, "open", "mdns/client", ([]), prefs, dests)


	#FIXME - add check for "if isinstance(p[DNS],  whatevertype):	here and at all p[] accesses.
	elif (sport != "53") and (dport == "53") and not p.haslayer(DNS):						#non-dns coming in from what looks like a DNS client.
		UnhandledPacket(p, prefs, dests)
### IP/UDPv4/bootp_dhcp=67
	elif meta['ip_class'] == '4' and (sport == "67") and (dport == "68"):		#Bootp/dhcp server talking to client
		ReportId("US", sIP, "UDP_" + sport, "open", "bootpordhcp/server", ([]), prefs, dests)
		process_udp_ports.UDPManualServerDescription[FromPort] = "bootpordhcp/server"
	elif meta['ip_class'] == '4' and (sport == "68") and (dport == "67"):		#Bootp/dhcp client talking to server
		#FIXME - pull ID field out as a name to report
		if sIP != "0.0.0.0":				#If the client is simply renewing an IP, remember it.
			ReportId("UC", sIP, "UDP_" + dport, "open", "bootpordhcp/client", ([]), prefs, dests)
			for one_opt in p[DHCP].options:				#Can't directly access p.haslayer(DHCPOptions) because it's a list of tuples.  https://stackoverflow.com/questions/22152130/how-can-i-get-option-number-from-an-dhcp-header-in-scapy
				if one_opt[0] == 'hostname':
					ReportId("NA", sIP, "DHCP", one_opt[1].decode('UTF-8'), "dhcp", ([]), prefs, dests)
		#else:						#If you want to record which macs are asking for addresses, do it here.
		#	pass

#__ haslayer(TFTP)
### IP/UDP/TFTP=69
	elif p.haslayer(TFTP):
		if dport == "69":
			ReportId("UC", sIP, "UDP_" + dport, "open", 'tftp/client', (['plaintext', 'portpolicyviolation', ]), prefs, dests)
		elif sport == "69":
			ReportId("US", sIP, "UDP_" + sport, "open", 'tftp/server', (['plaintext', 'portpolicyviolation', ]), prefs, dests)
			process_udp_ports.UDPManualServerDescription[FromPort] = "tftp/server"
		else:
			ShowPacket(p, meta, "IP/UDP/unhandled packet with TFTP layer", HonorQuit, prefs, dests)

### IP/UDP/udp_http=80 nmap quic scan
	elif (dport == "80") and (Payload == b'\r12345678Q999' + nullbyte):
		ReportId("UC", sIP, "UDP_" + dport, "open", "udp-http/client nmap QUIC scan", (['scan', ]), prefs, dests)
### IP/UDP/udp_http=80 with empty payload
	elif (dport == "80") and ((Payload is None) or (Payload == b'')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "null-udp-http/client", ([]), prefs, dests)
### IP/UDP/udp_http=80 with torrent current connection id payload		https://gist.github.com/xboston/6130535
	elif (dport == "80") and Payload and (Payload.startswith(torrent_connection_id)):
		ReportId("UC", sIP, "UDP_" + dport, "open", "udp-http/client torrent current connection id", ([]), prefs, dests)
### IP/UDP/udp_http=80
	elif sport == "80":							#udp http response
		ReportId("US", sIP, "UDP_" + sport, "open", "udp-http/server", ([]), prefs, dests)				#'portonlysignature'
		process_udp_ports.UDPManualServerDescription[FromPort] = "udp-http/server"
	elif dport == "80":							#udp http request
		ReportId("UC", sIP, "UDP_" + dport, "open", "udp-http/client", ([]), prefs, dests)				#'portonlysignature'
### IP/UDP/ntp=123
	elif dport == "123" and Payload.startswith(ntp_get_monlist):		#https://www.micron21.com/blog/2014/03/mechanics-of-ntp-ddos/ http://www.korznikov.com/2014/08/amplified-denial-of-service-with.html
		ReportId("UC", sIP, "UDP_" + dport, "open", 'ntp/client REQ_MON_GETLIST_1: Likely spoofed and DDOSed source IP', (['amplification', 'spoofed', 'dos']), prefs, dests)
	elif (dport == "123") and dIP in vonage_ntp:
		ReportId("UC", sIP, "UDP_" + dport, "open", "ntp/vonageclient", ([]), prefs, dests)
	elif (sport == "123") and sIP in vonage_ntp:
		ReportId("US", sIP, "UDP_" + sport, "open", "ntp/vonageserver", ([]), prefs, dests)
		process_udp_ports.UDPManualServerDescription[FromPort] = "ntp/vonageserver"

#__ haslayer(NTPHeader)
	elif has_advanced_ntp_headers and p.haslayer(NTPHeader):
		if sport != "123" and dport == "123" and str(p.getlayer(NTPHeader)).find('>/dev/null 2>&1\nchmod 777') > -1:
			ReportId("UC", sIP, "UDP_" + dport, "open", "udp123/client sending shellcode", (['malicious', ]), prefs, dests)
		elif (sport == "123") or (dport == "123"):
			ntp_stratum = p[NTPHeader].stratum
			#What comes back in the "id" field is either an IPv4 address of sIP's primary reference (good!) or
			#the first 4 bytes of the MD5 hash of the IPv6 address of sIP's primary reference (bad.)  Without actively
			#checking, there's no way to distinguish the two cases.  https://www.nwtime.org/ntps-refid/
			ntp_id = p[NTPHeader].id
			ntp_ref_id = str(p[NTPHeader].ref_id).rstrip(' \t\r\n\0')
			if ntp_id:
				ReportId("US", sIP, "UDP_" + sport, "open", 'ntp/server stratum=' + str(ntp_stratum) + ' reference=' + str(ntp_id), ([]), prefs, dests)
				process_udp_ports.UDPManualServerDescription[FromPort] = 'ntp/server stratum=' + str(ntp_stratum) + ' reference=' + str(ntp_id)
				ReportId("US", ntp_id, "UDP_" + sport, "open", 'ntp/server inferred from being a reference but must be checked.', ([]), prefs, dests)
				process_udp_ports.UDPManualServerDescription[ntp_id + ",UDP_" + sport] = 'ntp/server inferred from being a reference but must be checked.'
			elif ntp_ref_id in known_ntp_refs:
				ReportId("US", sIP, "UDP_" + sport, "open", 'ntp/server stratum=' + str(ntp_stratum), ([]), prefs, dests)
				process_udp_ports.UDPManualServerDescription[FromPort] = 'ntp/server stratum=' + str(ntp_stratum)
			else:
				ReportId("US", sIP, "UDP_" + sport, "open", 'ntp/server stratum=' + str(ntp_stratum), ([]), prefs, dests)
				process_udp_ports.UDPManualServerDescription[FromPort] = 'ntp/server stratum=' + str(ntp_stratum)
				#ShowPacket(p, meta, "IP/UDP/ntp with null reference:_" + str(ntp_ref_id) + "_", HonorQuit, prefs, dests)				#Even after adding 'i' to known_ntp_refs, this still kept tripping.
		else:
			ShowPacket(p, meta, "IP/UDP/unhandled packet with NTPHeader layer", HonorQuit, prefs, dests)

#__ haslayer(NTPPrivate)
	elif has_advanced_ntp_headers and p.haslayer(NTPPrivate):
		if (dport == "123") and p[NTPPrivate].response == 0:				#response == 0 is a request
			if p[NTPPrivate].request_code == 42:					#REQ_MON_GETLIST_1
				ReportId("UC", sIP, "UDP_123", "open", 'ntp/client REQ_MON_GETLIST_1: Likely spoofed and DDOSed source IP', (['amplification', 'spoofed']), prefs, dests)
			elif p[NTPPrivate].request_code == 32:					#REQ_REQUEST_KEY
				ReportId("UC", sIP, "UDP_123", "open", 'ntp/client', ([]), prefs, dests)
			else:
				ShowPacket(p, meta, "IPv4/UDPv4/ntp Mode 7 request but not REQ_MON_GETLIST_1", HonorQuit, prefs, dests)
		elif (sport == "123") and p[NTPPrivate].response == 1:					#response == 1 is a reply
			if p[NTPPrivate].request_code == 42:						#REQ_MON_GETLIST_1
				ReportId("US", sIP, "UDP_123", "open", 'ntp/server REQ_MON_GETLIST_1: Likely middleman in DDOS', (['amplification', 'dos']), prefs, dests)
				process_udp_ports.UDPManualServerDescription[FromPort] = 'ntp/server REQ_MON_GETLIST_1: Likely middleman in DDOS'
			else:
				ShowPacket(p, meta, "IPv4/UDPv4/ntp Mode 7 reply but not REQ_MON_GETLIST_1", HonorQuit, prefs, dests)
		else:
			ShowPacket(p, meta, "IP/UDP/unhandled packet with NTPPrivate layer", HonorQuit, prefs, dests)

#__ haslayer(NTPControl)
	elif has_advanced_ntp_headers and p.haslayer(NTPControl):
		if dport == "123":
			ReportId("UC", sIP, "UDP_123", "open", 'ntp_control/client', ([]), prefs, dests)
		else:
			ShowPacket(p, meta, "IP/UDP/unhandled packet with NTPControl layer", HonorQuit, prefs, dests)

	elif (not has_advanced_ntp_headers) and ((sport == "123") or (dport == "123")):
		UnhandledPacket(p, prefs, dests)							#Unfortunately, this version of scapy is too old to handle the new NTP headers.
### IP/UDP/pwdgen=129		https://tools.ietf.org/html/rfc972
	elif (dport == "129") and (Payload == b'\n'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "pwdgen/client", ([]), prefs, dests)
### IP/UDP/135
	elif sIP.startswith('64.39.99.') and dport == "135" and Payload.endswith(b'QUALYSGUARD123'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "epmap/clientscanner", (['scan', ]), prefs, dests)
	elif dport == "135" and Payload.find(b'NTLMSSP') > -1:
		ReportId("UC", sIP, "UDP_" + dport, "open", "epmap/client", ([]), prefs, dests)

#__ haslayer(NBNSQueryRequest)
### IP/UDP/netbios-ns=137 query
	elif p.haslayer(NBNSQueryRequest):
		if dport == "137":
			if meta['dMAC'] == "ff:ff:ff:ff:ff:ff":				#broadcast
				ReportId("UC", sIP, "UDP_" + dport, "open", "netbios-ns/broadcastclient", ([]), prefs, dests)
			elif Payload and (Payload.find(b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA') > -1):	#wildcard
				ReportId("UC", sIP, "UDP_" + dport, "open", "netbios-ns/wildcardclient", (['amplification', 'spoofed']), prefs, dests)
			else:
				ReportId("UC", sIP, "UDP_" + dport, "open", "netbios-ns/unicastclient", ([]), prefs, dests)
				UnhandledPacket(p, prefs, dests)
		else:
			ShowPacket(p, meta, "IP/UDP/unhandled packet with NBNSQueryRequest layer", HonorQuit, prefs, dests)

#__ haslayer(NBNSQueryResponse)
### IP/UDP/netbios-ns=137 response
	elif p.haslayer(NBNSQueryResponse):
		if sport == "137":
			netbios_hostname = p[NBNSQueryResponse].RR_NAME.rstrip().rstrip(nullbyte).decode('UTF-8')
			netbios_address = p[NBNSQueryResponse].NB_ADDRESS.rstrip().decode('UTF-8')
			ReportId("US", sIP, "UDP_" + sport, "open", "netbios-ns", ([]), prefs, dests)
			process_udp_ports.UDPManualServerDescription[FromPort] = "netbios-ns"
			ReportId("NA", netbios_address, "PTR", netbios_hostname, "netbios-ns", ([]), prefs, dests)
		else:
			ShowPacket(p, meta, "IP/UDP/unhandled packet with NBNSQueryResponse layer", HonorQuit, prefs, dests)

#__ haslayer(NBTDatagram)
### IP/UDP/netbios-dgm=138 query
	elif p.haslayer(NBTDatagram):
		netbios_hostname = p[NBTDatagram].SourceName.rstrip().decode('UTF-8')
		ReportId("NA", sIP, "PTR", netbios_hostname, "netbios-dgm", ([]), prefs, dests)
		if (sport == "138") and (dport == "138"):
			ReportId("US", sIP, "UDP_" + sport, "open", "netbios-dgm", ([]), prefs, dests)
			process_udp_ports.UDPManualServerDescription[FromPort] = "netbios-dgm"
		elif sport == "138":
			ReportId("US", sIP, "UDP_" + sport, "open", "netbios-dgm", ([]), prefs, dests)
			process_udp_ports.UDPManualServerDescription[FromPort] = "netbios-dgm"
		elif dport == "138":
			ReportId("UC", sIP, "UDP_" + dport, "open", "netbios-dgm/" + meta['cast_type'] +  "client", ([]), prefs, dests)
		else:
			ShowPacket(p, meta, "IP/UDP/unhandled packet with NBTDatagram layer", HonorQuit, prefs, dests)

#__ haslayer(SNMP)
### IP/UDP/SNMP=161
	elif p.haslayer(SNMP):
		#FIXME - extracting snmp community string?
		#type(p[SNMP].community)
		#p[SNMP].show()
		#snmp_community_string = remove_control_characters(str(p[SNMP].community.decode('utf-8'))).strip(' \t\r\n\0')
		#if dport == "161" and (p.haslayer(SNMPget) or p.haslayer(SNMPbulk) or p.haslayer(SNMPvarbind)):
		#	if ShowCredentials:
		#		ReportId("UC", sIP, "UDP_" + dport, "open", "snmp/client community string:" + snmp_community_string, (['plaintext', ]), prefs, dests)
		#	else:
		#		ReportId("UC", sIP, "UDP_" + dport, "open", 'snmp/client', (['plaintext']), prefs, dests)
		#elif sport == "161" and p.haslayer(SNMPresponse):
		#	if ShowCredentials:
		#		ReportId("US", sIP, "UDP_" + sport, "open", "snmp/server community string:" + snmp_community_string, (['plaintext', ]), prefs, dests)
		#		process_udp_ports.UDPManualServerDescription[FromPort] = "snmp/server community string:" + snmp_community_string
		#	else:
		#		ReportId("US", sIP, "UDP_" + sport, "open", 'snmp/server', (['plaintext', ]), prefs, dests)
		#		process_udp_ports.UDPManualServerDescription[FromPort] = "snmp/server"
		#else:
		ShowPacket(p, meta, "IP/UDP/unhandled packet with SNMP layer", HonorQuit, prefs, dests)

	elif sport == "161" or dport == "161":
		UnhandledPacket(p, prefs, dests)
### IP/UDP/svrloc=427	https://tools.ietf.org/html/rfc2608
	elif dport == "427" and Payload and (Payload.find(b'service:') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "svrloc/client", ([]), prefs, dests)
### IP/UDP/isakmp=500
	elif (sport == "500") and (dport == "500") and isinstance(p[ISAKMP], ISAKMP) and (p[ISAKMP].init_cookie != ''):
		ReportId("US", sIP, "UDP_" + sport, "open", "isakmp/generic", ([]), prefs, dests)
		process_udp_ports.UDPManualServerDescription[FromPort] = "isakmp/generic"
### IP/UDP/biff=512
	elif dport == "512" and Payload and (Payload.find(b'@') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "biff/client", ([]), prefs, dests)
### IP/UDP/syslog=514	https://www.ietf.org/rfc/rfc3164.txt
	elif dport == "514" and Payload and Payload.startswith(b'<') and (Payload[2] == b'>' or Payload[3] == b'>' or Payload[4] == b'>'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "syslog/client", (['plaintext', ]), prefs, dests)
		ReportId("US", dIP, "UDP_" + dport, "open", "syslog/server not confirmed", (['plaintext', ]), prefs, dests)
		process_udp_ports.UDPManualServerDescription[FromPort] = "syslog/server not confirmed"

		hostname_and_process = SyslogMatch.search(Payload)
		if (hostname_and_process is not None) and (len(hostname_and_process.groups()) >= 2):
			syslog_hostname = hostname_and_process.group(1)
			ReportId("NA", sIP, "PTR", syslog_hostname, "syslog", (['plaintext', ]), prefs, dests)
			process_name = hostname_and_process.group(2)
			ReportId("IP", sIP, "IP", "live", 'running process: ' + process_name, (['plaintext', ]), prefs, dests)
		else:
			#ShowPacket(p, meta, "Syslog that does not match regex", HonorQuit, prefs, dests)
			UnhandledPacket(p, prefs, dests)
### IP/UDP/snmp on alternate ports
	elif (dport in snmp_altport) and Payload and (Payload.find(b'public') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "snmp-altport/client", (['nonstandardport', ]), prefs, dests)
### IP/UDP/ibm-db2=523 client
	elif (dport == "523") and Payload and (Payload.find(b'DB2GETADDR') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "ibm-db2/clientscanner", (['scan', ]), prefs, dests)
### IP/UDP/DHCPv6=547 request
	elif meta['ip_class'] == '6' and (sport == "546") and (dport == "547") and dIP in ("ff02::1:2", "ff02:0000:0000:0000:0000:0000:0001:0002"):
		ReportId("UC", sIP, "UDP_" + dport, "open", "UDP DHCPv6", ([]), prefs, dests)
	elif meta['ip_class'] == '6' and (sport == "546") and (dport == "547"):	#dhcp request
		ShowPacket(p, meta, "IPv6/UDPv6/546-547-ff02::1:2 DHCP Request", HonorQuit, prefs, dests)
### IP/UDP/DHCPv6=547 reply
	elif meta['ip_class'] == '6' and (sport == "547") and (dport == "546"):
		pass
### IP/UDP/626 serialnumberd	https://svn.nmap.org/nmap/nmap-payloads
	elif (dport == "626") and (Payload == b'SNQUERY: 127.0.0.1:AAAAAA:xsvr'):		#nmap serialnumberd scan
		ReportId("UC", sIP, "UDP_" + dport, "open", "serialnumberd/clientscanner likely nmap scan", (['scan', ]), prefs, dests)
### IP/UDP/636,992,993 make sure this follows snmp_altport line  Payload contains \x03www\x03163\x03com
	elif dport in www163com_ports and Payload and (Payload.find(www163com_payload) > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "scan_www163com/client", (['scan', ]), prefs, dests)
### IP/UDP/udp-ldaps=636
	elif dport in fenull_scan_names and Payload.startswith(b"8") and Payload.endswith(fenulls):
		ReportId("UC", sIP, "UDP_" + dport, "open", fenull_scan_names[dport] + "/client", (['scan', ]), prefs, dests)
### IP/UDP/loadav=750
	elif dport == '750' and Payload and Payload.find(nullbyte + 'NESSUS.ORG' + nullbyte) > -1:
		if sIP in nessus_scan_ips:
			ReportId("UC", sIP, "UDP_" + dport, "open", "loadav/clientscanner nessus scanner", (['scan', ]), prefs, dests)
		else:
			ReportId("UC", sIP, "UDP_" + dport, "open", "loadav/clientscanner nessus unregistered scanner IP address", (['scan', ]), prefs, dests)
### IP/UDP/winpopup	winpopup spam client
	elif dport in ("1026", "1027", "1028") and Payload and ((Payload.find(b'Download Registry Update from:') > -1) or (Payload.find(b'CRITICAL ERROR MESSAGE! - REGISTRY DAMAGED AND CORRUPTED.') > -1) or (Payload.find(b'Your system registry is corrupted and needs to be cleaned immediately.') > -1) or (Payload.find(b'CRITICAL SYSTEM ERRORS') > -1)):
		ReportId("UC", sIP, "UDP_" + dport, "open", "winpopup/spamclient", (['malicious', ]), prefs, dests)
### IP/UDP/sharemouse=1046 rc_iamhere sharemouse	https://www.hybrid-analysis.com/sample/ca51df55d9c938bf0dc2ecbc10b148ec5ab8d259f3ea97f719a1a498e128ee05?environmentId=100
	elif sport == "1046" and dport == "1046" and (meta['dMAC'] == "ff:ff:ff:ff:ff:ff") and Payload and Payload.startswith(b'rc_iamhere:6555:0:0:'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "sharemouse/broadcastclient rc_iamhere sharemouse trojan", (['malicious', ]), prefs, dests)
		ReportId("NA", sIP, "NA", Payload[20:], "sharemouse trojan", (['malicious', ]), prefs, dests)
### IP/UDP/udp1124=1124 used by printers
	elif (dport == "1124") and (meta['dMAC'] == "ff:ff:ff:ff:ff:ff") and Payload and (Payload.find(b'std-scan-discovery-all') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "udp1124/broadcast", ([]), prefs, dests)
### IP/UDP/search-agent=1234 used by stora NAS
	elif (dport == "1234") and (meta['dMAC'] == "ff:ff:ff:ff:ff:ff") and Payload and (Payload.find(b'Hello there. I am at ') > -1):
		HostnameMatch = StoraHostnameMatch.search(Payload)
		if (HostnameMatch is not None) and (len(HostnameMatch.groups()) >= 1):
			ReportId("UC", sIP, "UDP_" + dport, "open", "stora_nas_scan/broadcast hostname: " + HostnameMatch.group(1), ([]), prefs, dests)
		else:
			ReportId("UC", sIP, "UDP_" + dport, "open", "stora_nas_scan/broadcast", ([]), prefs, dests)
### IP/UDP/mssql=1434	Probable mssql attack
	elif dport == "1434" and Payload and (Payload.find(b'Qh.dll') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "mssql/clientattack", (['malicious', ]), prefs, dests)
	elif dport == "1434" and Payload and Payload in (twobyte, twozero):		#https://portunus.net/2015/01/21/mc-sqlr-amplification/ .  Text refers to a one-byte \x02, but I've seen \x02\x00 as well.
		ReportId("UC", sIP, "UDP_" + dport, "open", "mssql/client nmap ping scan", (['amplification', 'ddos', 'scan']), prefs, dests)
### IP/UDP/kdeconnect=1716
	elif sport == "1716" and dport == "1716" and (meta['dMAC'] == "ff:ff:ff:ff:ff:ff") and Payload and (Payload.find(b'kdeconnect.') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "kdeconnect/broadcast", ([]), prefs, dests)
	elif sport == "1716" and dport == "1716" and Payload and (Payload.find(b'kdeconnect.') > -1):
		ReportId("US", sIP, "UDP_" + sport, "open", 'kdeconnect/server', ([]), prefs, dests)
		process_udp_ports.UDPManualServerDescription[FromPort] = "kdeconnect/server"

#__ haslayer(Radius)
### IP/UDP/radius=1812
	elif p.haslayer(Radius):
		if sport == "1812":
			ReportId("US", sIP, "UDP_" + sport, "open", 'radius/server', ([]), prefs, dests)
			process_udp_ports.UDPManualServerDescription[FromPort] = "radius/server"
		elif dport == "1812":
			ReportId("UC", sIP, "UDP_" + dport, "open", 'radius/client', ([]), prefs, dests)
		else:
			ShowPacket(p, meta, "IP/UDP/unhandled packet with Radius layer", HonorQuit, prefs, dests)

	elif (sport == "1813") and (dport == "1900"):		#Scapy misparses this as Radius accounting, when it's SSDP.  Ignore.
		pass
### IP/UDP/ssdp=1900	https://embeddedinn.wordpress.com/tutorials/upnp-device-architecture/
	elif dport in ("1900", "1990", "32412", "32414") and dIP in ("255.255.255.255", "239.255.255.250", "ff02:0000:0000:0000:0000:0000:0000:000c", "ff05:0000:0000:0000:0000:0000:0000:000c", "ff08:0000:0000:0000:0000:0000:0000:000c", "ff0e:0000:0000:0000:0000:0000:0000:000c") and Payload and (Payload.startswith((b'M-SEARCH', b'B-SEARCH'))):		#ssdp discover
		if dport == "1900":
			ssdp_warns = []
		else:
			ssdp_warns = ['nonstandardport']
		#FIXME - pull in *cast type from meta
		ReportId("UC", sIP, "UDP_" + dport, "open", "ssdp-discovery/broadmulticastclient", (ssdp_warns), prefs, dests)
	elif (dport == "1900") and Payload and (Payload.startswith((b'M-SEARCH', b'B-SEARCH'))):		#ssdp discover
		ReportId("UC", sIP, "UDP_" + dport, "open", "ssdp-discovery/client", ([]), prefs, dests)
	elif (dport == "1900") and dIP in ("255.255.255.255", "239.255.255.250", "ff02:0000:0000:0000:0000:0000:0000:000c", "ff05:0000:0000:0000:0000:0000:0000:000c", "ff08:0000:0000:0000:0000:0000:0000:000c", "ff0e:0000:0000:0000:0000:0000:0000:000c") and Payload and (Payload.startswith(b'NOTIFY')):		#ssdp announcement
		additional_info = ''
		LocationMatch = SSDPLocationMatch.search(Payload)
		if (LocationMatch is not None) and (len(LocationMatch.groups()) >= 1):
			additional_info = additional_info + ' SSDP Location: ' + str(LocationMatch.group(1)).strip()
		ServerMatch = SSDPServerMatch.search(Payload)
		if (ServerMatch is not None) and (len(ServerMatch.groups()) >= 1):
			additional_info = additional_info + ' SSDP Server: ' + str(ServerMatch.group(1)).replace(',', ' ').strip()
		ReportId("UC", sIP, "UDP_" + dport, "open", "ssdp-announce/client" + additional_info, ([]), prefs, dests)
	elif dport in ("1900", "11211") and Payload and (Payload == b'GET / HTTP/1.1\r\n\r\n'):		#bogus GET packet
		ReportId("UC", sIP, "UDP_" + dport, "open", "ssdp-bogus-get/clientscanner", (['scan', ]), prefs, dests)
	elif (dport == "1900") and dIP in ("239.255.255.250", "ff02:0000:0000:0000:0000:0000:0000:000c", "ff05:0000:0000:0000:0000:0000:0000:000c", "ff08:0000:0000:0000:0000:0000:0000:000c", "ff0e:0000:0000:0000:0000:0000:0000:000c"):		#ssdp
		ShowPacket(p, meta, "IP/UDP/1900-multicast SSDP unknown method", HonorQuit, prefs, dests)
### IP/UDP/hsrp=1985	https://en.wikipedia.org/wiki/Hot_Standby_Router_Protocol	https://tools.ietf.org/html/rfc2281
	elif sport in ("1985", "2029") and dport in ("1985", "2029") and meta['ttl'] == 1 and dIP in ('224.0.0.2', '224.0.0.102', 'ff02::66', 'ff02:0000:0000:0000:0000:0000:0000:0066'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "hsrp/multicastclient", ([]), prefs, dests)
		ReportId("RO", sIP, "HSRP", "router", "", ([]), prefs, dests)
### IP/UDP/ethernetip=2222	http://kazanets.narod.ru/files/Acro_ethernetIP_747a.pdf , see "CIP Encapsulation Message"
	elif (dport == "2222") and Payload and Payload.startswith(ethernetip_list_identity):
		ReportId("UC", sIP, "UDP_" + dport, "open", "ethernetip/clientscanner", (['scan', ]), prefs, dests)
### IP/UDP/msopid=2223	http://www.crufty.net/sjg/blog/osx-and-office-do-not-mix.htm
	elif (dport == "2223") and (meta['cast_type'] == "broadcast") and Payload and Payload.startswith(b'MSOPID'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "msopid/clientscanner", (['scan', ]), prefs, dests)
### IP/UDP/digiman=2362
	elif (dport == "2362") and Payload and Payload.startswith(b'DIGI'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "digiman/client", ([]), prefs, dests)
### IP/UDP/sybase=2638
	elif (dport == "2638") and Payload and (Payload.find(b'CONNECTIONLESS_TDS') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "sybase/client", (['scan', ]), prefs, dests)
### IP/UDP/mdap-port=3235
	elif (dport == "3235") and Payload and Payload.startswith(b'ANT-SEARCH MDAP/1.1'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "mdap-port/client", ([]), prefs, dests)
### IP/UDP/enpc=3289
	elif (dport == "3289") and (meta['dMAC'] == "ff:ff:ff:ff:ff:ff"):
		if Payload and (Payload.startswith(b'EPSON')):
			ReportId("UC", sIP, "UDP_" + dport, "open", "enpc/broadcast", ([]), prefs, dests)
		else:
			UnhandledPacket(p, prefs, dests)
### IP/UDP/teredo=3544	https://tools.ietf.org/html/rfc4380
	elif (dport == "3544") and Payload:	#and Payload.startswith(fournulls):	#Signature needs improvement
		ReportId("UC", sIP, "UDP_" + dport, "open", "teredo/client", ([]), prefs, dests)
		UnhandledPacket(p, prefs, dests)
### IP/UDP/upnp-discovery=3702
	elif (dport == "3702") and Payload and (Payload.startswith(b'<?xml') or Payload.find(b'://schemas.xmlsoap.org/') > -1):
		if dIP in ("239.255.255.250", "ff02::c", "ff02:0000:0000:0000:0000:0000:0000:000c"):
			ReportId("UC", sIP, "UDP_" + dport, "open", "upnp-discovery/broadcastclient", ([]), prefs, dests)
		else:
			ReportId("UC", sIP, "UDP_" + dport, "open", "upnp-discovery/client", ([]), prefs, dests)
### IP/UDP/bfd-control=3784		https://tools.ietf.org/html/rfc5881
	elif (dport == "3784") and (meta['ttl'] == 255):
		#FIXME - add check that sport must be between 49152 and 65535
		ReportId("UC", sIP, "UDP_" + dport, "open", "bfd-control/client", ([]), prefs, dests)
### IP/UDP/xpl=3865
	elif (dport == "3865") and (dIP == "255.255.255.255"):					#XPL, http://wiki.xplproject.org.uk/index.php/Main_Page
		ReportId("UC", sIP, "UDP_" + dport, "open", "xpl/client", ([]), prefs, dests)
### IP/UDP/vertx=4070	https://github.com/brad-anton/VertX/blob/master/VertX_Query.py
	elif (dport == "4070") and (Payload == b'discover;013;'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "vertx/client", (['scan', ]), prefs, dests)

#__ haslayer(ESP)
### IP/UDP/esp=4500	https://learningnetwork.cisco.com/thread/76175
	elif p.haslayer(ESP):
		if dport == "4500":
			if p[ESP].data == 'TP/1.1\r\nHost: www\r\n\r\n':
				ReportId("UC", sIP, "UDP_" + dport, "open", "esp/client", (['scan', 'tunnel']), prefs, dests)
			else:
				ReportId("UC", sIP, "UDP_" + dport, "open", "esp/client", (['tunnel', ]), prefs, dests)
		elif sport == "4500":
			ReportId("US", sIP, "UDP_" + sport, "open", "esp/server", (['tunnel', ]), prefs, dests)
			process_udp_ports.UDPManualServerDescription[FromPort] = "esp/server"
		else:
			ShowPacket(p, meta, "IP/UDP/unhandled packet with ESP layer", HonorQuit, prefs, dests)

### IP/UDP/drobo=5002 used by drobo NAS
	elif (dport == "5002") and Payload and Payload.startswith(b'DRINETTM'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "drobo_nas_scan/" + meta['cast_type'] + "client", ([]), prefs, dests)
### IP/UDP/vonage
	elif (sport == "5061") and (dport == "5061") and (dIP in vonage_sip_servers):		#Vonage SIP client
		if Payload and (Payload.find(b'.vonage.net:5061 SIP/2.0') > -1):
			SipMatch = process_udp_ports.SipPhoneMatch.search(Payload)
			if (SipMatch is not None) and (len(SipMatch.groups()) >= 1):
				ReportId("UC", sIP, "UDP_" + dport, "open", "sip/vonage_client, phone number: " + SipMatch.group(1), ([]), prefs, dests)
			else:
				ReportId("UC", sIP, "UDP_" + dport, "open", "sip/vonage_client", ([]), prefs, dests)
		else:
			UnhandledPacket(p, prefs, dests)
	elif (sport == "5061") and (dport == "5061") and (sIP in vonage_sip_servers):	#Vonage SIP server
		if Payload and (Payload.find(b'.vonage.net:5061>') > -1):
			ReportId("US", sIP, "UDP_" + sport, "open", "sip/vonage_server", ([]), prefs, dests)
			process_udp_ports.UDPManualServerDescription[FromPort] = "sip/vonage_server"
		else:
			UnhandledPacket(p, prefs, dests)
### IP/UDP/nat-pmp=5351	http://miniupnp.free.fr/nat-pmp.html , https://tools.ietf.org/html/rfc6886
	elif dport == "5351":
		if Payload and Payload.startswith(nullbyte * 2):						#\x00\x00 is Public address request
			ReportId("UC", sIP, "UDP_" + dport, "open", "nat-pmp-public-address-discovery/client", (['scan', ]), prefs, dests)
		elif Payload and Payload.startswith((zeroone, zerotwo)):					#\x00\x0[12] is mapping request
			ReportId("UC", sIP, "UDP_" + dport, "open", "nat-pmp-mapping-request/client", ([]), prefs, dests)
		else:
			ShowPacket(p, meta, "IPv4/UDPv4/5351 nat-pmp unknown payload", HonorQuit, prefs, dests)

#__ haslayer(LLMNRQuery)
### IP/UDP/llmnr=5355 query
	elif p.haslayer(LLMNRQuery):
		if (dport == "5355") and dIP in ("224.0.0.252", "ff02::1:3", "ff02:0000:0000:0000:0000:0000:0001:0003") and (meta['ttl'] in (1, 255)) and (p[LLMNRQuery].qr == 0): #llmnr (link-local multicast node resolution)
			UnhandledPacket(p, prefs, dests)
		else:
			ShowPacket(p, meta, "IP/UDP/unhandled packet with LLMNRQuery layer", HonorQuit, prefs, dests)

### IP/UDP/llmnr=5355 response
	elif (dport == "5355") and dIP in ("224.0.0.252", "ff02::1:3", "ff02:0000:0000:0000:0000:0000:0001:0003") and (meta['ttl'] in (1, 255)): #llmnr (link-local multicast node resolution)
		ShowPacket(p, meta, "IP/UDP/5355-224.0.0.252,ff02::1:3 llmnr not query", HonorQuit, prefs, dests)
		#Can we pass this off to PUDR?
	elif dport == "5355":							#unicast fe80->fe80 llmnr (link-local multicast node resolution)
		ShowPacket(p, meta, "IP/UDP/5355 unicast llmnr not to 224.0.0.252,1:3", HonorQuit, prefs, dests)
### IP/UDP/corosync=5405 used by corosync
	elif (dport == "5405") and (meta['dMAC'] == "ff:ff:ff:ff:ff:ff"):
		ReportId("UC", sIP, "UDP_" + dport, "open", "corosync/broadcast", ([]), prefs, dests)
### IP/UDP/pcanywherestat=5632 client
	elif (dport == "5632") and Payload and (Payload.find(b'NQ') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "pcanywherestat/clientscanner", (['scan', ]), prefs, dests)
	elif (sport == "6515") and (dport == "6514") and (dIP == "255.255.255.255"):		#mcafee ASaP broadcast, looking for a proxy out.  http://www.myasap.de/intl/EN/content/virusscan_asap/faq_new.asp
		if Payload and (Payload.find(b'<rumor version=') > -1):
			ReportId("UC", sIP, "UDP_" + dport, "open", "asap/client", ([]), prefs, dests)
		else:
			UnhandledPacket(p, prefs, dests)
### IP/UDP/coap=5683	https://tools.ietf.org/html/rfc6690 , http://www.herjulf.se/download/coap-2013-fall.pdf , https://tools.ietf.org/html/rfc7252#section-3
	elif (dport == "5683") and Payload and (Payload.startswith((b'@', b'P', b'`', b'p')) or (Payload.find(b'.well-known') > -1)):		# '@' confirmable, 'P' non-confirmable, '`' acknowledgement, or 'p' Reset  (The acknowledgment and reset may have to go in sport == "5683" instead)
		ReportId("UC", sIP, "UDP_" + dport, "open", "coap/client", ([]), prefs, dests)
### IP/UDP/bt-lpd=6771	https://security.stackexchange.com/questions/102766/wireshark-reveals-suspicious-udp-traffic-sending-to-a-bogon-ip-address
	elif (dport == "6771") and (dIP == "239.192.152.143") and Payload and (Payload.startswith(b'BT-SEARCH * HTTP/1.1')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "bt-lpd/client", ([]), prefs, dests)
### IP/UDP/unreal_status=7778	https://arp242.net/weblog/online_unreal_tournament_server_browser_with_pcntl_fork()
	elif (dport == "7778") and Payload and Payload.startswith(b'\\status\\'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "unreal_status/client", ([]), prefs, dests)
### IP/UDP/kissdvd=8000	https://www.tapatalk.com/groups/helplinedirect/getting-linksys-kiss-1600-to-work-with-ubuntu-t35.html
	elif (dport == "8000") and Payload and Payload == b'ARE_YOU_KISS_PCLINK_SERVER?':
		ReportId("UC", sIP, "UDP_" + dport, "open", "kissdvd/client", (['scan', ]), prefs, dests)
### IP/UDP/canon-bjnp2=8610
	elif (dport == "8610") and meta['cast_type'] and Payload and (Payload.startswith(b'MFNP')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "udp8610/" + meta['cast_type'], ([]), prefs, dests)
### IP/UDP/canon-bjnp2=8612		https://support.usa.canon.com/kb/index?page=content&id=ART109227
	elif dport in ("8612", "8613") and meta['cast_type'] and Payload and (Payload.startswith(b'BJNP')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "canon-bjnp2/" + meta['cast_type'], ([]), prefs, dests)
	elif dport in ("8612", "8613") and dIP in ('ff02::1', 'ff02:0000:0000:0000:0000:0000:0000:0001') and Payload and (Payload.startswith(b'BJNP')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "canon-bjnp2/client", ([]), prefs, dests)
### IP/UDP/canon-bjnb-bnjb=8612
	elif (dport == "8612") and meta['cast_type'] and Payload and (Payload.startswith((b'BNJB', b'BJNB'))):
		ReportId("UC", sIP, "UDP_" + dport, "open", "canon-bjnb-bnjb/" + meta['cast_type'], ([]), prefs, dests)
### IP/UDP/itunesdiscovery=8765
	elif dport == "8765":									#XPL, http://wiki.xplproject.org.uk/index.php/Main_Page
		ReportId("UC", sIP, "UDP_" + dport, "open", "itunesdiscovery/broadcast", ([]), prefs, dests)		#'portonlysignature'
### IP/UDP/sunwebadmin=8800
	elif dport == "8800" and Payload and Payload.startswith(b'DHGET'):				#http://sites.ieee.org/neworleans/files/2016/12/12052016-Presentation-IoT-security-website-copy.pdf
		ReportId("UC", sIP, "UDP_" + dport, "open", "sunwebadmin/client possibly Mirai", (['dos', ]), prefs, dests)
### IP/UDP/aoldns
	elif (sport in ("9052", "9053", "9054")) and (sIP in aol_dns_servers):	#Possibly AOL dns response
		if Payload and (Payload.find(b'dns-01') > -1):
			ReportId("US", sIP, "UDP_" + sport, "open", "aoldns/server", ([]), prefs, dests)
			process_udp_ports.UDPManualServerDescription[FromPort] = "aoldns/server"
		else:
			UnhandledPacket(p, prefs, dests)
### IP/UDP/teamspeak3=9987,59596 client	https://github.com/TeamSpeak-Systems/ts3init_linux_netfilter_module
	elif dport in ("9987", "59596") and Payload and (Payload.startswith(b'TS3INIT1')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "teamspeak3/clientscanner", (['scan', 'dos', ]), prefs, dests)
### UP/UDP/ubnt-discover=10001	https://github.com/headlesszeke/ubiquiti-probing
	elif dport == "10001" and Payload and (Payload == ubiquiti_discover):
		ReportId("UC", sIP, "UDP_" + dport, "open", "ubnt-discover/clientscanner", (['scan', ]), prefs, dests)
### IP/UDP/memcached=11211		https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/	https://github.com/memcached/memcached/blob/master/doc/protocol.txt
	elif dport in ("1121", "11211") and Payload:
		if ((Payload.find(b'gets ') > -1) or (Payload.find(b'stats') > -1)):
			ReportId("UC", sIP, "UDP_" + dport, "open", 'memcached/client: Likely spoofed and DDOSed source IP', (['amplification', 'malicious', 'spoofed']), prefs, dests)
		elif Payload.find(b'version') > -1:
			ReportId("UC", sIP, "UDP_" + dport, "open", 'memcached/client', (['scan', ]), prefs, dests)
		else:
			ShowPacket(p, meta, "IP/UDP/memcached=1121 or 11211 request but non-gets/stats/version", HonorQuit, prefs, dests)
	elif sport == "11211":
		ReportId("US", sIP, "UDP_" + sport, "open", 'memcached/server', ([]), prefs, dests)
		process_udp_ports.UDPManualServerDescription[FromPort] = "memcached/server"
### IP/UDP/zmapscanner=1707,3269,3544,6619,1121[45]								https://zmap.io/ , https://github.com/zmap/zmap
	elif dport in zmap_host_www_ports and (Payload == b'GET / HTTP/1.1\r\nHost: www\r\n\r\n'):
		ReportId("UC", sIP, "UDP_" + dport, "open", 'zmapscanner/client', (['scan', ]), prefs, dests)
### IP/UDP/makerbotdiscovery=12307		https://github.com/gryphius/mini-makerbot-hacking/blob/master/doc/makerbotmini.md
	elif (sport == "12309") and (dport == "12307") and meta['cast_type']:
		if Payload and (Payload.startswith(b'{"command": "broadcast"')):
			ReportId("UC", sIP, "UDP_" + dport, "open", "makerbotdiscovery/" + meta['cast_type'], ([]), prefs, dests)
### IP/UDP/12314
	elif dport == "12314" and Payload and Payload.startswith(fournulls):					#Actually,lots more nulls than 4.
		ReportId("UC", sIP, "UDP_" + dport, "open", 'udp12314/client', (['scan', ]), prefs, dests)
### IP/UDP/dropbox=17500	http://whatportis.com/ports/17500_dropbox-lansync-protocol-db-lsp-used-to-synchronize-file-catalogs-between-dropbox-clients-on-your-local-network
	elif (sport == "17500") and (dport == "17500"):
		if Payload and (Payload.find(b'"host_int"') > -1):
			ReportId("UC", sIP, "UDP_" + dport, "open", "dropbox/client", ([]), prefs, dests)
		else:
			UnhandledPacket(p, prefs, dests)
### IP/UDP/googlemeet=19302-19309
	elif (dport in meet_ports) and (dIP in meet_hosts):
		ReportId("UC", sIP, "UDP_" + dport, "open", "googlemeet/client", ([]), prefs, dests)
	elif (sport in meet_ports) and (sIP in meet_hosts):
		ReportId("US", sIP, "UDP_" + sport, "open", "googlemeet/server", ([]), prefs, dests)
		process_udp_ports.UDPManualServerDescription[FromPort] = "googlemeet/server"
	elif dport in meet_ports:
		ReportId("UC", sIP, "UDP_" + dport, "open", "googlemeet/client missing dIP:" + dIP, ([]), prefs, dests)		#'portonlysignature'
	elif sport in meet_ports:
		ReportId("US", sIP, "UDP_" + sport, "open", "googlemeet/server missing sIP:" + sIP, ([]), prefs, dests)		#'portonlysignature'
		process_udp_ports.UDPManualServerDescription[FromPort] = "googlemeet/server missing sIP:" + sIP
### IP/UDP/develo=19375	https://flambda.de/2013/06/18/audioextender/	https://ubuntuforums.org/showthread.php?t=1942539	https://www2.devolo.com/products/dLAN-Powerline-1485-Mbps/dLAN-Wireless-extender/data/Data-sheet-dLAN-Wireless-extender-Starter-Kit-com.pdf
	elif dport == "19375" and meta['cast_type'] and Payload.startswith(b'whoisthere'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "develo/" + meta['cast_type'] + "client", ([]), prefs, dests)		#Note, payload is "whoisthere\x00' + str(ip.address) + '\x00' + str(subnet_mask) + '\x00\x001\x00'
### IP/UDP/skype=all over the place
	elif (dport in skype_ports) and (dIP in skype_hosts):
		ReportId("UC", sIP, "UDP_" + dport, "open", "skype/client", ([]), prefs, dests)
	elif (sport in skype_ports) and (sIP in skype_hosts):
		ReportId("US", sIP, "UDP_" + sport, "open", "skype/server", ([]), prefs, dests)
		process_udp_ports.UDPManualServerDescription[FromPort] = "skype/server"
	elif dIP in skype_hosts:
		ReportId("UC", sIP, "UDP_" + dport, "open", "skype/client, missing dport:" + dport, ([]), prefs, dests)
	elif sIP in skype_hosts:
		ReportId("US", sIP, "UDP_" + sport, "open", "skype/server, missing sport:" + sport, ([]), prefs, dests)
		process_udp_ports.UDPManualServerDescription[FromPort] = "skype/server, missing sport:" + sport
	elif dport in skype_ports:
		ReportId("UC", sIP, "UDP_" + dport, "open", "skype/client missing dIP:" + dIP, ([]), prefs, dests)		#'portonlysignature'
	elif sport in skype_ports:
		ReportId("US", sIP, "UDP_" + sport, "open", "skype/server missing sIP:" + sIP, ([]), prefs, dests)		#'portonlysignature'
		process_udp_ports.UDPManualServerDescription[FromPort] = "skype/server missing sIP:" + sIP
### IP/UDP/pyzor=24441
	elif dport == "24441":											#Pyzor
		if Payload and (Payload.find(b'User:') > -1):
			ReportId("UC", sIP, "UDP_" + dport, "open", "pyzor/client", ([]), prefs, dests)
		else:
			UnhandledPacket(p, prefs, dests)
### IP/UDP/unknown26079
	elif (sport == "26079") or (dport == "26079") or sIP in ("52.179.141.141", "100.112.42.45") or dIP in ("52.179.141.141", "100.112.42.45"):
		UnhandledPacket(p, prefs, dests)
### IP/UDP/halflife=27005 and others
	elif (sport == "27005") and (dport in ('27015', '27016', '27017')):					#Halflife client live game
		ReportId("UC", sIP, "UDP_" + dport, "open", "halflife/client", ([]), prefs, dests)				#'portonlysignature'
	elif (dport == "27013") and (dIP == "207.173.177.12"):							#variable payload, so can't Payload and (Payload.find(b'Steam.exe') > -1)				#Halflife client
		ReportId("UC", sIP, "UDP_" + dport, "open", "halflife/client", ([]), prefs, dests)
	elif (sport == "27013") and (sIP == "207.173.177.12"):							#halflife server
		ReportId("US", sIP, "UDP_" + sport, "open", "halflife/server", ([]), prefs, dests)
		process_udp_ports.UDPManualServerDescription[FromPort] = "halflife/server"
	elif (sport in '27015', '27016', '27017') and (dport == "27005"):					#halflife server live game
		ReportId("US", sIP, "UDP_" + sport, "open", "halflife/server", ([]), prefs, dests)				#'portonlysignature'
		process_udp_ports.UDPManualServerDescription[FromPort] = "halflife/server"
	elif dport in ("27015", "27016", "27025", "27026"):							#Variable payload, so can't: Payload and (Payload.find(b'basic') > -1)	#Halflife client
		ReportId("UC", sIP, "UDP_" + dport, "open", "halflife/client", ([]), prefs, dests)				#'portonlysignature'
	elif sport in ("27015", "27016", "27025", "27026"):							#Variable payload, so can't: Payload and (Payload.find(b'basic') > -1)	#Halflife client
		ReportId("US", sIP, "UDP_" + sport, "open", "halflife/server", ([]), prefs, dests)				#'portonlysignature'
		process_udp_ports.UDPManualServerDescription[FromPort] = "halflife/server"
	elif (dport == "27017") and (dIP in SteamFriendsServers):	#Steamfriends client
		if Payload and (Payload.find(b'VS01') > -1):
			ReportId("UC", sIP, "UDP_" + dport, "open", "steamfriends/client", ([]), prefs, dests)
		else:
			UnhandledPacket(p, prefs, dests)
	elif (sport == "27017") and (sIP in SteamFriendsServers):	#Steamfriends server
		if Payload and (Payload.find(b'VS01') > -1):
			ReportId("US", sIP, "UDP_" + sport, "open", "steamfriends/server", ([]), prefs, dests)
			process_udp_ports.UDPManualServerDescription[FromPort] = "steamfriends/server"
		else:
			UnhandledPacket(p, prefs, dests)
	elif sport in ("21020", "21250", "27016", "27017", "27018", "27030", "27035", "27040", "28015"):	#halflife server
		if Payload and (Payload.find(b'Team Fortress') > -1):
			ReportId("US", sIP, "UDP_" + sport, "open", "halflife/server", ([]), prefs, dests)			#'portonlysignature'
			process_udp_ports.UDPManualServerDescription[FromPort] = "halflife/server"
		else:
			UnhandledPacket(p, prefs, dests)
	elif sport == "27019":											#halflife server
		ReportId("US", sIP, "UDP_" + sport, "open", "halflife/server", ([]), prefs, dests)				#'portonlysignature'
		process_udp_ports.UDPManualServerDescription[FromPort] = "halflife/server"

### IP/UDP/steam-ihs-discovery=27036		https://codingrange.com/blog/steam-in-home-streaming-discovery-protocol
	elif (sport == "27036") and (dport == "27036") and (dIP == "255.255.255.255"):
		if Payload and (Payload.startswith(stream_ihs_discovery_header)):
			ReportId("UC", sIP, "UDP_" + dport, "open", "stream-ihs-discovery-broadcast/client", ([]), prefs, dests)
		else:
			UnhandledPacket(p, prefs, dests)
	elif (dport == "27036") and Payload and (Payload.startswith(stream_ihs_discovery_header)):
		ReportId("UC", sIP, "UDP_" + dport, "open", "stream-ihs-discovery/client", ([]), prefs, dests)
	elif dport in halflife_altport:										#Halflife client
		if Payload and (Payload.find(b'Source Engine Query') > -1):
			ReportId("UC", sIP, "UDP_" + dport, "open", "halflife/client", ([]), prefs, dests)			#'portonlysignature'
		else:
			UnhandledPacket(p, prefs, dests)
### IP/UDP/lima=25213	https://support.meetlima.com/hc/en-us/articles/115004950326-README-document
	elif dport == "25213" and Payload and (Payload.startswith(b'ZVPN')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "limavpn/client", (['tunnel', ]), prefs, dests)
### IP/UDP/openarena=27960	https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=665656 , http://openarena.ws/board/index.php?topic=4391.0 , http://blog.alejandronolla.com/2013/06/24/amplification-ddos-attack-with-quake3-servers-an-analysis-1-slash-2/
	elif (dport == "27960") and Payload and Payload.startswith(eight_fs + b'getstatus'):
		ReportId("UC", sIP, "UDP_" + dport, "open", 'openarena-quake3/client getstatus: Likely spoofed and DDOSed source IP', (['amplification', 'dos', 'spoofed']), prefs, dests)
### IP/UDP/hap=28784	https://hal.inria.fr/hal-01456891/document
	elif (dport == "28784") and Payload and Payload.startswith(b'HAP'):
		ReportId("UC", sIP, "UDP_" + dport, "open", 'hap/client', (['scan', ]), prefs, dests)
### IP/UDP/traceroute
	elif ((dport >= "33434") and (dport <= "33524")):	#udptraceroute client
		ReportId("UC", sIP, "UDP_33434", "open", "udptraceroute/client", ([]), prefs, dests)				#'portonlysignature'
### IP/UDP/lima=33612	https://support.meetlima.com/hc/en-us/articles/115004950326-README-document
	elif dport == "33612" and Payload and (Payload.startswith(b'LIMA')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "lima/client", ([]), prefs, dests)
### IP/UDP/tzsp=37008	https://korniychuk.org.ua/instruction/live-packet-captures-using-mikrotik-routeros-and-wireshark/
	elif dport == "37008":
		ReportId("UC", sIP, "UDP_" + dport, "open", "tzsp/client", (['tunnel', ]), prefs, dests)
		ShowPacket(p, meta, "IP/UDP/TZSP", HonorQuit, prefs, dests)
### IP/UDP/halflife=40348
	elif dport == "40348" and Payload and (Payload.find(b'HLS') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "halflife/client", ([]), prefs, dests)
### IP/UDP/crestron-cip=41794	https://media.defcon.org/DEF%20CON%2026/DEF%20CON%2026%20presentations/Ricky%20Lawshae/DEFCON-26-Lawshae-Who-Controls-the-Controllers-Hacking-Crestron.pdf
	elif (sport == "41794") and (dport == "41794") and Payload and Payload.startswith(crestron_prelude + b'hostname'):
		ReportId("UC", sIP, "UDP_" + dport, "open", 'crestron-cip/clientscanner', (['scan', ]), prefs, dests)
### IP/UDP/zengge-bulb=48899 client https://github.com/vikstrous/zengge-lightcontrol/blob/master/README.md
	elif (dport == "48899") and Payload and (Payload.find(b'HF-A11ASSISTHREAD') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "zengge-bulb/clientscanner", (['scan', ]), prefs, dests)
### IP/UDP/linkproof=49153 client	https://eromang.zataz.com/2010/04/28/suc007-activities-on-49153udp-linkproof-proximity-advanced/
	elif (dport == "49153") and Payload and (Payload.startswith(b'linkproof.proximity.advanced')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "radware-linkproof/clientscanner", (['scan', ]), prefs, dests)
### IP/UDP/netis-backdoor-53413=53413 client, exploting Netis router backdoor: https://isc.sans.edu/forums/diary/Surge+in+Exploit+Attempts+for+Netis+Router+Backdoor+UDP53413/21337/
	elif dport == "53413":							#To limit this signature to just shellcode, add the following tests to this line:   and Payload and (Payload.find(b'; chmod 777 ') > -1)
		ReportId("UC", sIP, "UDP_" + dport, "open", "netis-backdoor-53413/client", (['malicious', ]), prefs, dests)	#'portonlysignature'
### IP/UDP/logitech-arx=54915		http://support.moonpoint.com/network/udp/port_54915/
	elif sport == "54915" and dport == "54915" and meta['cast_type']:
		ReportId("UC", sIP, "UDP_" + dport, "open", "logitech-arx/" + meta['cast_type'] + "client", ([]), prefs, dests)	#'portonlysignature'
### IP/UDP/brother-announce=54925 and 54926 used by brother printers		http://ww2.chemistry.gatech.edu/software/Drivers/Brother/MFC-9840CDW/document/ug/usa/html/sug/index.html?page=chapter7.html
	elif (dport in ("54925", "54926")) and meta['cast_type'] and Payload and (Payload.find(b'NODENAME=') > -1):
		BrotherMatch = BrotherAnnounceMatch.search(Payload)
		if (BrotherMatch is not None) and (len(BrotherMatch.groups()) >= 4):
			#In the packets I've seen, groups 1, 2, and 3 are ip addresses (1 ipv4 and 2 ipv6).  Group 4 is a nodename ("BRWF" + uppercase mac address, no colons)
			ReportId("UC", sIP, "UDP_" + dport, "open", "brother-announce/" + meta['cast_type'] + " nodename: " + BrotherMatch.group(4), ([]), prefs, dests)
			ReportId("UC", BrotherMatch.group(1), "UDP_" + dport, "open", "brother-announce/" + meta['cast_type'] + " nodename: " + BrotherMatch.group(4), ([]), prefs, dests)
			ReportId("UC", BrotherMatch.group(2), "UDP_" + dport, "open", "brother-announce/" + meta['cast_type'] + " nodename: " + BrotherMatch.group(4), ([]), prefs, dests)
			ReportId("UC", BrotherMatch.group(3), "UDP_" + dport, "open", "brother-announce/" + meta['cast_type'] + " nodename: " + BrotherMatch.group(4), ([]), prefs, dests)
		else:
			ReportId("UC", sIP, "UDP_" + dport, "open", "brother-announce/" + meta['cast_type'], ([]), prefs, dests)
### IP/UDP/spotify-broadcast=57621		https://mrlithium.blogspot.com/2011/10/spotify-and-opting-out-of-spotify-peer.html
	elif (dport == "57621") and Payload and (Payload.startswith(b'SpotUdp')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "spotify/" + meta['cast_type'] + "client", ([]), prefs, dests)
### IP/UDP/probes with empty payloads
	elif dport in empty_payload_ports and Payload == b'':
		ReportId("UC", sIP, "UDP_" + dport, "open", "empty-payload/client", ([]), prefs, dests)
	elif Payload == b'':
		ReportId("UC", sIP, "UDP_" + dport, "open", "empty-payload/client Port not registered", ([]), prefs, dests)
		UnhandledPacket(p, prefs, dests)
### IP/UDP/quake3 disconnect amplification		http://blog.alejandronolla.com/2013/08/05/amplification-ddos-attack-with-quake3-servers-an-analysis-2-slash-2/
	elif Payload == quake3_disconnect:
		ReportId("UC", sIP, "UDP_" + dport, "open", 'quake3/client: Disconnect, likely spoofed and DDOSed source IP', (['amplification', 'malicious', 'spoofed']), prefs, dests)
		UnhandledPacket(p, prefs, dests)
### IP/UDP/bt-dht		http://www.bittorrent.org/beps/bep_0005.html , https://isc.sans.edu/forums/diary/Identifying+applications+using+UDP+payload/6031/
	elif Payload and Payload.find(b':id') > -1 and ((Payload.find(b':info_hash') > -1 and Payload.find(b':get_peers') > -1) or Payload.find(b':ping') > -1 or Payload.find(b'9:find_node') > -1):	#Unfortunately, can run on any port
		ReportId("UC", sIP, "UDP_" + dport, "open", 'bt-dht-scan/clientscanner', (['scan', ]), prefs, dests)
	elif Payload and Payload.find(b':id') > -1 and Payload.find(b':token') > -1 and (Payload.find(b':nodes') > -1 or Payload.find(b':values')):
		ReportId("US", sIP, "UDP_" + sport, "open", 'bt-dht/server', ([]), prefs, dests)
		process_udp_ports.UDPManualServerDescription[FromPort] = "bt-dht/server"
	elif Payload and Payload.find(b'; wget ') > -1 and Payload.find(b'; sh ') > -1 and Payload.find(b'; rm -rf ') > -1:
		ReportId("UC", sIP, "UDP_" + dport, "open", 'shellcode/clientscanner', (['scan', 'malicious']), prefs, dests)
	elif Payload and Payload.startswith(a0_string):									#Payload starting with A\x00
		UnhandledPacket(p, prefs, dests)
	elif dport in SecUDPPortNames:
		warning_list = []
		if dport in udp_port_warnings:
			warning_list = [udp_port_warnings[dport]]
		UnhandledPacket(p, prefs, dests)
		ReportId("UC", sIP, "UDP_" + dport, "open", str(SecUDPPortNames[dport]) + "/client", (warning_list), prefs, dests)	#'portonlysignature'
	elif sport in SecUDPPortNames:
		warning_list = []
		if sport in udp_port_warnings:
			warning_list = [udp_port_warnings[sport]]
		UnhandledPacket(p, prefs, dests)
		ReportId("US", sIP, "UDP_" + sport, "open", str(SecUDPPortNames[sport]) + "/server", (warning_list), prefs, dests)	#'portonlysignature'
		process_udp_ports.UDPManualServerDescription[FromPort] = str(SecUDPPortNames[sport]) + "/server"
	elif meta['ip_class'] == '4' and p[IP].frag > 0:
		UnhandledPacket(p, prefs, dests)
	elif (sport == "53") and not p.haslayer(DNS):									#source port 53, but no parsed DNS layer.  Seen this in large packets with Raw immediately following UDP.
		UnhandledPacket(p, prefs, dests)
	elif sport == "53":												#source port 53.  I've seen some coming back from port 53 with qr=0, request.  Hmmm.
		UnhandledPacket(p, prefs, dests)
	elif sIP in shodan_hosts and Payload == fournulls + b'abcdefgh':
		ReportId("UC", sIP, "UDP_" + dport, "open", "shodan_host/clientscanner abcdefgh", (['scan', ]), prefs, dests)
	elif sIP in shodan_hosts:
		ReportId("UC", sIP, "UDP_" + dport, "open", "shodan_host/clientscanner", (['scan', ]), prefs, dests)
	elif Payload == fournulls + b'abcdefgh':
		ReportId("UC", sIP, "UDP_" + dport, "open", "shodan_host/clientscanner abcdefgh Unlisted host", (['scan', ]), prefs, dests)
	elif sIP in known_scan_ips:
		ReportId("UC", sIP, "UDP_" + dport, "open", "udp/clientscanner known scanner", (['scan', ]), prefs, dests)

	elif meta['dMAC'] == "ff:ff:ff:ff:ff:ff" and dport in broadcast_udp_ports:
		ReportId("UC", sIP, "UDP_" + dport, "open", "udp" + dport + "/broadcastclient", ([]), prefs, dests)			#'portonlysignature'
	elif sport in broadcast_udp_ports:
		ReportId("US", sIP, "UDP_" + sport, "open", 'udp' + sport + '/server', ([]), prefs, dests)				#'portonlysignature'
		process_udp_ports.UDPManualServerDescription[FromPort] = 'udp' + sport + '/server'
	#elif meta['dMAC'] == "ff:ff:ff:ff:ff:ff":
	#	ShowPacket(p, meta, "IP/UDP/unhandled broadcast", HonorQuit, prefs, dests)
	#else:
	#	ShowPacket(p, meta, "IP/UDP/unhandled port", HonorQuit, prefs, dests)


def processpacket(p):
	"""Extract information from a single packet off the wire."""

	#Because this is called from scapy.sniff with no apparent way to hand down params other than the raw packet, we have to pull these two from main by hand.
	prefs = cl_args
	dests = destinations

	#Persistent variables
	#These 4 hold the seconds_since_the_epoch and human readable UTC versions of the earliest and latest packets
	if "start_stamp" not in processpacket.__dict__:
		processpacket.start_stamp = None
	if "start_string" not in processpacket.__dict__:
		processpacket.start_string = ''
	if "end_stamp" not in processpacket.__dict__:
		processpacket.end_stamp = None
	if "end_string" not in processpacket.__dict__:
		processpacket.end_string = ''
	if "current_stamp" not in processpacket.__dict__:
		processpacket.current_stamp = None
	if "current_string" not in processpacket.__dict__:
		processpacket.current_string = ''

	if "ClosedUDPPortsReceived" not in processpacket.__dict__:
		processpacket.ClosedUDPPortsReceived = {}	#Dictionary of sets.  Key is expanded IP address, value is a set of "IP,Proto_Port" strings that sent back "closed".  High counts of these are systems that are scanning for ports.

	if debug_known_layer_lists:
		p_layers = list(ReturnLayers(p))
		if p_layers not in known_layer_lists:
			debug_out('>>>>>>>> ' + str(p_layers), prefs, dests)
			ShowPacket(p, meta, "Unknown layer list", HonorQuit, prefs, dests)
			quit()

		for one_layer in p_layers:
			if one_layer not in layer_label_to_key:
				debug_out('>>>>>>>> ' + str(one_layer) + ' not in layer_label_to_key', prefs, dests)
				ShowPacket(p, meta, "Unknown layer list", HonorQuit, prefs, dests)
				quit()

	processpacket.current_stamp, processpacket.current_string = packet_timestamps(p)
	if not processpacket.start_stamp or processpacket.current_stamp < processpacket.start_stamp:
		processpacket.start_stamp = processpacket.current_stamp
		processpacket.start_string = processpacket.current_string
	if not processpacket.end_stamp or processpacket.current_stamp > processpacket.end_stamp:
		processpacket.end_stamp = processpacket.current_stamp
		processpacket.end_string = processpacket.current_string

	meta = generate_meta_from_packet(p, prefs, dests)
	#Convert:
	#sMac -> meta['sMAC']
	#dMac -> meta['dMAC']
	#meta['cast_type']
	#pp_ttl -> meta['ttl']

	#Transitional variables
	sIP = meta['sIP']
	dIP = meta['dIP']
	sport = meta['sport']
	dport = meta['dport']

	if p.getlayer(Raw):
		Payload = p.getlayer(Raw).load
	else:
		Payload = b""


### Spanning Tree Protocol
	if isinstance(p, Dot3) and p.haslayer(LLC) and isinstance(p[LLC], LLC):
		pass	#Nothing really to learn from it.
### 802.3 without LLC
	elif isinstance(p, Dot3):
		pass	#Nothing really to learn from it.
### Need more details on how to handle.
	elif p.haslayer(Ether) and p[Ether] is None:
		ShowPacket(p, meta, "non-ethernet packet: " + str(type(p)), HonorQuit, prefs, dests)
### ARP
	elif (p.haslayer(Ether) and p[Ether].type == 0x0806) and p.haslayer(ARP) and isinstance(p[ARP], ARP):		#ARP
		#pull arp data from here instead of tcp/udp packets, as these are all local
		if p[ARP].op == 1:			#1 is request ("who-has")
			pass
		elif p[ARP].op == 2:			#2 is reply ("is-at")
			if (p[ARP].psrc is not None) and (p[ARP].hwsrc is not None):
				IPAddr = p[ARP].psrc
				MyMac = p[ARP].hwsrc.upper()
				ReportId("MA", IPAddr, 'Ethernet', MyMac, '', ([]), prefs, dests)
			else:
				UnhandledPacket(p, prefs, dests)
		else:
			UnhandledPacket(p, prefs, dests)
### ARP, truncated
	elif p.haslayer(Ether) and p[Ether].type == 0x0806:		#2054: ARP, apparently truncated
		UnhandledPacket(p, prefs, dests)
### IPv4 ethertype but not ipv4 in the ip header
	elif ((p.haslayer(CookedLinux) and p[CookedLinux].proto == 0x800) or (p.haslayer(Ether) and ((p[Ether].type == 0x0800) or (p[Ether].type == 0x8100))) or not p.haslayer(Ether)) and p.haslayer(IP) and isinstance(p[IP], IP) and p[IP].version != 4:
		#ShowPacket(p, meta, "IPV4 packet with version != 4", HonorQuit, prefs, dests)
		UnhandledPacket(p, prefs, dests)
### IPv4
	elif ((p.haslayer(CookedLinux) and p[CookedLinux].proto == 0x800) or (p.haslayer(Ether) and ((p[Ether].type == 0x0800) or (p[Ether].type == 0x8100))) or not p.haslayer(Ether)) and p.haslayer(IP) and isinstance(p[IP], IP):

		if meta['sMAC'] == 'ff:ff:ff:ff:ff:ff':
			ReportId("IP", sIP, "Broadcast_source_mac", "open", "Source mac address is broadcast", (['noncompliant', ]), prefs, dests)

		#Best to get these from arps instead; if we get them from here, we get router macs for foreign addresses.
		#ReportId("MA", sIP, "Ethernet", meta['sMAC'], '', ([]), prefs, dests)
		#ReportId("MA", dIP, "Ethernet", dMAC, '', ([]), prefs, dests)

### IPv4/IP
		if p[IP].proto == 0:
			ShowPacket(p, meta, "IPv4/Protocol 0", HonorQuit, prefs, dests)
### IPv4/ICMPv4
		elif (p[IP].proto == 1) and p.haslayer(ICMP) and isinstance(p[ICMP], ICMP):
			Type = p[ICMP].type
			Code = p[ICMP].code

### IPv4/ICMPv4/Echo Reply=0
			if Type == 0:
				ReportId("IP", sIP, "IP", "live", 'icmp echo reply', ([]), prefs, dests)
### IPv4/ICMPv4/Unreachable=3
			elif (Type == 3) and p.haslayer(IPerror) and isinstance(p[IPerror], IPerror):	#Unreachable, check that we have an actual embedded packet
				if type(p[IPerror]) != IPerror:
					ShowPacket(p, meta, "IPv4/ICMPv4/Unreachable=type3/Not IPError: " + str(type(p[IPerror])), HonorQuit, prefs, dests)

				if Code == 0:					#Net unreachable
					ReportId("IP", meta['OrigdIP'], "IP", "dead", 'net unreachable', ([]), prefs, dests)
					ReportId("RO", sIP, "NetUn", "router", "client_ip=" + dIP, ([]), prefs, dests)
				elif Code == 1:					#Host unreachable
					ReportId("IP", meta['OrigdIP'], "IP", "dead", 'host unreachable', ([]), prefs, dests)
					ReportId("RO", sIP, "HostUn", "router", "client_ip=" + dIP, ([]), prefs, dests)
				elif Code == 2:					#Protocol unreachable
					ReportId("RO", sIP, "ProtoUn", "router", "client_ip=" + dIP, ([]), prefs, dests)
				#Following codes are Port unreachable, Network/Host Administratively Prohibited, Network/Host unreachable for TOS, Communication Administratively prohibited
				elif Code in (3, 9, 10, 11, 12, 13) and (p[IPerror].proto == 17) and p.haslayer(UDPerror) and isinstance(p[UDPerror], UDPerror):	#Port unreachable and embedded protocol = 17, UDP, as it should be
					DNSServerLoc = meta['OrigsIP'] + ",UDP_53"
					if (p[UDPerror].sport == 53) and (DNSServerLoc in process_udp_ports.UDPManualServerDescription) and (process_udp_ports.UDPManualServerDescription[DNSServerLoc] == "dns/server"):	#Cross-function variable
						#If orig packet coming from 53 and coming from a dns server, don't do anything (closed port on client is a common effect)
						#Don't waste time on port unreachables going back to a dns server; too common, and ephemeral anyways.
						pass
					else:
						#If orig packet coming from something other than 53, or coming from 53 and NOT coming from a dns server, log as closed
						OrigDPort = str(p[UDPerror].dport)
						ReportId("US", meta['OrigdIP'], "UDP_" + OrigDPort, "closed", "port unreachable", ([]), prefs, dests)

						if include_udp_errors_in_closed_ports:
							#Prober is dIP.  Probed port is: meta['OrigdIP'] + ",UDP_" + OrigDPort
							if dIP not in processpacket.ClosedUDPPortsReceived:
								processpacket.ClosedUDPPortsReceived[dIP] = set()
							processpacket.ClosedUDPPortsReceived[dIP].add(meta['OrigdIP'] + ",UDP_" + OrigDPort)
							if len(processpacket.ClosedUDPPortsReceived[dIP]) >= min_closed_ports_for_scanner:
								ReportId("IP", dIP, "IP", "suspicious", 'Scanned UDP closed ports.', (['scan', ]), prefs, dests)
				elif Code in (3, 9, 10, 11, 12, 13) and (p[IPerror].proto == 6) and isinstance(p[TCPerror], TCPerror):	#Port unreachable and embedded protocol = 6, TCP, which it shouldn't.  May be the same firewall providing the TCP FR's
					pass

					#Following code disabled as it needs cross-process dictionaries, and isn't valid in the first place.
					##Now we _could_ claim the machine sending the error is a linux firewall.
					#OrigDPort = str(p[TCPerror].dport)
					#Service = meta['OrigdIP'] + ",TCP_" + OrigDPort
					#if Service in processpacket.SynSentToTCPService and ((Service not in processpacket.LiveTCPService) or processpacket.LiveTCPService[Service]):
					#	processpacket.LiveTCPService[Service] = False
					#	ReportId("TS", meta['OrigdIP'], "TCP_" + OrigDPort, "closed", '', ([]), prefs, dests)

					#if Service in processpacket.SynSentToTCPService:
					#	#Prober is dIP.  Probed port is Service (= meta['OrigdIP'] + ",TCP_" + OrigDPort)
					#	if dIP not in processpacket.ClosedTCPPortsReceived:
					#		processpacket.ClosedTCPPortsReceived[dIP] = set()
					#	processpacket.ClosedTCPPortsReceived[dIP].add(Service)
					#	if len(processpacket.ClosedTCPPortsReceived[dIP]) >= min_closed_ports_for_scanner:
					#		ReportId("IP", dIP, "IP", "suspicious", 'Scanned closed ports.', (['scan', ]), prefs, dests)
				elif (Code == 3) and (p[IPerror].proto == 1) and isinstance(p[ICMPerror], ICMPerror):	#Port unreachable and embedded protocol = 1, ICMP; not sure if this is legit or not.
					#Now we _could_ claim the machine sending the error is a linux firewall.
					pass
				elif Code == 3:					#Port unreachable, but we do not have (complete) underlying layers below IPerror or IPerror6
					pass
				elif Code == 4:					#Fragmentation needed
					pass
				elif Code == 6:					#Net unknown
					ReportId("IP", meta['OrigdIP'], "IP", "dead", 'net unknown', ([]), prefs, dests)
				elif Code == 7:					#Host unknown
					ReportId("IP", meta['OrigdIP'], "IP", "dead", 'host unknown', ([]), prefs, dests)
				elif Code == 9:					#Network Administratively Prohibited
					pass					#Can't tell much from this type of traffic.  Possibly list as firewall?
				elif Code == 10:				#Host Administratively Prohibited
					pass
				elif Code == 11:				#Network unreachable for TOS
					pass
				elif Code == 12:				#Host unreachable for TOS
					pass
				elif Code == 13:				#Communication Administratively prohibited
					pass
				else:
					ShowPacket(p, meta, "IPv4/ICMPv4/Type=3/unhandled code: " + str(Code), HonorQuit, prefs, dests)
### IPv4/ICMPv3/Source Quench=4		https://tools.ietf.org/html/rfc6633 - ipv4 source quench deprecated since 2012, does not exist in ipv6
			elif Type == 4:
				UnhandledPacket(p, prefs, dests)
### IPv4/ICMPv4/Redirect=5
			elif (Type == 5) and isinstance(p[IPerror], IPerror):	#Unreachable, check that we have an actual embedded packet
				if type(p[IPerror]) != IPerror:
					ShowPacket(p, meta, "IPv4/ICMPv4/Redirect=type5/Not IPError: " + str(type(p[IPerror])), HonorQuit, prefs, dests)
				elif Code in (0, 1, 2, 3):			#Network, Host, TOS+Network, TOS+Host
					ReportId("RO", sIP, "Redirect", "router", "attempted_router client_ip=" + dIP, ([]), prefs, dests)
					better_router = p[ICMP].gw
					ReportId("RO", better_router, "Redirect", "router", "recommended_router client_ip=" + dIP, ([]), prefs, dests)
				else:
					UnhandledPacket(p, prefs, dests)
### IPv4/ICMPv4/Echo Request=8
			elif Type == 8:
				#FIXME - check payload for ping sender type, perhaps
				if Payload.find(b'liboping -- ICMP ping library') > -1:
					ReportId("IP", sIP, "IP", "live", 'oping icmp echo request scanner', (['scan', ]), prefs, dests)
				else:
					ReportId("IP", sIP, "IP", "live", 'icmp echo request scanner', (['scan', ]), prefs, dests)
### IPv4/ICMPv4/Router Advertisement=9		https://tools.ietf.org/html/rfc1256
			elif Type == 9:
				ReportId("RO", sIP, "RouterAdv", "router", '', ([]), prefs, dests)
### IPv4/ICMPv4/Time exceeded=11
			elif Type == 11:
				if Code == 0:					#TTL exceeded
					#FIXME - put original target IP as column 5?
					ReportId("RO", sIP, "TTLEx", "router", "client_ip=" + dIP, ([]), prefs, dests)
				else:
					UnhandledPacket(p, prefs, dests)
			elif Type in (6, 15, 16, 17, 18, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39):	#https://tools.ietf.org/html/rfc6918
				ReportId("IP", sIP, "ICMP_type_" + str(Type), "open", "Deprecated ICMP type scanner", (['noncompliant', 'scan']), prefs, dests)
			elif Type >= 44 and Type <= 252:			#https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
				ReportId("IP", sIP, "ICMP_type_" + str(Type), "open", "Reserved ICMP type scanner", (['noncompliant', 'scan']), prefs, dests)
			else:
				UnhandledPacket(p, prefs, dests)
				ShowPacket(p, meta, 'Unhandled ipv4 ICMP packet', HonorQuit, prefs, dests)
		elif p[IP].proto == 1:
			UnhandledPacket(p, prefs, dests)
### IPv4/IGMPv4
		elif p[IP].proto == 2:		#IGMP
			UnhandledPacket(p, prefs, dests)
### IPv4/TCPv4
		elif p[IP].proto == 6 and p.haslayer(TCP) and isinstance(p[TCP], TCP):		#TCP
			ReportAll(TCP_extract(p, meta, prefs, dests), prefs, dests)

### IPv4/TCPv4, probably truncated/fragmented
		elif p[IP].proto == 6:		#TCP, but haslayer fails.  Quite possibly a fragment; either way we can't do anything with it.
			UnhandledPacket(p, prefs, dests)
			#ShowPacket(p, meta, "IPv4/TCPv4/no TCP layer", HonorQuit, prefs, dests)
### IPv4/UDPv4
		elif p[IP].proto == 17 and p.haslayer(UDP):			#old form: (type(p[UDP]) == UDP):
			#UDP.  We have to check the object type as well as we do get (corrupted? truncated?) packets with type 17 that aren't udp:  AttributeError: 'NoneType' object has no attribute 'sport'
			#Change over to p.getlayer(ICMPv6DestUnreach) ?  We're getting crashes on elif p[IP].proto == 17 and (type(p[UDP]) == UDP):
			#FIXME - possibly run udp packets through processpacket.ServiceFPs as well?
			process_udp_ports(meta, p, prefs, dests)

### IPv4/UDPv4, probably truncated/fragmented
		elif p[IP].proto == 17:					#This is the case where the protocol is listed as 17, but there's no complete UDP header.  Quite likely a 2nd or future fragment.
			UnhandledPacket(p, prefs, dests)
### IPv4/UDPv4/ipencap
		elif p[IP].proto == 4:					#ipencap, IP encapsulated in IP.
			outer_ip = p.getlayer(IP, nb=1)
			inner_layer = outer_ip.payload
			if isinstance(inner_layer, IP):
				#FIXME - submit the inner packet for processing?
				if inner_layer.getlayer(Raw).load == "this is not an attack":
					ReportId("IP", sIP, "ipencap", "open", 'ipencap/client', (['tunnel', 'scan']), prefs, dests)
				else:
					ReportId("IP", sIP, "ipencap", "open", 'ipencap/client', (['tunnel', ]), prefs, dests)
			else:
				ShowPacket(p, meta, "ipencap with non-IP inner layer", HonorQuit, prefs, dests)

### IPv4/IPSecv4/GRE	#GRE
		elif p[IP].proto == 47 and p.haslayer(GRE):
			ReportId("PC", sIP, "PROTO_" + str(p[IP].proto), "open", "gre/client", (['tunnel', ]), prefs, dests)
			if p[GRE].proto == 2048:		#0x800==2048==IPv4
				if p[GRE].payload:
					encap_packet = p[GRE].payload
					processpacket(encap_packet)
				else:
					UnhandledPacket(p, prefs, dests)
			elif p[GRE].proto == 25944:		#0x6558==25944==Trans Ether Bridging
				if p.haslayer(Raw):
					encap_packet_raw = p[Raw].load
					encap_packet = Ether(encap_packet_raw)
					processpacket(encap_packet)
				else:
					UnhandledPacket(p, prefs, dests)
			elif p[GRE].proto == 34827:		#0x880B==34827==PPP
				if p.haslayer(Raw):
					#Sample payload:   \x00\x08:v\xff\x03\x00!E\x00\x00c\x00\x00   Hack; strip off first 8 bytes and interpret the rest as IP.  Similar packet has 4 byte intro, so we test that too.
					encap_packet_raw = None
					if p[GRE].load[4:6] == ip_start_bytes:
						encap_packet_raw = p[GRE].load[4:]
					elif p[GRE].load[8:10] == ip_start_bytes:
						encap_packet_raw = p[GRE].load[8:]
					if encap_packet_raw:
						encap_packet = IP(encap_packet_raw)
						processpacket(encap_packet)
					else:
						ShowPacket(p, meta, "GRE raw does not appear to have E\x00\x00", HonorQuit, prefs, dests)
				else:
					UnhandledPacket(p, prefs, dests)
			else:
				ShowPacket(p, meta, "GRE unhandled proto", HonorQuit, prefs, dests)

### IPv4/IPSecv4/ESP	#ESP (IPSEC)
		elif p[IP].proto == 50:
			ReportId("PC", sIP, "PROTO_" + str(p[IP].proto), "open", "ipsec-esp/client", (['tunnel', ]), prefs, dests)
			ReportId("PS", dIP, "PROTO_" + str(p[IP].proto), "open", "ipsec-esp/server unconfirmed", (['tunnel', ]), prefs, dests)
			UnhandledPacket(p, prefs, dests)
### IPv4/IPSecv4/AH	#AH (IPSEC)
		elif p[IP].proto == 51:
			ReportId("PC", sIP, "PROTO_" + str(p[IP].proto), "open", "ipsec-ah/client", (['tunnel', ]), prefs, dests)
			ReportId("PS", dIP, "PROTO_" + str(p[IP].proto), "open", "ipsec-ah/server unconfirmed", (['tunnel', ]), prefs, dests)
			UnhandledPacket(p, prefs, dests)
### IPv4/EIGRPv4	EIGRP = Enhanced Interior Gateway Routing Protocol
		elif (p[IP].proto == 88) and dIP in ("224.0.0.10", "FF02:0:0:0:0:0:0:A"):
			#224.0.0.10 for IPv4 EIGRP Routers, FF02:0:0:0:0:0:0:A for IPv6 EIGRP Routers
			ReportId("RO", sIP, "EIGRP", "router", "", ([]), prefs, dests)
		elif p[IP].proto == 88:					#Different target address format, perhaps?
			ShowPacket(p, meta, "IPv4/EIGRP unknown target IP", HonorQuit, prefs, dests)
### IPv4/OSPFv4
		elif (p[IP].proto == 89) and (dIP == "224.0.0.5"):		#OSPF = Open Shortest Path First
			UnhandledPacket(p, prefs, dests)
### IPv4/PIMv4
		elif (p[IP].proto == 103) and (dIP == "224.0.0.13"):		#PIM = Protocol Independent Multicast
			UnhandledPacket(p, prefs, dests)
### IPv4/VRRPv4
		elif (p[IP].proto == 112) and (dIP == "224.0.0.18"):		#VRRP = virtual router redundancy protocol
			UnhandledPacket(p, prefs, dests)
### IPv4/SSCOPMCE
		elif p[IP].proto == 128:
			UnhandledPacket(p, prefs, dests)
		else:		#http://www.iana.org/assignments/protocol-numbers
			#Look up protocol in /etc/protocols
			ShowPacket(p, meta, "Other IP protocol (" + meta['sIP'] + "->" + meta['dIP'] + "): " + str(p[IP].proto), HonorQuit, prefs, dests)
	#Look up other ethernet types in:
	# http://en.wikipedia.org/wiki/EtherType
	# /etc/ethertypes
	# http://www.iana.org/assignments/ethernet-numbers
	# http://standards.ieee.org/develop/regauth/ethertype/eth.txt
	# http://www.cavebear.com/archive/cavebear/Ethernet/type.html
		if "SuspiciousIPs" in ReportId.__dict__ and ReportId.SuspiciousIPs and (sIP in ReportId.SuspiciousIPs or dIP in ReportId.SuspiciousIPs):			#Cross-function variable
			SuspiciousPacket(p, prefs, dests)
	elif ((p.haslayer(CookedLinux) and p[CookedLinux].proto == 0x800) or (p.haslayer(Ether) and ((p[Ether].type == 0x0800) or (p[Ether].type == 0x8100)))):
		#Like above, but has no IP layer.  Probably truncated packet at the end of a still-running capture.
		UnhandledPacket(p, prefs, dests)
### 2114: Wake-on-lan
	elif p.haslayer(Ether) and p[Ether].type == 0x0842:
		UnhandledPacket(p, prefs, dests)
### 9728: Unknown
	elif p.haslayer(Ether) and p[Ether].type == 0x2600:
		UnhandledPacket(p, prefs, dests)
	#FIXME - add checks for CookedLinux and Ipv6 as well as Ether+IPv6
### IPv6 ethertype but not ipv6 in the ip header
	elif (p.haslayer(Ether) and p[Ether].type == 0x86DD) and p.haslayer(IPv6) and isinstance(p[IPv6], IPv6) and p[IPv6].version != 6:
		#ShowPacket(p, meta, "IPV6 packet with version != 6", HonorQuit, prefs, dests)
		UnhandledPacket(p, prefs, dests)
### IPv6
	elif (p.haslayer(Ether) and p[Ether].type == 0x86DD) and p.haslayer(IPv6) and isinstance(p[IPv6], IPv6):
		if meta['sMAC'] == 'ff:ff:ff:ff:ff:ff':
			ReportId("IP", sIP, "Broadcast_source_mac", "open", "Source mac address is broadcast", (['noncompliant', ]), prefs, dests)

### IPv6/IPv6ExtHdrHopByHop=0  Hop-by-hop option header
		if p[IPv6].nh == 0 and meta['ttl'] == 1 and p.getlayer(IPv6ExtHdrHopByHop) and p[IPv6ExtHdrHopByHop].nh == 58 and (p.haslayer(ICMPv6MLQuery) or p.haslayer(ICMPv6MLReport) or p.haslayer(ICMPv6MLDone)):	#0 is Hop-by-hop options
			UnhandledPacket(p, prefs, dests)
			#FIXME - try to extract Multicast info later.
			#if p[ICMPv6MLQuery].type == 130:		#MLD Query
			#	if p[ICMPv6MLQuery].mladdr == '::'	#General query
			#		pass
			#	else:					#Multicast-address-specific query
			#		pass
			#elif p[ICMPv6MLQuery].type == 131:		#Multicast Listener Report
			#	pass
			#elif p[ICMPv6MLQuery].type == 132:		#Multicast Listener Done
			#	pass
			#else:
			#	pass
		elif p[IPv6].nh == 0 and p.getlayer(IPv6ExtHdrHopByHop) and p[IPv6ExtHdrHopByHop].nh == 58 and (isinstance(p[IPv6ExtHdrHopByHop].payload, Raw) or p[IPv6ExtHdrHopByHop].payload.type == 135):
			#The packet claims to have an ICMPv6 layer, but the following layer is Raw.  Ignore.  Any chance that scapy is not interpreting the next layer down when it encounters a hop-by-hop?
			#Or, the inner packet is a neighbor solicitation.
			UnhandledPacket(p, prefs, dests)
		elif p[IPv6].nh == 0:
			ShowPacket(p, meta, "IPv6/IPv6ExtHdrHopByHop = 0; FIXME, intermediate header on its way to the real header", HonorQuit, prefs, dests)
			#https://tools.ietf.org/html/rfc2711 (router alert option)
			#Specifically "router contains a MLD message": https://tools.ietf.org/html/rfc2710
### IPv6/TCPv6=6
		elif p[IPv6].nh == 6 and p.haslayer(TCP):
			ReportAll(TCP_extract(p, meta, prefs, dests), prefs, dests)
		elif p[IPv6].nh == 6:
			ShowPacket(p, meta, "IPv6/nh==6 but no TCP layer", HonorQuit, prefs, dests)
### IPv6/UDPv6=17
		elif (p[IPv6].nh == 17) and p.haslayer(UDP):
			process_udp_ports(meta, p, prefs, dests)

### IPv6/Fragmentation=44
		elif p[IPv6].nh == 44: 		#Fragment header.  Not worth trying to extract info from following headers.
			#https://tools.ietf.org/html/rfc5798
			UnhandledPacket(p, prefs, dests)
### IPv6/ICMPv6=58
		elif p[IPv6].nh == 58:
			#Layer names; see layers/inet6.py ( /opt/local/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages/scapy/layers/inet6.py ), hash named icmp6typescls
### IPv6/ICMPv6=58/DestUnreach=1
			if p.getlayer(ICMPv6DestUnreach) and p.getlayer(IPerror6) and isinstance(p[IPerror6], IPerror6):   	#https://tools.ietf.org/html/rfc4443#section-3.1
				Code = p[ICMPv6DestUnreach].code
### IPv6/ICMPv6=58/DestUnreach=1/No route to dest=0	No route to destination; appears equivalent to IPv4 net unreachable
				if Code == 0:
					ReportId("IP", meta['OrigdIP'], "IP", "dead", 'net unreachable', ([]), prefs, dests)
					ReportId("RO", sIP, "NetUn", "router", "client_ip=" + dIP, ([]), prefs, dests)
### IPv6/ICMPv6=58/DestUnreach=1/AdminProhib=1		Communication with destination administratively prohibited (blocked by firewall)
				elif Code == 1:
					pass
### IPv6/ICMPv6=58/DestUnreach=1/BeyondScope=2		Beyond scope of source address					https://tools.ietf.org/html/rfc4443
				elif Code == 2:
					pass
### IPv6/ICMPv6=58/DestUnreach=1/AddressUnreach=3	Address unreachable (general, used when there is no more specific reason); appears equivalent to host unreachable
				elif Code == 3:
					ReportId("IP", meta['OrigdIP'], "IP", "dead", 'host unreachable', ([]), prefs, dests)
					ReportId("RO", sIP, "HostUn", "router", "client_ip=" + dIP, ([]), prefs, dests)
### IPv6/ICMPv6=58/DestUnreach=1/PortUnreach=4		Port unreachable and embedded protocol = 17, UDP, as it should be.  Appears equivalent to port unreachable
				elif (Code == 4) and (p[IPerror6].nh == 17) and p.haslayer(UDPerror) and isinstance(p[UDPerror], UDPerror):
					DNSServerLoc = meta['OrigsIP'] + ",UDP_53"
					if (p[UDPerror].sport == 53) and (DNSServerLoc in process_udp_ports.UDPManualServerDescription) and (process_udp_ports.UDPManualServerDescription[DNSServerLoc] == "dns/server"):	#Cross-function variable
						#If orig packet coming from 53 and coming from a dns server, don't do anything (closed port on client is a common effect)
						#Don't waste time on port unreachables going back to a dns server; too common, and ephemeral anyways.
						pass
					else:
						#If orig packet coming from something other than 53, or coming from 53 and NOT coming from a dns server, log as closed
						OrigDPort = str(p[UDPerror].dport)
						OrigDstService = meta['OrigdIP'] + ",UDP_" + OrigDPort
						ReportId("US", meta['OrigdIP'], "UDP_" + OrigDPort, "closed", "port unreachable", ([]), prefs, dests)

						if include_udp_errors_in_closed_ports:
							#Prober is dIP.  Probed port is: meta['OrigdIP'] + ",UDP_" + OrigDPort
							if dIP not in processpacket.ClosedUDPPortsReceived:
								processpacket.ClosedUDPPortsReceived[dIP] = set()
							processpacket.ClosedUDPPortsReceived[dIP].add(OrigDstService)
							if len(processpacket.ClosedUDPPortsReceived[dIP]) >= min_closed_ports_for_scanner:
								ReportId("IP", dIP, "IP", "suspicious", 'Scanned UDP closed ports.', (['scan', ]), prefs, dests)
				elif (Code == 4) and (p[IPerror6].nh == 6) and p.haslayer(TCPerror) and isinstance(p[TCPerror], TCPerror):				#Port unreachable and embedded protocol = 6, TCP, which it shouldn't.
					pass

					#Following code disabled because it depends on cross-process dictionaries and it's not legal in the first place.
					#OrigDPort = str(p[TCPerror].dport)
					#Service = meta['OrigdIP'] + ",TCP_" + OrigDPort
					#if Service in processpacket.SynSentToTCPService and ((Service not in processpacket.LiveTCPService) or processpacket.LiveTCPService[Service]):
					#	processpacket.LiveTCPService[Service] = False
					#	ReportId("TS", str(p[IPerror6].dst), "TCP_" + str(p[TCPerror].dport), "closed", '', ([]), prefs, dests)

					#if Service in processpacket.SynSentToTCPService:
					#	#Prober is dIP.  Probed port is meta['OrigdIP'] + ",TCP_" + OrigDPort
					#	if dIP not in processpacket.ClosedTCPPortsReceived:
					#		processpacket.ClosedTCPPortsReceived[dIP] = set()
					#	processpacket.ClosedTCPPortsReceived[dIP].add(Service)
					#	if len(processpacket.ClosedTCPPortsReceived[dIP]) >= min_closed_ports_for_scanner:
					#		ReportId("IP", dIP, "IP", "suspicious", 'Scanned TCP closed ports.', (['scan', ]), prefs, dests)
				elif (Code == 4) and (p[IPerror6].nh == 58):									#Port unreachable and embedded protocol = 58, ICMP.  Seen in response to pings
					pass
### IPv6/ICMPv6=58/DestUnreach=1/FailedPolicy=5		Source address failed ingress/egress policy (subset of code 1)	https://tools.ietf.org/html/rfc4443
				elif Code == 5:
					pass
### IPv6/ICMPv6=58/DestUnreach=1/RejectRoute=6		Reject route to destination (subset of code 1)			https://tools.ietf.org/html/rfc4443
				elif Code == 6:
					pass
### IPv6/ICMPv6=58/DestUnreach=1/HeaderError=7		Error in source routing header					https://tools.ietf.org/html/rfc6550 https://tools.ietf.org/html/rfc6554
				elif Code == 7:
					pass
### IPv6/ICMPv6=58/DestUnreach=1/Unknown
				else:
					ShowPacket(p, meta, "IPV6/ICMPv6/Dest Unreach=1/Unknown code", HonorQuit, prefs, dests)
### IPv6/ICMPv6=58/PacktTooBig=2
			elif p.getlayer(ICMPv6PacketTooBig):
				ReportId("RO", sIP, "TooBig", "router", "client_ip=" + dIP, ([]), prefs, dests)
### IPv6/ICMPv6=58/TimeExceeded=3
			elif p.getlayer(ICMPv6TimeExceeded):
				Code = p[ICMPv6TimeExceeded].code
				if Code == 0:				#hop limit exceeded in transit
					ReportId("RO", sIP, "TTLEx", "router", "client_ip=" + dIP, ([]), prefs, dests)
				else:
					ShowPacket(p, meta, "IPv6/ICMPv6/ICMPv6TimeExceeded = type 3/Code = " + str(Code), HonorQuit, prefs, dests)
### IPv6/ICMPv6=58/EchoRequest=128
			elif p.getlayer(ICMPv6EchoRequest):
				pass
### IPv6/ICMPv6=58/EchoReply=129
			elif p.getlayer(ICMPv6EchoReply):
				ReportId("IP", sIP, "IP", "live", 'icmp echo reply', ([]), prefs, dests)
### IPv6/ICMPv6=58/ND_RouterSolicitation=133
			elif p.getlayer(ICMPv6ND_RS) and (dIP == "ff02:0000:0000:0000:0000:0000:0000:0002"):
				pass
### IPv6/ICMPv6=58/ND_RouterAdvertisement=134
			elif p.getlayer(ICMPv6ND_RA) and (dIP == "ff02:0000:0000:0000:0000:0000:0000:0001"):
				AdditionalInfo = 'hop_limit=' + str(p[ICMPv6ND_RA].chlim)
				if p.getlayer(ICMPv6NDOptPrefixInfo):
					AdditionalInfo = AdditionalInfo + ' net=' + str(p[ICMPv6NDOptPrefixInfo].prefix) + '/' + str(p[ICMPv6NDOptPrefixInfo].prefixlen)
				if p.getlayer(ICMPv6NDOptRDNSS):
					for one_dns in p[ICMPv6NDOptRDNSS].dns:
						AdditionalInfo = AdditionalInfo + ' dns=' + str(one_dns)
				ReportId("RO", sIP, "RouterAdv", "router", AdditionalInfo, ([]), prefs, dests)

				if p.getlayer(ICMPv6NDOptSrcLLAddr):
					router_mac_addr = str(p[ICMPv6NDOptSrcLLAddr].lladdr)
					ReportId("MA", sIP, 'Ethernet', router_mac_addr, '', ([]), prefs, dests)
### IPv6/ICMPv6=58/ND_NeighborSolicitation=135												https://tools.ietf.org/html/rfc4861
			elif p.getlayer(ICMPv6ND_NS) and meta['ttl'] == 255 and p[ICMPv6ND_NS].code == 0:
				host_mac_addr = ''
				if p.getlayer(ICMPv6NDOptSrcLLAddr):
					host_mac_addr = str(p[ICMPv6NDOptSrcLLAddr].lladdr)
				elif p.getlayer(Ether):
					host_mac_addr = meta['sMAC']
				#else:
				#	pass	#No source for ethernet mac addr, ignore
				if host_mac_addr:
					ReportId("MA", sIP, 'Ethernet', host_mac_addr, '', ([]), prefs, dests)
### IPv6/ICMPv6=58/ND_NeighborAdvertisement=136												https://tools.ietf.org/html/rfc4861
			elif p.getlayer(ICMPv6ND_NA) and p.getlayer(Ether) and meta['ttl'] == 255 and p[ICMPv6ND_NA].code == 0:
				if p[ICMPv6ND_NA].R == 1:
					ReportId("RO", sIP, "NeighborAdvRouterFlag", "router", '', ([]), prefs, dests)
				host_mac_addr = meta['sMAC']
				ReportId("MA", sIP, 'Ethernet', host_mac_addr, '', ([]), prefs, dests)
### IPv6/ICMPv6=58/ND_Redirect=137													http://www.tcpipguide.com/free/t_ICMPv6RedirectMessages-2.htm
			elif p.getlayer(ICMPv6ND_Redirect) and p.getlayer(Ether) and meta['ttl'] == 255 and p[ICMPv6ND_Redirect].code == 0:
				ReportId("RO", sIP, "ND_Redirect_source", "router", "client_ip=" + dIP, ([]), prefs, dests)				#the original complaining router
				ReportId("RO", p[ICMPv6ND_Redirect].tgt, "ND_Redirect_target", "router", "client_ip=" + dIP, ([]), prefs, dests)	#the better router to use
				if p.getlayer(ICMPv6NDOptDstLLAddr):
					ReportId("MA", p[ICMPv6ND_Redirect].tgt, 'Ethernet', p[ICMPv6NDOptDstLLAddr].lladdr, '', ([]), prefs, dests)	#packet probably includes the mac address of the better router too.
			else:
				ShowPacket(p, meta, "IPv6/ICMPv6/unhandled type", HonorQuit, prefs, dests)
### IPv6/SATNET-EXPAK=64
		elif p[IPv6].nh == 64:
			UnhandledPacket(p, prefs, dests)
### IPv6/EIGRPv4	EIGRP = Enhanced Interior Gateway Routing Protocol
		elif (p[IPv6].nh == 88) and dIP in ("224.0.0.10", "FF02:0:0:0:0:0:0:A"):
			#224.0.0.10 for IPv4 EIGRP Routers, FF02:0:0:0:0:0:0:A for IPv6 EIGRP Routers
			ReportId("RO", sIP, "EIGRP", "router", "", ([]), prefs, dests)
		elif p[IPv6].nh == 88:						#Different target address format, perhaps?
			ShowPacket(p, meta, "IPv6/EIGRP unknown target IP", HonorQuit, prefs, dests)
### IPv6/OSPF=89
		elif (p[IPv6].nh == 89) and (dIP == "ff02:0000:0000:0000:0000:0000:0000:0005"): 		#OSPF
			#https://tools.ietf.org/html/rfc5340
			UnhandledPacket(p, prefs, dests)
### IPv6/VRRP=112
		elif (p[IPv6].nh == 112) and (dIP == "ff02:0000:0000:0000:0000:0000:0000:0012"): 		#VRRPv6	VRRP = virtual router redundancy protocol
			#https://tools.ietf.org/html/rfc5798
			UnhandledPacket(p, prefs, dests)
### IPv6/other
		else:
			ShowPacket(p, meta, "IPV6 unknown protocol; Next header:" + str(p[IPv6].nh), HonorQuit, prefs, dests)

		if "SuspiciousIPs" in ReportId.__dict__ and ReportId.SuspiciousIPs and (sIP in ReportId.SuspiciousIPs or dIP in ReportId.SuspiciousIPs):	#Cross-function variable
			SuspiciousPacket(p, prefs, dests)
### No ethernet layer
	elif not p.haslayer(Ether):
### 802.11 wireless
		if p.haslayer(RadioTap):
			if p.haslayer(Dot11) and p.haslayer(Dot11Deauth) and p[Dot11Deauth].reason == 7:	#"class3-from-nonass"
				if p[Dot11].addr1 == p[Dot11].addr3:		#These should be the AP mac address
					ReportId("WI", "0.0.0.0", "802.11_Deauth", "Deauthentication: client=" + p[Dot11].addr2 + " AP=" + p[Dot11].addr1, "", ([]), prefs, dests)
				elif p[Dot11].addr2 == p[Dot11].addr3:		#These should be the AP mac address
					ReportId("WI", "0.0.0.0", "802.11_Deauth", "Deauthentication: client=" + p[Dot11].addr1 + " AP=" + p[Dot11].addr2, "", ([]), prefs, dests)
				else:
					ShowPacket(p, meta, "802.11 Deauth", HonorQuit, prefs, dests)
			elif p.haslayer(Dot11) and p.haslayer(Dot11Elt):
				current_element = None
				if p.haslayer(Dot11Beacon):
					current_element = p.getlayer(Dot11Beacon).payload
				elif p.haslayer(Dot11ProbeReq):
					current_element = p.getlayer(Dot11ProbeReq).payload
				elif p.haslayer(Dot11ProbeResp):
					current_element = p.getlayer(Dot11ProbeResp).payload
				elif p.haslayer(Dot11AssoReq):
					current_element = p.getlayer(Dot11AssoReq).payload
				elif p.haslayer(Dot11AssoResp):
					current_element = p.getlayer(Dot11AssoResp).payload
				elif p.haslayer(Dot11Auth):
					if p[Dot11Auth].status == 0:	#success
						ReportId("WI", "0.0.0.0", "802.11_Auth", "success", "", ([]), prefs, dests)
				else:
					ShowPacket(p, meta, "802.11 Elt with unknown intermediate header", HonorQuit, prefs, dests)
				if current_element:
					while isinstance(current_element, Dot11Elt):		#Somewhat equivalent:	while not isinstance(current_element, NoPayload):
						if current_element.ID == 0 and current_element.info.strip():	#ESSID
							ReportId("WI", "0.0.0.0", "802.11 ESSID", current_element.info.strip().replace('\n', '').replace('\r', '').replace(',', ' '), "", ([]), prefs, dests)
						current_element = current_element.payload
			elif p.haslayer(Dot11) and p[Dot11].type == 0:					#0 == Management
				UnhandledPacket(p, prefs, dests)
			elif p.haslayer(Dot11) and p[Dot11].type == 1:					#1 == Control
				UnhandledPacket(p, prefs, dests)
			elif p.haslayer(Dot11) and p[Dot11].type == 2 and p.haslayer(LLC):		#2 == Data
				UnhandledPacket(p, prefs, dests)
			elif p.haslayer(Dot11) and p[Dot11].type == 2 and p.haslayer(Dot11WEP):		#2 == Data
				ReportId("WI", "0.0.0.0", "802.11 WEP", "", "", ([]), prefs, dests)
			elif p.haslayer(Dot11):
				ShowPacket(p, meta, "802.11", HonorQuit, prefs, dests)
				UnhandledPacket(p, prefs, dests)
			else:
				UnhandledPacket(p, prefs, dests)
		elif p.haslayer(Raw):
			#Sample payload from Mac lo0 packet:   \x02\x00\x00\x00E\x00\x00   Hack; strip off first 4 bytes and interpret the rest as IP.
			encap_packet_raw = None
			if p[Raw].load[0:6] in two_prelude_ip_start:
				encap_packet_raw = p[Raw].load[4:]
			if encap_packet_raw:
				encap_packet = IP(encap_packet_raw)
				processpacket(encap_packet)
			else:
				ShowPacket(p, meta, "Non-ethernet raw does not appear to have E\x00\x00", HonorQuit, prefs, dests)
		else:
			UnhandledPacket(p, prefs, dests)
		#ShowPacket(p, meta, "packet has no ethernet layer", HonorQuit, prefs, dests)
	elif p[Ether].type == 0x4860:		#18528: ?
		UnhandledPacket(p, prefs, dests)
	elif p[Ether].type == 0x6002:		#24578: MOP Remote Console
		UnhandledPacket(p, prefs, dests)
	elif p[Ether].type == 0x8001:		#32769: ?
		UnhandledPacket(p, prefs, dests)
	elif p[Ether].type == 0x8035:		#32821: Reverse ARP https://en.wikipedia.org/wiki/Reverse_Address_Resolution_Protocol
		UnhandledPacket(p, prefs, dests)
	elif p[Ether].type == 0x8100:		#33024 = IEEE 802.1Q VLAN-tagged frames (initially Wellfleet)
		UnhandledPacket(p, prefs, dests)
	elif p[Ether].type == 0x872D:		#34605 ?
		UnhandledPacket(p, prefs, dests)
	elif p[Ether].type == 0x8809:		#34825 LACP (builds multiple links into a trunk)
		UnhandledPacket(p, prefs, dests)
	elif p[Ether].type == 0x888E:		#34958 EAPOL, EAP over LAN (IEEE 802.1X)
		UnhandledPacket(p, prefs, dests)
	elif p[Ether].type == 0x8899:		#34969 Unknown
		UnhandledPacket(p, prefs, dests)
	elif p[Ether].type == 0x88A2:		#34978 ATA over ethernet
		UnhandledPacket(p, prefs, dests)
	elif p[Ether].type == 0x88A7:		#34983 Unknown
		UnhandledPacket(p, prefs, dests)
	elif p[Ether].type == 0x88CC:		#35020 LLDP Link Layer Discovery Protocol
		UnhandledPacket(p, prefs, dests)
	elif p[Ether].type == 0x88E1:		#35041 HomePlug AV MME
		UnhandledPacket(p, prefs, dests)
	elif p[Ether].type == 0x8912:		#35090 unknown
		UnhandledPacket(p, prefs, dests)
	elif p[Ether].type == 0x9000:		#36864 = Ethernet loopback protocol.  http://wiki.wireshark.org/Loop
		UnhandledPacket(p, prefs, dests)
	else:
		ShowPacket(p, meta, "Unregistered ethernet type:" + str(p[Ether].type), HonorQuit, prefs, dests)
		#For a good reference on new ethernet types, see:
		#http://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
		#http://www.iana.org/assignments/ethernet-numbers
		#http://en.wikipedia.org/wiki/EtherType


#======== Start of main code. ========
if __name__ == "__main__":
	import argparse

	#List of IP addresses that should never be tagged as suspicious
	if "TrustedIPs" not in __main__.__dict__:
		__main__.TrustedIPs = load_json_from_file(trusted_ips_file)
		if not __main__.TrustedIPs:
			sys.stderr.write("Problem reading/parsing " + trusted_ips_file + ", setting to default list.\n")
			sys.stderr.flush
			__main__.TrustedIPs = default_trusted_ips
			#write_object(trusted_ips_file, json.dumps(__main__.TrustedIPs))

	signal.signal(signal.SIGINT, signal_handler)

	parser = argparse.ArgumentParser(description='Passer version ' + str(passerVersion))
	input_options = parser.add_mutually_exclusive_group()
	input_options.add_argument('-i', '--interface', help='Interface from which to read packets (default is all interfaces)', required=False, default=None)
	#input_options.add_argument('-r', '--read', help='Pcap file(s) from which to read packets (use   -   for stdin)', required=False, default=[], nargs='*')	#Not supporting stdin at the moment
	input_options.add_argument('-r', '--read', help='Pcap file(s) from which to read packets', required=False, default=[], nargs='*')
	parser.add_argument('-l', '--log', help='File to which to write output csv lines', required=False, default=None)
	parser.add_argument('-s', '--suspicious', help='File to which to write packets to/from suspicious IPs', required=False, default=None)
	parser.add_argument('-u', '--unhandled', help='File to which to write unhandled packets', required=False, default=None)
	parser.add_argument('--acks', help=argparse.SUPPRESS, required=False, default=False, action='store_true')							#Left in to allows calling scripts to continue to work, not used.  Old help: 'Save unhandled ack packets as well'
	parser.add_argument('-d', '--devel', help='Enable development/debug statements', required=False, default=False, action='store_true')
	parser.add_argument('-q', '--quit', help='With -d, force passer to quit when debug packets are shown', required=False, default=False, action='store_true')
	parser.add_argument('--nxdomain', help='Show NXDomain DNS answers', required=False, default=False, action='store_true')
	parser.add_argument('--creds', help='Show credentials as well', required=False, default=False, action='store_true')
	parser.add_argument('-b', '--bpf', help='BPF to restrict which packets are processed', required=False, default='')
	parser.add_argument('--timestamp', help='Show timestamp and time string in 6th and 7th fields', required=False, default=False, action='store_true')
	parser.add_argument('--debuglayers', required=False, default=False, action='store_true', help=argparse.SUPPRESS)						#Debug scapy layers, hidden option
	(parsed, unparsed) = parser.parse_known_args()
	cl_args = vars(parsed)


	debug_known_layer_lists = cl_args['debuglayers']

	if cl_args['bpf']:
		if len(unparsed) > 0:
			sys.stderr.write('Too many arguments that do not match a parameter, exiting.\n')
			quit()
	else:
		if len(unparsed) == 0:
			cl_args['bpf'] = ''
		elif len(unparsed) == 1:
			cl_args['bpf'] = str(unparsed[0])
		else:
			sys.stderr.write('Too many arguments that do not match a parameter.  Any chance you did not put the bpf expression in quotes?  Exiting.\n')
			quit()

	InterfaceName = cl_args['interface']
	#Not currently used - all blocks that would use this have been commented out.
	#SaveUnhandledAcks = cl_args['acks']
	ShowCredentials = cl_args['creds']									#If True , we'll include passwords in the output lines.  At the time of this writing, only the snmp community string is logged when True

	destinations = {}					#Do we need destinations at all, or could we just use cl_args?
	destinations['unhandled'] = cl_args['unhandled']
	destinations['suspicious'] = cl_args['suspicious']

	debug_out("Passer version " + str(passerVersion), cl_args, destinations)

	if not os.path.exists(config_dir):
		os.makedirs(config_dir)

	if not has_advanced_ntp_headers:
		debug_out('The version of scapy on your system does not appear to be new enough to include advanced NTP processing.  If possible, please upgrade scapy.', cl_args, destinations)

	debug_out("BPFilter is " + cl_args['bpf'], cl_args, destinations)
	#Hmmm, setting bpf appears not to work.  It loads correctly into the variable, but the sniff command appears to ignore it.



	#To set scapy options:
	#conf.verb = 0
	#conf.iface = 'eth1'			#Default: every interface
	#conf.nmap_base  = '/usr/share/nmap/nmap-os-fingerprints'
	#conf.p0f_base   = '/etc/p0f.fp'
	#conf.promisc = 1

	try:
		conf.sniff_promisc = 1
	except:
		config.sniff_promisc = 1

	#Neither this nor adding "filter=cl_args['bpf']" to each sniff line seems to actually apply the bpf.  Hmmm.
	try:
		conf.filter = cl_args['bpf']
	except:
		config.filter = cl_args['bpf']

	#if exit_now:
	#	quit(1)


	#read_from_stdin = False		#If stdin requested, it needs to be processed last, so we remember it here.  We also handle the case where the user enters '-' more than once by simply remembering it.

	#if cl_args['interface'] is None and cl_args['read'] == []:
		#debug_out("No source specified with -i or -r, exiting.", cl_args, destinations)
		#quit(1)
		#debug_out('No source specified, reading from stdin.', cl_args, destinations)
		#read_from_stdin = True


	#Process normal files first
	for PcapFilename in cl_args['read']:
		work_filename = None
		delete_temp = False

		if not PcapFilename:
			debug_out("Skipping empty filename.", cl_args, destinations)
		elif PcapFilename == '-':
			#read_from_stdin = True
			debug_out("Unable to read from stdin, exiting.", cl_args, destinations)
			quit(1)
		elif not os.path.exists(PcapFilename):
			debug_out("No file named " + str(PcapFilename) + ", skipping.", cl_args, destinations)
		elif not os.access(PcapFilename, os.R_OK):
			debug_out(str(PcapFilename) + " is unreadable, skipping.", cl_args, destinations)
		#By this point we have an existing, readable, non-empty, non-stdin file.  Now check to see if we need to decompress it, and finally process the pcap file.
		elif PcapFilename.endswith('.bz2'):
			work_filename = open_bzip2_file_to_tmp_file(PcapFilename)
			delete_temp = True
		elif PcapFilename.endswith('.gz'):
			work_filename = open_gzip_file_to_tmp_file(PcapFilename)
			delete_temp = True
		else:		#File exists and is neither a bzip2 file nor a gzip file.  Process as is.
			work_filename = PcapFilename


		if work_filename:
			if False:					#New scapy "stopper" feature to exit if needed; doesn't work yet, disabled.
				#https://github.com/secdev/scapy/wiki/Contrib:-Code:-PatchSelectStopperTimeout
				sniff(store=0, offline=work_filename, filter=cl_args['bpf'], stopperTimeout=5, stopper=exit_now, prn=lambda x: processpacket(x))
			elif False:					#Old scapy "stop_filter" feature to exit if needed; doesn't work yet, disabled.
				sniff(store=0, offline=work_filename, filter=cl_args['bpf'], stop_filter=exit_now_packet_param, prn=lambda x: processpacket(x))
			else:						#No attempt to exit sniff loop for the moment.
				sniff(store=0, offline=work_filename, filter=cl_args['bpf'], prn=lambda x: processpacket(x))

		if delete_temp and work_filename != PcapFilename and os.path.exists(work_filename):
			os.remove(work_filename)


	#Now that we've done all files, sniff from a specific interface.
	if InterfaceName:
		if False:						#New scapy "stopper" feature to exit if needed; doesn't work yet, disabled.
			#https://github.com/secdev/scapy/wiki/Contrib:-Code:-PatchSelectStopperTimeout
			sniff(store=0, iface=InterfaceName, filter=cl_args['bpf'], stopperTimeout=5, stopper=exit_now, prn=lambda x: processpacket(x))
		elif False:						#Old scapy "stop_filter" feature to exit if needed; doesn't work yet, disabled.
			sniff(store=0, iface=InterfaceName, filter=cl_args['bpf'], stop_filter=exit_now_packet_param, prn=lambda x: processpacket(x))
		else:							#No attempt to exit sniff loop for the moment.
			sniff(store=0, iface=InterfaceName, filter=cl_args['bpf'], prn=lambda x: processpacket(x))


	#If the user didn't specify any files or interfaces to read from, read from all interfaces.
	if not InterfaceName and cl_args['read'] == []:
		if False:						#New scapy "stopper" feature to exit if needed; doesn't work yet, disabled.
			#https://github.com/secdev/scapy/wiki/Contrib:-Code:-PatchSelectStopperTimeout
			sniff(store=0, filter=cl_args['bpf'], stopperTimeout=5, stopper=exit_now, prn=lambda x: processpacket(x))
		elif False:						#Old scapy "stop_filter" feature to exit if needed; doesn't work yet, disabled.
			sniff(store=0, filter=cl_args['bpf'], stop_filter=exit_now_packet_param, prn=lambda x: processpacket(x))
		else:							#No attempt to exit sniff loop for the moment.
			sniff(store=0, filter=cl_args['bpf'], prn=lambda x: processpacket(x))

	#To limit to the first 500 packets, add ", count=500" at the end of the "sniff" command inside the last paren


	generate_summary_lines()

	#Only write out if changes have been made (if no changes have been made, no point in writing the dictionary out).  To test this, see if there are any entries in ReportId.NewSuspiciousIPs.
	if "NewSuspiciousIPs" in ReportId.__dict__ and ReportId.NewSuspiciousIPs:					#Cross-function variable
		#If NewSuspiciousIPs has been initialized, so has SuspiciousIPs; no need to test for it.

		#We may be in a situation where two copies of this program running at the same time may both have changes to write.  Just before writing this out, we re-read the on-disk version to pull in any changes made by other copies that finished before us.
		SuspiciousIPs_at_end = load_json_from_file(suspicious_ips_file)
		if SuspiciousIPs_at_end:
			for one_trusted in __main__.TrustedIPs:
				if one_trusted in SuspiciousIPs_at_end:
					del SuspiciousIPs_at_end[one_trusted]

			#Now we copy all entries from the on-disk version (which may contain more than we originally read) into ReportId.SuspiciousIPs just before writing it back out.
			for one_ip in SuspiciousIPs_at_end:
				if one_ip not in ReportId.SuspiciousIPs:				#Cross-function variable
					ReportId.SuspiciousIPs[one_ip] = []				#Cross-function variable
				for one_warning in SuspiciousIPs_at_end[one_ip]:
					if one_warning not in ReportId.SuspiciousIPs[one_ip]:		#Cross-function variable
						ReportId.SuspiciousIPs[one_ip].append(one_warning)	#Cross-function variable

		#Yes, this is shaky and still has race conditions.  It's worse than using a database, and better than doing nothing at all.  Worst case we lose some entries from one of the copies.
		write_object(suspicious_ips_file, json.dumps(ReportId.SuspiciousIPs))		#Cross-function variable

	if "start_stamp" in processpacket.__dict__ and "start_string" in processpacket.__dict__ and "end_stamp" in processpacket.__dict__ and "end_string" in processpacket.__dict__:	#Cross-function variable
		#FIXME - move to just after sniffing done for a given source and add up the deltas into a cumulative time for all captures.
		if processpacket.start_stamp and processpacket.end_stamp:														#Cross-function variable
			pcap_delta = processpacket.end_stamp - processpacket.start_stamp												#Cross-function variable
			#FIXME - switch to "verbose", and look for others like versions
			debug_out("The packets processed ran from " + processpacket.start_string + " to " + processpacket.end_string + " for " + str(pcap_delta) + " seconds.", cl_args, destinations)	#Cross-function variable
		else:
			debug_out("It does not appear the start and end stamps were set - were any packets processed?", cl_args, destinations)
