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
import tempfile		#Used in processing compressed files
import gzip		#Lets us read gzip compressed files
import bz2		#Lets us read bzip2 compressed files
import signal		#For catching Ctrl-C
import string		#Needed for python 2.5.2?
import warnings		#Needed for p0f?
import unicodedata	#Needed for removing control characters
import pytz

#This may be too restrictive.
#from scapy import sniff, p0f, sr1, IP, ICMP, IPerror, TCPerror, UDPerror, ICMPerror

try:
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


#Following does not help with 'IndexError: Layer [Raw.load] not found'
#from scapy.packet import Raw

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





#Commented out p0f as it's not working at the moment
#load_module("p0f")


#======== Global arrays ========
#These two are used to discover servers.  If we've seen a SYN go to a port, and a SYN/ACK back from it,
#that's a pretty good sign it's a server.  Not truly stateful, but a generally good guess.
SynSentToTCPService = {}	#Boolean dictionary: Have we seen a syn sent to this "IP,Proto_Port" pair yet?
LiveTCPService = {}		#Boolean dictionary: Have we seen a SYN/ACK come back (true) or a RST (False) from this "IP,Proto_Port" pair?

#Next two are used to discover clients.  If we've seen a SYN/ACK going to what appears to be a client port, and it
#later responds with a FIN, we'll call that a live TCP client.
SynAckSentToTCPClient = {}	#Boolean dictionary: Have we seen a SYN/ACK sent to this "IP,Proto_Port" pair yet?
LiveTCPClient = {}		#Boolean dictionary: Have we seen a FIN from this client, indicating a 3 way handshake and successful conversation?

NmapServerDescription = {}	#String dictionary: What server is this "IP,Proto_Port" pair?  These descriptions come from nmap-service-probes.
ManualServerDescription = {}	#Same as above, but locally found strings
ClientDescription = {}		#String dictionary: What client is on this "IP,Proto_Port"?  NOTE: the port here is the _server_ port at the other end.  So if
				#Firefox on 1.2.3.4 is making outbound connections to port 80 on remote servers, ClientDescription['1.2.3.4,TCP_80'] = "http/firefox"

				#Dictionary of Dictionaries of sets, replaces the specific dictionaries.  First key is 2 letter record type, second key is IP address, final value (a set) is what we have seen for that record type and IP.
GenDesc = {'DN': {}, 'IP': {}, 'MA': {}, 'NA': {}, 'PC': {}, 'PS': {}, 'RO': {}, 'TC': {}, 'TS': {}, 'UC': {}, 'US': {}}


MacAddr = {}			#String dictionary: For a given IP (key), what is its mac (value)?  This is only queried and set in ReportId
EtherManuf = {}			#String dictionary: for a given key of the first three uppercase octets of a mac address ("00:01:0F"), who made this card?

DNSRecord = {}			#Dictionary of arrays of strings: For a given key of IPAddr,'A' or IPAddr,'PTR', what are it's corresponding hostname(s) (stored in an array)?

HostIPs = {}			#Dictionary of arrays: For a given fully qualified hostname, what IPs (array) are associated?

ServiceFPs = {}			#Dictionary of service fingerprints.  Keys are straight int port numbers (no TCP or UDP), or 'all' for strings that need
				#to be matched against all ports.  These are loaded from nmap's "nmap-service-probes", ignoring the probes since we're passive.
				#Values are lists of tuples, ala: [("Apache *server ready.", "Apache web"), ("VSFTPD FTP at your service", "vsftpd ftp")]
				#Note that the first object in a tuple is a _compiled regex_ rather than the printable strings I've used above.
				#A sample (non-compiled) version looks like:  {80: [('^Server: Apache/', 'http/apachewebserver')]}


SuspiciousIPs = {}		#Dictionary of lists.  Key is IP address, value is list which contains all this IP address' suspicious characteristics.
NewSuspiciousIPs = {}		#Just like above, but _only_ the entries added during this session; used for printing with ctrl-c or at the end.
TrustedIPs = []			#List of IP addresses that should never be tagged as suspicious

ClosedPortsReceived = {}	#Dictionary of sets.  Key is expanded IP address, value is a set of "IP,Proto_Port" strings that sent back "closed".  High counts of these are systems that are scanning for ports.

				#UDP ports banned by policy.  May wish to do the entire range from 0 to 21 inclusive.
				#Perhaps add 161: snmp and solaris in.routed 520.
PolicyViolationUDPPorts = {'7': 'echo', '9': 'discard', '11': "sysstat", '13': 'daytime', '17': "qotd", '19': 'chargen', '69': 'tftp'}
				#TCP ports banned by policy.  May wish to do the entire range from 0 to 19 inclusive.
PolicyViolationTCPPorts = {'7': 'echo', '9': 'discard', '11': "sysstat", '13': 'daytime', '17': "qotd", '19': 'chargen', '23': 'telnet', '79': 'finger', "512": "rexec", "513": "rlogin", "514": "rsh_rcp"}
				#Some ports in PriUDPPortNames and SecUDPPortNames need warnings attached to them - list them and their warning here.
udp_port_warnings = {'13': 'small', '17': 'small', '1194': 'tunnel', '1701': 'tunnel', '1723': 'tunnel', '4500': 'tunnel', '8080': 'tunnel'}

botnet_warning_list = {}	#Dictionary of "IP,proto_port": ['warning1', 'warning2'] entries that say if you see that trio, that IP should get this/these warnings.
				#If we see syn/ack coming back from tcp C&C's, tag the host as 'bot_candc' and the dest IP of the syn/ack as 'bot'
				#For UDP, just use any data heading _to_ the CandC to tag both ends (source is 'bot', dest os 'bot_candc')
				#FIXME - implement


must_stop = False		#Set to true if exit requested by signal

#======== Constants ========
KeepGoing = False		#Dont change this - it's an internal value to make the code more readable.  Change QuitOnShow instead.
HonorQuit = True		#Dont change this - it's an internal value to make the code more readable.  Change QuitOnShow instead.


#======== Port lists ========
#======== Following are primary ports we want to do a full report on
### IPv4/UDPv4/sunrpc=111
### IPv4/UDPv4/ldap=389
### IPv4/UDPv4/openvpn=1194		https://openvpn.net/index.php/open-source/documentation/howto.html
### IPv4/UDPv4/l2f_or_lt2p=1701
### IPv4/UDPv4/pptp=1723
### IPv4/UDPv4/biap-mp=1962
### IPv4/UDPv4/rdp=3389			https://www.rdpsoft.com/blog/remote-desktop-protocol/rdp-udp-transport-azure/
### IPv4/UDPv4/l2tp=4500		https://www.privateinternetaccess.com/helpdesk/kb/articles/what-ports-are-used-by-your-vpn-service
### IPv4/UDPv4/openvpn8080=8080		https://www.privateinternetaccess.com/helpdesk/kb/articles/what-ports-are-used-by-your-vpn-service
### IPv4/UDPv4/gotomeeting8200=8200	https://support.logmeininc.com/gotomeeting/help/optimal-firewall-configuration-g2m060010
### IPv4/UDPv4/udp8888=8888
### IPV4/UDPv4/hangouts			https://community.arubanetworks.com/t5/Security/Configuring-Network-for-Google-Hangouts/td-p/59274
PriUDPPortNames = {"88": "kerberos", "111": "sunrpc", "177": "xdmcp", "389": "ldap", "443": "udp_https", "500": "isakmp", "520": "rip", "1194": "openvpn", "1701": "l2tp1701", "1723": "pptp", "1853": "gotomeeting1853", "1962": "biap-mp", "2123": "gtp-control", "3389": "rdp", "3478": "skype3478", "3479": "skype3479", "3480": "skype3480", "3481": "skype3481", "4500": "l2tp", "6881": "bittorrent6881", "8080": "openvpn8080", "8200": "gotomeeting8200", "8888": "udp8888", "19305": "hangouts", "19306": "hangouts", "19307": "hangouts", "19308": "hangouts", "19309": "hangouts"}

#======== Following udp ports are low priority ones that we just log anyways
### IPv4/UDPv4/13    daytime		https://gkbrk.com/wiki/daytime_protocol/
### IPv4/UDPv4/17    qotd 		https://gkbrk.com/wiki/qotd_protocol/
### IPv4/UDPv4/179   bgp
### IPv4/UDPv4/445   microsoft-ds
### IPv4/UDPv4/465   igmpv3lite		https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-4015
### IPv4/UDPv4/808   omirr/omirrd	but payload looks like snmp.  Hmm.
### IPv4/UDPv4/1080  			does not appear to be used by socks
### IPv4/UDPv4/1099  rmiregistry
### IPv4/UDPv4/5093  sentinel-lm	https://www.kb.cert.org/vuls/id/108790
### IPv4/UDPv4/5094  hart-ip		https://wiki.wireshark.org/HART-IP
### IPv4/UDPv4/3128  assigned to squid, but not actually used by it
### IPv4/UDPv4/6000  lots of possibilities
### IPv4/UDPv4/8123  unknown udp8123
### IPv4/UDPv4/9987  teamspeak3-voice	https://www.speedguide.net/port.php?port=9987
### IPv4/UDPv4/17185 vxworks-debug	https://ics-cert.us-cert.gov/advisories/ICSA-10-214-01
### IPv4/UDPv4/30718 lantronix		https://www.slideshare.net/kost/vk-exploringtreasuresof77-fehlantronixconfidence2014
### IPv4/UDPv4/47808 bacnet		https://wiki.wireshark.org/Protocols/bacnet
### IPv4/UDPv4/44818 rockwell-encap	http://literature.rockwellautomation.com/idc/groups/literature/documents/qr/comm-qr001_-en-e.pdf , https://ics-cert.us-cert.gov/advisories/ICSA-13-011-03
SecUDPPortNames = {"7": "echo", "13": "daytime", "17": "qotd", "19": "chargen", "179": "bgp", "192": "osu-nms", "445": "microsoft-ds", "465": "igmpv3lite", "513": "who", "623": "asf-rmcp_or_ipmi", "808": "omirr", "1080": "udpsocks", "1099": "rmiregistry", "1500": "udp1500", "1604": "darkcomet_rat_winframe_icabrowser", "3128": "udpsquid", "3283": "udp3283", "3386": "udp3386", "4738": "udp4738", "4800": "udp4800", "5006": "udp5006", "5008": "udp5008", "5093": "sentienl-lm", "5094": "hart-ip", "5354": "mdnsresponder", "5632": "pcanywherestat", "6000": "udp6000", "6969": "acmsoda", "6970": "rtsp", "8000": "udp8000", "8123": "udp8123", "8301": "udp8301", "8302": "udp8302", "9050": "udp9050", "9600": "udp9600", "9987": "teamspeak3-voice", "16464": "udp16464", "17185": "vxworks-debug", "20000": "udp20000", "24223": "udp24223", "27960": "udp27960", "30718": "lantronix", "32015": "udp32015", "32764": "udp32764", "32770": "udp32770", "34436": "udp34436", "35950": "udp35950", "44818": "rockwell-encap", "46414": "udp46414", "47808": "bacnet", "50023": "udp50023", "51413": "transmission", "53007": "udp53007", "55020": "udp55020", "63520": "udp63520", "64211": "udp64211"}

#From 122.224.158.195, payload is "8'\x82\xd7\x8fZ\xdbc\xfe\x00\x00\x00\x00\x00"
fenull_scan_names = {"21": "udp-21", "22": "udp-22", "23": "udp-23", "25": "udp-25", "49": "udp-49", "80": "udp-80", "102": "udp-102", "110": "udp-110", "143": "udp-143", "636": "udp-636", "992": "udp-992", "993": "udp-993", "995": "udp-995"}
empty_payload_ports = ('1', '17', '19', '18895', '50174', '50597', '50902', '52498', '52576', '52620', '52775', '52956', '55180', '56089', '57347', '57563', '57694', '58034', '58153', '58861', '59024', '59413', '60463', '60799', '61016', '61651', '62473', '62915', '63137', '63556', '63571', '63878', '64727', '65154', '65251')
halflife_altport = ("1265", "2303", "20100", "21025", "21550", "27000", "27017", "27018", "27019", "27022", "27030", "27035", "27050", "27078", "27080", "28015", "28100", "45081")

#For all of the following, see if the payload contains snmp.
### IPv4/UDPv4/21 22 23 25 tacacs=49 http=80 iso-tsap=102 110 143 igmpv3lite=465 ldaps=636 omirr=808 992 993 995 client
snmp_altport = ("21", "22", "23", "25", "49", "80", "102", "110", "143", "465", "636", "808", "992", "993", "995")

sip_altport = (
               "22", "23", "80", "110",
               "1000", "1001", "1002", "1003", "1004", "1005", "1006", "1007", "1008", "1009", "1010", "1011", "1012", "1013", "1014", "1015", "1016", "1017", "1018", "1019", "1020", "1021", "1022", "1023", "1024", "1025", "1028", "1029", "1030", "1031", "1032", "1033", "1034", "1035", "1036", "1037", "1038", "1039", "1040", "1041", "1042", "1043", "1044", "1045", "1046", "1047", "1048", "1049", "1050", "1051", "1052", "1053", "1054", "1055", "1056", "1057", "1058", "1059", "1060", "1061", "1062", "1063", "1064", "1065", "1066", "1068", "1070", "1071", "1072", "1074", "1075", "1090", "1111", "1190", "1560", "1200", "1900",
               "2000", "2002", "2020", "2030", "2050", "2060", "2080", "2165", "2170", "2175", "2180", "2185", "2190", "2195", "2200", "2205", "2210", "2215", "2220", "2222", "2225", "2230", "2235", "2240", "2245", "2250", "2255", "2260", "2265", "2270", "2275", "2280", "2285", "2290", "2295", "2300", "2305", "2310", "2315", "2320", "2325", "2330", "2335", "2340", "2345", "2350", "2355", "2360", "2365", "2370", "2375", "2380", "2385", "2390", "2395", "2400", "2405", "2410", "2415", "2420", "2425", "2430", "2435", "2440", "2445", "2450", "2455", "2460", "2465", "2470", "2475", "2480", "2485", "2490", "2495", "2500", "2505", "2510", "2515", "2520", "2525", "2530", "2535", "2540", "2545", "2550", "2555", "2560", "2565", "2570", "2575", "2580", "2585", "2590", "2595", "2600", "2605", "2610", "2615", "2620", "2625", "2630", "2635", "2640", "2645", "2650", "2655", "2660",
               "3000", "3001", "3020", "3040", "3050", "3060", "3333", "3541",
               "4000", "4001", "4040", "4051", "4046", "4050", "4060", "4061", "4062", "4063", "4064", "4065", "4066", "4068", "4070", "4071", "4072", "4074", "4075", "4080", "4090", "4100", "4444", "4569", "4880",
               "5000", "5001", "5002", "5003", "5004", "5005", "5007", "5009", "5010", "5011", "5012", "5013", "5014", "5015", "5016", "5017", "5018", "5019", "5020", "5021", "5022", "5023", "5024", "5025", "5026", "5027", "5028", "5029", "5030", "5031", "5032", "5033", "5034", "5035", "5036", "5037", "5038", "5039", "5040", "5041", "5042", "5043", "5044", "5045", "5046", "5047", "5048", "5049", "5050", "5051", "5052", "5055", "5057", "5059", "5060", "5061", "5062", "5063", "5064", "5065", "5066", "5067", "5068", "5069", "5070", "5071", "5072", "5073", "5074", "5075", "5076", "5077", "5078", "5079", "5080", "5081", "5082", "5083", "5084", "5085", "5086", "5087", "5088", "5089", "5090", "5091", "5092", "5094", "5095", "5096", "5097", "5098", "5099", "5100", "5105", "5110", "5115", "5120", "5125", "5130", "5135", "5140", "5145", "5150", "5155", "5160", "5165", "5166", "5170", "5175", "5180", "5185", "5190", "5195", "5200", "5205", "5210", "5215", "5220", "5225", "5230", "5235", "5240", "5245", "5250", "5255", "5260", "5265", "5270", "5275", "5280", "5285", "5290", "5295", "5300", "5305", "5310", "5315", "5320", "5325", "5330", "5335", "5340", "5345", "5350", "5355", "5360", "5365", "5370", "5375", "5380", "5385", "5390", "5395", "5400", "5405", "5410", "5415", "5420", "5425", "5430", "5435", "5440", "5444", "5445", "5450", "5455", "5460", "5465", "5470", "5475", "5480", "5485", "5490", "5495", "5500", "5505", "5510", "5515", "5520", "5525", "5530", "5535", "5540", "5545", "5550", "5555", "5560", "5565", "5566", "5570", "5575", "5580", "5585", "5590", "5595", "5600", "5605", "5610", "5615", "5620", "5625", "5626", "5630", "5635", "5636", "5640", "5645", "5650", "5655", "5656", "5657", "5660", "5665", "5670", "5675", "5680", "5685", "5690", "5695", "5700", "5705", "5710", "5715", "5720", "5725", "5730", "5735", "5740", "5745", "5750", "5755", "5760", "5765", "5770", "5775", "5780", "5785", "5790", "5795", "5800", "5805", "5810", "5815", "5820", "5825", "5830", "5835", "5840", "5845", "5850", "5855", "5860", "5865", "5870", "5875", "5880", "5885", "5890", "5895", "5900", "5905", "5910", "5915", "5920", "5925", "5930", "5935", "5940", "5945", "5950", "5955", "5960", "5965", "5970", "5975", "5980", "5985", "5990", "5995",
               "6000", "6005", "6010", "6011", "6015", "6020", "6022", "6025", "6030", "6033", "6035", "6040", "6044", "6045", "6046", "6050", "6051", "6055", "6060", "6061", "6062", "6063", "6064", "6065", "6066", "6068", "6070", "6071", "6072", "6074", "6075", "6077", "6080", "6082", "6085", "6088", "6089", "6090", "6095", "6099", "6100", "6105", "6110", "6115", "6120", "6125", "6130", "6135", "6140", "6145", "6150", "6155", "6160", "6165", "6170", "6175", "6180", "6185", "6190", "6195", "6200", "6205", "6210", "6215", "6220", "6225", "6230", "6235", "6240", "6245", "6250", "6255", "6260", "6265", "6270", "6275", "6280", "6285", "6290", "6295", "6300", "6305", "6310", "6315", "6320", "6325", "6330", "6335", "6340", "6345", "6350", "6355", "6360", "6365", "6370", "6375", "6380", "6385", "6390", "6395", "6400", "6405", "6410", "6415", "6420", "6425", "6430", "6435", "6440", "6445", "6450", "6455", "6460", "6465", "6470", "6475", "6480", "6485", "6490", "6495", "6500", "6505", "6510", "6515", "6520", "6525", "6530", "6535", "6540", "6545", "6550", "6555", "6560", "6565", "6570", "6575", "6580", "6585", "6590", "6595", "6600", "6605", "6610", "6615", "6620", "6625", "6630", "6635", "6640", "6645", "6650", "6655", "6660", "6665", "6666", "6670", "6675", "6680", "6685", "6690", "6695", "6700", "6705", "6710", "6715", "6720", "6725", "6730", "6735", "6740", "6745", "6750", "6755", "6760", "6765", "6770", "6775", "6780", "6785", "6790", "6795", "6800", "6805", "6810", "6815", "6820", "6825", "6830", "6835", "6840", "6845", "6850", "6855", "6860", "6865", "6870", "6875", "6880", "6885", "6890", "6895", "6900", "6905", "6910", "6915", "6920", "6925", "6930", "6935", "6940", "6945", "6950", "6955", "6960", "6965", "6970", "6975", "6980", "6985",
               "7000", "7010", "7050", "7055", "7060", "7065", "7070", "7080", "7090", "7100", "7160", "7170", "7228", "7275", "7760", "7777", "7780", "7890",
               "8000", "8040", "8046", "8050", "8051", "8060", "8061", "8062", "8063", "8064", "8065", "8066", "8068", "8070", "8071", "8072", "8074", "8075", "8090", "8100", "8160", "8190", "8890",
               "9000", "9010", "9060", "9070", "9080", "9090", "9099", "9160", "9988", "9999",
               "10000", "10020", "10090", "10800", "11010", "11050", "11060", "11070", "11080", "11111", "11790", "11999", "12000", "12999", "15060", "15061", "15062", "15070", "15080", "15090", "15134", "15160", "15161", "15165", "15260", "15360", "16060", "16868", "17030", "17070", "18079", "18080", "19050", "19060",
               "20000", "21790", "22222", "24474", "25024", "25060", "25161", "25070", "25080", "25160", "25165", "25260", "25270",
               "30000", "31790", "33333", "35000", "35060", "35160", "35161", "35165", "35270", "35360", "35370", "35759",
               "40000", "40070", "41650", "44444", "45060", "45070", "45160", "45161", "45165", "45170", "45270", "45560", "45570", "45670", "45679", "45770", "45789", "45970",
               "50000", "50600", "50601", "50602", "50603", "50604", "50605", "50606", "50607", "50608", "50609", "50679", "50845", "51060", "51790", "55051", "55060", "55070", "55160", "55165", "55555", "56060", "58070", "58080",
               "60000", "65002", "65060", "65302", "65476"
              )

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
nullbyte = '00'.decode('hex')
twobyte = '02'.decode('hex')
twozero = '0200'.decode('hex')
fournulls = '00000000'.decode('hex')
fenulls = 'fe0000000000'.decode('hex')
stream_ihs_discovery_header = 'FFFFFFFF214C5FA0'.decode('hex')
www163com_payload = '03'.decode('hex') + "www" + '03'.decode('hex') + "163" + '03'.decode('hex') + "com"	#\x03www\x03163\x03com
a0_string = 'A' + nullbyte
zeroone = '0001'.decode('hex')
zerotwo = '0002'.decode('hex')
eight_fs = 'FFFFFFFF'.decode('hex')
crestron_prelude = '14000000010400030000'.decode('hex')
ip_start_bytes = '4500'.decode('hex')
two_prelude_ip_start = ('020000004500'.decode('hex'), '020000004502'.decode('hex'), '020000004510'.decode('hex'))
quake3_disconnect = 'FFFFFFFF'.decode('hex') + 'disconnect'
torrent_connection_id = '0000041727101980'.decode('hex')
ethernetip_list_identity = '6300'.decode('hex')
ntp_get_monlist = '1700032a'.decode('hex')
cacti_payload = '000100'.decode('hex') + 'cacti-monitoring-system' + '00'.decode('hex')
ubiquiti_discover = '01000000'.decode('hex')

#======== Regexes ========
SipPhoneMatch = re.compile('Contact: ([0-9-]+) <sip')
StoraHostnameMatch = re.compile('Hostname:<([a-zA-Z0-9_\.-]+)>')
SSDPLocationMatch = re.compile('LOCATION:([a-zA-Z0-9:,/_\. -]+)\r')
SSDPServerMatch = re.compile('[Ss][Ee][Rr][Vv][Ee][Rr]:([a-zA-Z0-9:,/_\. -]+)\r')
BrotherAnnounceMatch = re.compile('IP=([0-9][0-9\.]*):5492[56];IPv6=\[([0-9a-fA-F:][0-9a-fA-F:]*)\]:5492[56],\[([0-9a-fA-F:][0-9a-fA-F:]*)\]:5492[56];NODENAME="([0-9a-zA-Z][0-9a-zA-Z]*)"')
SIPFromMatch = re.compile('From:[^<]*<sip:([a-zA-Z0-9_\.-]+)@([a-zA-Z0-9:_\.-]+)[;>]')		#https://en.wikipedia.org/wiki/SIP_URI_scheme
SIPToMatch = re.compile('To:[^<]*<sip:([a-zA-Z0-9_\.-]+)@([a-zA-Z0-9:_\.-]+)[;>]')
SyslogMatch = re.compile('^<[0-9][0-9]*>[A-Z][a-z][a-z] [ 0-9][0-9] [0-2][0-9]:[0-9][0-9]:[0-9][0-9] ([^ ][^ ]*) ([^: [][^: []*)[: []')		#Match 1 is short hostname, match 2 is process name that generated the message


#======== Misc ========
#See "Reference ID (refid)" in https://www.ietf.org/rfc/rfc5905.txt
known_ntp_refs = ('1PPS', 'ACTS', 'ATOM', 'BCS', 'CDMA', 'CHU', 'CTD', 'DCF', 'DCFP', 'DCFa', 'DCFp', 'DCFs', 'GAL', 'GCC', 'GNSS', 'GOES', 'GPS', 'GPS1', 'GPSD', 'GPSm', 'GPSs', 'GOOG', 'HBG', 'INIT', 'IRIG', 'JJY', 'kPPS', 'LOCL', 'LORC', 'MRS', 'MSF', 'MSL', 'NICT', 'NIST', 'NMC1', 'NMEA', 'NTS', 'OCXO', 'ONBR', 'PPS', 'PPS0', 'PPS1', 'PTB', 'PTP', 'PZF', 'RATE', 'ROA', 'SHM', 'SLK', 'SOCK', 'STEP', 'TAC', 'TDF', 'TRUE', 'UPPS', 'USIQ', 'USNO', 'UTC', 'WWV', 'WWVB', 'WWVH', 'XMIS', 'i', 'shm0', '', None)

no_warn_name_tails = ('64-ptr.not.set.', '.adsl.', 'ptr-not-configured.cloudatcost.', '-bj-cnc.', '.ha.cnc.', 'domain.not.configured.', '.cto-go-a1k-01.', '.cust.', '.dedicated.', '.dhcp.', '.dsl.', '.fixed.', '.gnace701.', '.gnace702.', '.gnace703.', '.gnace704.', '.adsl-surfen.hetnet.', '.home.', '.hosted.', '.iplocal.', 'ipv6.', '.kdca.', '.lan.', 'localdomain.', 'localhost.', '.muc.', '.nvi.', 'hosted.by.pcextreme.', '.cust.dsl.teletu.', '.cust.vodafonedsl.')

#Can't do '.', appears to show up from legitimate servers.
#RE: 'domain.doesnt.exist.anywhereZZZZ'; this adds a second object to the tuple.  Without it, the test for '.'.endswith(tuple_below) turns into '.'.endswith(tuple_below_treated_as_string)
amplified_any_a_dnsobjs = ('067.cz.', '2soe.ru.', '30259.info.', '36088.info.', '36372.info.', '379zc.com.', '43614.info.', '53193.info.', '67252.info.', 'a.packetdevil.com.', 'aa.10781.inf.', 'aa.asd3sc.com.', 'aa.mmtac1.com.', 'aa3247.com.', 'adrenalinessss.cc.', 'ahuyehue.info.', 'babywow.co.uk.', 'basjuk.com.ru.', 'bitchgotraped.cloudns.eu.', 'bitstress.com.', 'cdnmyhost.com.', 'cheatsharez.com.', 'd.directedat.asia.', 'd6991.com.', 'datburger.cloudns.org.', 'dd0s.asia.', 'ddosforums.pw.', 'defcon.org.', 'disposableemailcheck.com.', 'dnsamplificationattacks.cc.', 'doleta.gov.', 'dqwd.ru.', 'edelion.su.', 'energystar.gov.', 'erhj.pw.', 'eschenemnogo.com.', 'evgeniy-marchenko.cc.', 'fkfkfkfa.co.uk.', 'fkfkfkfa.com.', 'fkfkfkfr.com.', 'free-google-2.cloudns.org.', 'freeinfosys.com.', 'gerdar3.ru.', 'ghmn.ru.', 'globe.gov.', 'gransy.com.', 'grappyblog.com.', 'grungyman.cloudns.org.', 'gtml2.com.', 'guessinfosys.com.', 'hackwhatlol.cc.', 'hak4umz.net.', 'hccforums.nl.', 'hizbullah.me.', 'ilineage2.ru.', 'inboot.co.', 'iorr.ru.', 'iri.so.', 'irlwinning.com.', 'jk1l.ru.', 'kiddy3233655.ru.', 'kvfn.ru.', 'la2low.cc.', 'lineage2-game.ru.', 'loo1.ru.', 'lrc-pipec.com.', 'marusiaattack.pw.', 'maximumstresser.net.', 'mydnsscan.us.', 'nf3.pw.', 'nlhosting.nl.', 'notthebestdomainintheworld.cloudns.org.', 'nukes.directedat.asia.', 'oggr.ru.', 'ohhr.ru.', 'ojjr.ru.', 'pddos.com.', 'pidarastik.ru.', 'pipcvsemnaher.com.', 'pizdaizda.com.ru.', 'pkts.asia.', 'qha.cc.', 'qww1.ru.', 'reanimator.in.', 'saveroads.ru.', 'sheshows.com.', 'siska1.com.', 'stellolstel.cc.', 'stopdrugs77.com.', 'supermegatrue.mcdr.ru.', 'svist21.cz.', 'thebestdomainintheworld.cloudns.eu.', 'theswat.net.', 'txt.fwserver.com.ua.', 'uzuzuu.ru.', 'viareality.cz.', 'wradish.com.', 'www.jrdga.info.', 'xcqv.de.', 'zaikapaika.com.', 'zong.zong.co.ua.', 'f.directedat.asia.')
amplified_any_a_rrsig_dnsobjs = ('1rip.com.', 'domain.doesnt.exist.anywhereZZZZ')
amplified_any_aaaa_txt_dnsobjs = ('bfhmm.com.', 'domain.doesnt.exist.anywhereZZZZ')
amplified_any_dnskey_dnsobjs = ('org.', 'domain.doesnt.exist.anywhereZZZZ')
amplified_any_dnskey_ds_rrsig_dnsobjs = ('fca.gov.', 'rose-hulman.edu.')
amplified_any_dnsobjs = ('0day.com.', '0day.net.', '4fwhk.com.', 'access-board.gov.', 'activum.nu.', 'aids.gov.', 'anaheim.cz.', 'anonsc.com.', 'azmx.ru.', 'bangtest.zong.co.ua.', 'biz.', 'census.gov.', 'cockblock.pw.', 'commerce.gov.', 'cpsc.gov.', 'darkyu.org.', 'ddos.cat.', 'directedat.asia.', 'doc.gov.', 'dongs.directedat.asia.', 'downboot.xyz.', 'eda.gov.', 'eftps.gov.', 'edu.za.', 'energy.gov.', 'fema.gov.', 'fkfkfkfb.org.', 'fkfkfkfc.biz.', 'formality.directedat.asia.', 'fr.', 'ghmn.ru.', 'globe.gov.', 'grungyman.cloudns.org.', 'hajjamservices.us.', 'hoffmeister.be.', 'hoffmeister.br.', 'hrsa.gov.', 'ic3.gov.', 'isc.org.', 'krasti.us.', 'kth.se.', 'lalka.com.ru.', 'leth.cc.', 'lounge.pw.', 'magas.bslrpg.com.', 'maritim.go.id.', 'mz.gov.pl.', 'nccih.nih.gov.', 'nrc.gov.', 'packetdevil.com.', 'paypal.co.uk.', 'pigedit.com.', 'psg.com.', 'r16.l2exzor.ru.', 'ripe.net.', 'sandia.gov.', 'scandns.tk.', 'se.', 'sema.cz.', 'seznam.cz.', 'srvit.org.', 't.pbub.info.', 'teste.bslrpg.com.', 'usadf.gov.', 'verisign.com.', 'wapa.gov.', 'webpanel.sk.')
amplified_any_domains = ('paypalobjects.com.', 'domain.doesnt.exist.anywhereZZZZ')
amplified_any_ds_dnsobjs = ('ietf.org.', 'domain.doesnt.exist.anywhereZZZZ')
amplified_any_ns_dnsobjs = ('domenamocy.pl.', 'vlch.net.')		#Can't put '.' in for NS; there appear to be legitimate queries for it.
amplified_any_txt_dnsobjs = ('1x1.cz.', 'admin.blueorangecare.com.', 'admin.gull.ca.', 'amp.crack-zone.ru.', 'bmw.digmehl.cu.cc.', 'cmiui.com.', 'etk.heckbro.cu.cc.', 'non.digmehl.cu.cc.', 't4.deparel.com.', 'txt.pwserver.com.ua.', 'txt409.tekjeton.com.', 'x.mpnp.info.', 'x.privetrc.com.', 'x.slnm.info.', 'x.xipzersscc.com.', 'ym.rctrhash.com.', 'zzgst.com.')
unamplified_any_domains = ('in-addr.arpa.', 'ip6.arpa.', 'local.', 'rob.stearns.org.', 'stearns.org.', 'tourdesigns.com.', 'tourdesignsinc.com.')
unsure_any_domains = ()

botnet_domains = ('ddos.cat.')
botnet_hosts = ('magnesium.ddos.cat.')

config_dir = os.path.expanduser('~/.passer/')

suspicious_ips_file = config_dir + '/suspicious_ips.json'
trusted_ips_file = config_dir + '/trusted_ips.json'

#For my internal use to look for new service strings
#This payload logging is disabled when Devel == False
#Quite likely a security risk, I don't recommend enabling it.
ServerPayloadDir = '/var/tmp/passer-server/'
ClientPayloadDir = '/var/tmp/passer-client/'

min_closed_ports_for_scanner = 20	#If an IP gets RSTs or unreachables to at least this many unique IP/transport/port combinations, call it a scanner.
include_udp_errors_in_closed_ports = False	#If True, we look at unreachables and other ICMP errors for UDP ports in the "closed_ports" array; if False, we don't (and only count TCP RST's)

debug_known_layer_lists = False


start_stamp = None			#These 4 hold the seconds_since_the_epoch and human readable UTC versions of the earliest and latest packets
start_string = ''
end_stamp = None
end_string = ''


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

passerVersion = "2.62"


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

	Debug("exit_now called")

	return must_stop


def exit_now_packet_param(one_packet_param):
	"""Returns true if exit was requested.  Checks global must_stop, which is set in signal_handler.  Packet handed to us is ignored."""

	#Debug("exit_now_packet_param called")

	return must_stop


def generate_summary_lines():
	"""Print any remaining lines, generally ones that are stored but not a direct result of a packet."""

	#This comes first because it may add 'scan' to the suspicious characteristics list for one or more IPs, which will be printed by the next loop.
	for an_ip in sorted(ClosedPortsReceived):
		if len(ClosedPortsReceived[an_ip]) >= min_closed_ports_for_scanner:
			ReportId("IP", an_ip, "IP", "suspicious", 'Scanned ' + str(len(ClosedPortsReceived[an_ip])) + ' closed ports.', (['scan']))

	for an_ip in sorted(NewSuspiciousIPs):
		ReportId("IP", an_ip, "IP", "suspicious", 'Warnings:' + ':'.join(NewSuspiciousIPs[an_ip]), ([]))

	return


def Debug(DebugStr):
	"""Prints a note to stderr"""
	if Devel != False:
		sys.stderr.write(DebugStr + '\n')


def ShowPacket(orig_packet, banner_string, quit_override_preference):
	"""In development mode, displays details about an unknown packet, and exits if QuitOnShow (user param) is True."""
	UnhandledPacket(orig_packet)

	if Devel != False:
		Debug("======== " + str(banner_string))
		try:
			Debug(str(orig_packet.show(dump=True)))
		except TypeError:					#On older versions of scapy (<= 2.2.0) TypeError: show() got an unexpected keyword argument 'dump'
			Debug(str(orig_packet.show()))
		ls(orig_packet)						#This one's still spitting to stdout, not sure how to redirect to stderr
		Debug(str(orig_packet.answers))
		Debug("Packet type: " + str(type(orig_packet)))
		if quit_override_preference and QuitOnShow:		#quit_override_preference is either KeepGoing == false or HonorQuit == True
			quit()


def remove_control_characters(s):
	"""Strip out any control characters in the string."""

	return "".join(ch for ch in unicode(s) if unicodedata.category(ch)[0] != "C")


def packet_timestamps(pt_p):
	"""This returns the timestamp in (floating point) seconds-since-the-epoch and (string) UTC human readable formats."""

	p_timestamp = pt_p.time					#packet.time can be read from an existing packet or written to a created packet.
	p_seconds_since_epoch = float(time.mktime(datetime.fromtimestamp(p_timestamp).timetuple()))
	#Debug(str(p_seconds_since_epoch))

	p_human_readable_utc = datetime.fromtimestamp(p_seconds_since_epoch, tz=pytz.utc).strftime('%Y-%m-%d %H:%M:%S')	#This shows UTC
	#Debug(p_human_readable)

	#Not used at the moment.
	#p_human_readable_localtz = datetime.fromtimestamp(p_timestamp).strftime('%Y-%m-%d %H:%M:%S')
	#Debug(p_human_readable_localtz)	#This is the human readable timestamp in local time

	return (p_seconds_since_epoch, p_human_readable_utc)


def open_bzip2_file_to_tmp_file(bzip2_filename):
	"""Open up a bzip2 file to a temporary file and return that filename."""

	tmp_fd, tmp_path = tempfile.mkstemp()
	try:
		with os.fdopen(tmp_fd, 'wb') as tmp_h, bz2.BZ2File(bzip2_filename, 'rb') as compressed_file:
			for data in iter(lambda: compressed_file.read(100 * 1024), b''):
				tmp_h.write(data)
		return tmp_path
	except:
		sys.stderr.write("While expanding bzip2 file, unable to write to " + str(tmp_path) + ', exiting.\n')
		raise


def open_gzip_file_to_tmp_file(gzip_filename):
	"""Open up a gzip file to a temporary file and return that filename."""

	tmp_fd, tmp_path = tempfile.mkstemp()
	try:
		with os.fdopen(tmp_fd, 'wb') as tmp_h, gzip.GzipFile(gzip_filename, 'rb') as compressed_file:
			for data in iter(lambda: compressed_file.read(100 * 1024), b''):
				tmp_h.write(data)
		return tmp_path
	except:
		sys.stderr.write("While expanding gzip file, unable to write to " + str(tmp_path) + ', exiting.\n')
		raise


##FIXME - remove this function
#def LogNewPayload(PayloadDir, PayloadFile, Payload):
#	"""Saves the payload from an ack packet to a file named after the server or client port involved."""
#
#	#Better yet, wrpcap("/path/to/pcap", list_of_packets)
#
#	if Devel:
#		if os.path.isdir(PayloadDir):
#			if not Payload == "None":
#				pfile = open(PayloadFile, 'a')
#				pfile.write(Payload)
#				pfile.close()


def UnhandledPacket(up_packet):
	"""Save packets that have not been (completely) processed out to a pcap file for later analysis."""

	global UnhandledFile

	if UnhandledFile is not None:
		UnhandledFile.write(up_packet)


def SuspiciousPacket(sp_packet):
	"""Save packets that are to/from a suspicious IP out to a pcap file for later analysis."""

	global SuspiciousFile

	if SuspiciousFile is not None:
		SuspiciousFile.write(sp_packet)


def write_object(filename, generic_object):
	"""Write out an object to a file."""

	with open(filename, "wb") as write_h:
		write_h.write(generic_object)

	return

def LoadMacData(MacFile):
	"""Load Ethernet Mac address prefixes from standard locations (from ettercap, nmap, wireshark, and/or arp-scan)."""
	global EtherManuf

	More = ''
	if EtherManuf:
		More = ' more'

	LoadCount = 0

	if os.path.isfile(MacFile):
		try:
			MacHandle = open(MacFile, 'r')

			for line in MacHandle:
				if (len(line) >= 8) and (line[2] == ':') and (line[5] == ':'):
					#uppercase incoming strings just in case one of the files uses lowercase
					MacHeader = line[:8].upper()
					Manuf = line[8:].strip()
					if MacHeader not in EtherManuf:
						EtherManuf[MacHeader] = Manuf
						LoadCount += 1
				elif (len(line) >= 7) and (re.search('^[0-9A-F]{6}[ \t]', line) is not None):
					MacHeader = str.upper(line[0:2] + ':' + line[2:4] + ':' + line[4:6])
					Manuf = line[7:].strip()
					if MacHeader not in EtherManuf:
						EtherManuf[MacHeader] = Manuf
						LoadCount += 1

			MacHandle.close()
			if '00:00:00' in EtherManuf:
				del EtherManuf['00:00:00']		#Not really Xerox
				LoadCount -= 1
			Debug(str(LoadCount) + More + " mac prefixes loaded from " + str(MacFile))
			return True
		except:
			Debug("Unable to load " + str(MacFile))
			return False
	else:
		Debug("Unable to load " + str(MacFile))
		return False




def LoadNmapServiceFP(ServiceFileName):
	"""Load nmap fingerprints from nmap-service-probes, usually in /usr/share/nmap."""

	#File format details at http://nmap.org/vscan/vscan-fileformat.html

	global ServiceFPs

	LoadCount = 0
	CompileSuccess = 0
	CompileFail = 0
	PortArray = []

	if os.path.isfile(ServiceFileName):
		try:
			ServiceHandle = open(ServiceFileName, "r")
			for line in ServiceHandle:
				if (len(line) >= 5) and (line[0:6] == "Probe "):
					#print "==== PROBE ===="
					PortArray = []
					#print len(PortArray), PortArray			#len of empty array is 0
				elif (len(line) >= 5) and (line[0:6] == "match "):
					#print "match"
					#print line
					InformationPresent = True
													#Sample line:
													#  match srun m|^X\0\0\0$| p/Caucho Resin JSP Engine srun/
					Remainder = line[6:].strip()					#  srun m|^X\0\0\0$| p/Caucho Resin JSP Engine srun/
					MatchStart = Remainder.find(" m")				#      4
					ProtoString = Remainder[:MatchStart].replace(',', ';')		#  srun
					#At the moment, nmap-service-probes uses these separators:
					#3 m%, 2 m+, 126 m/, 29 m=, 2 m@, and 3509 m|
					#No flags on %, +,
					#Only flags should be "i" (case-insensitive) and "s" ("." can match newline)
					Separator = Remainder[MatchStart+2:MatchStart+3]		#        |
					MatchEnd = Remainder.find(Separator, MatchStart+3)		#                  16
					MatchString = Remainder[MatchStart+3:MatchEnd]			#         ^X\0\0\0$

					#Handle an "i" or "s" flag after separator
					#Debug("==== " + Remainder[MatchEnd+1:MatchEnd+4])
					if MatchEnd + 1 == len(Remainder):
						InformationPresent = False
						#Debug("No information data for " + MatchString)
					elif Remainder[MatchEnd+1:MatchEnd+2] == " ":
						PPointer = MatchEnd + 2
						MatchFlags = re.M
						#Debug(Remainder + ", no flags")
					elif Remainder[MatchEnd+1:MatchEnd+3] == "i ":
						PPointer = MatchEnd + 3
						MatchFlags = re.M | re.I
						#Debug(Remainder + ", i flag")
					elif Remainder[MatchEnd+1:MatchEnd+3] == "s ":
						PPointer = MatchEnd + 3
						MatchFlags = re.M | re.S
						#Debug(Remainder + ", s flag")
					elif (Remainder[MatchEnd+1:MatchEnd+4] == "is ") or (Remainder[MatchEnd+1:MatchEnd+4] == "si "):
						PPointer = MatchEnd + 4
						MatchFlags = re.M | re.I | re.S
						#Debug(Remainder + ", i and s flag")
					#Following lines commented out as they're only needed for development
					#else:
					#	Debug("Unrecognized nmap-service-probes flag combination")
					#	Debug(str(MatchEnd + 1) + " " + str(len(Remainder)))
					#	Debug(Remainder + ", unknown flags")
					#	#quit()

					#Substitute ; for , in ProtoString and ServerDescription since we're using commas as field delimiters in output
					ServerDescription = Remainder[PPointer:].replace(',', ';')	#                    p/Caucho Resin JSP Engine srun/

					#The nmap-service-probes file uses a character set ("[...]") issue that python doesn't like.
					#If a "-" is used inside a character set, it should either be in the first or last position,
					#or used in a character range ("[.....a-z.....]").  The following move any dashes to first or
					#last position so re.compile is happy.
					MatchString = MatchString.replace("[\w-", "[-\w")		#The dash needs to be at the end or it's treated as a range specifier
					MatchString = MatchString.replace("[\d-", "[-\d")		#same
					MatchString = MatchString.replace("[\w\d-_.]", "[\w\d_.-]")	#and so on...
					MatchString = MatchString.replace("[\w\d-_]", "[\w\d_-]")
					MatchString = MatchString.replace("[.-\w]", "[.\w-]")
					MatchString = MatchString.replace("[\s-\w.,]", "[\s\w.,-]")
					MatchString = MatchString.replace("[\w\d-.]", "[\w\d.-]")
					MatchString = MatchString.replace("[\d\.-\w]", "[\d\.\w-]")
					MatchString = MatchString.replace("[^-_A-Z0-9]", "[^_A-Z0-9-]")
					MatchString = MatchString.replace("[^-A-Z0-9]", "[^A-Z0-9-]")

					#If you get a rule that mismatches, find its "match" line in nmap-service-probes and pull out the "p/..../' signature name.
					#Copy an "elif..." section below and put the signature name (without "p/" and "/") inside the quotes after .find .
					if ServerDescription.find('Skype VoIP data channel') > -1:
						#This "14 bytes of random stuff" signature way misfires.
						pass
					elif ServerDescription.find('Microsoft Distributed Transaction Coordinator') > -1:
						#This "ERROR" signature matches other protocols.
						pass
					elif ServerDescription.find('Erlang Distribution Node') > -1:
						#This signature mismatches.
						pass
					elif ServerDescription.find('Lotus Domino Console') > -1:
						#This signature mismatches.
						pass
					elif ServerDescription.find('LANDesk remote management') > -1:
						#This signature mismatches.
						pass
					elif not InformationPresent:
						#There's a regex match, but no information about, skip.
						pass
					else:
						try:
							#We try to compile the MatchString now before inserting into ServiceFPs so the work only needs to be
							#done once.  If this fails we fall down to the except and simply don't use the tuple.
							#Originally 413 out of 3671 match lines failed to compile because of "-" placement in character sets.
							#The problem, and a fixed version, have been reported to the nmap developers.
							#The use of "str" seems redundant, but we have occasionally gotten:
							#line 511: OutputDescription = OneTuple[1]
							#TypeError: expected a character buffer object
							SearchTuple = (re.compile(MatchString, MatchFlags), str(ProtoString + "://" + ServerDescription))
							CompileSuccess += 1
							if len(PortArray) == 0:
								#No ports declared yet; we'll place this search pair under the special port "all"
								if 'all' not in ServiceFPs:
									ServiceFPs['all'] = []
								ServiceFPs['all'].append(SearchTuple)
								LoadCount += 1
							else:
								#Register this search pair for every port requested
								for OnePort in PortArray:
									if int(OnePort) not in ServiceFPs:
										ServiceFPs[int(OnePort)] = []
									ServiceFPs[int(OnePort)].append(SearchTuple)
									LoadCount += 1
						except:
							#print "Failed to compile " + MatchString
							CompileFail += 1

				elif (len(line) >= 5) and (line[0:6] == "ports "):
					PortArray = []
					RawPortsString = line[6:].strip()
					#print "ports are ", RawPortsString
					for PortBlock in RawPortsString.split(","):		#Each PortBlock is either an individual port or port range
						if PortBlock.find("-") > -1:
							#We have a port range
							PortRange = PortBlock.split("-")
							for OnePort in range(int(PortRange[0]), int(PortRange[1]) + 1):
								PortArray.append(OnePort)
						else:
							PortArray.append(PortBlock)
					#print len(PortArray), PortArray
				elif (len(line) >= 9) and (line[0:10] == "softmatch "):
					pass
					#softmatches look very weak at the moment; none give a productname.  Skip for the moment.
					#print "softmatch"

			ServiceHandle.close()

			if CompileFail == 0:
				Debug(str(CompileSuccess) + " nmap service signatures successfully loaded.")
			else:
				Debug(str(CompileSuccess) + " nmap service signatures successfully loaded, unable to parse " + str(CompileFail) + " others.")
			return True
		except:
			Debug("Failed to load " + ServiceFileName)
			return False
	else:
		Debug("Unable to find " + ServiceFileName)
		return False


def extract_len_string(len_encoded_string):
	"""Assumes byte 0 is a length, followed by a string of that
	length (1-255 bytes).  Returns that string and the remainder of
	the len_enocded_string after the first string has been removed.
	Example call: cpu, remainder = extract_len_string(hinfo_payload)
	gives back "ARMV7L" and "\x05LINUX" for another round of
	extraction."""


	ret_str = ''

	str_len = ord(len_encoded_string[0])
	if str_len > 0:
		ret_str = str(len_encoded_string[1:str_len+1])
	string_tail = len_encoded_string[str_len+1:]

	return (ret_str, string_tail)



#def mac_of_ipaddr(ipv6addr):
#	"""For a supplied IPv6 address in EUI-64 format, return the mac address of the system that's behind it.  For an address not in that format, return ''."""




def RememberDNS(IPAddr, Hostname, RecType):
	"""Remember dns objects in DNSRecord and HostIPs.  RecType is 'A', 'AAAA', 'PTR', or 'CNAME'."""
	global DNSRecord
	global HostIPs

	if (Hostname == '') or (IPAddr in ('::', '0000:0000:0000:0000:0000:0000:0000:0000')):
		return

	if IPAddr + "," + RecType not in DNSRecord:			#If we haven't seen this hostname for this IPAddr,
		DNSRecord[IPAddr + "," + RecType] = [Hostname]		#make an array with just this hostname
	elif Hostname not in DNSRecord[IPAddr + "," + RecType]:		#If we _do_ have existing hostnames for this IP, but this new Hostname isn't one of them
		DNSRecord[IPAddr + "," + RecType].append(Hostname)	#Add this Hostname to the list

	if Hostname not in HostIPs:
		if not isFQDN(Hostname):	#We don't want to remember ips for names like "www", "ns1.mydom", "localhost", etc.
			return
		HostIPs[Hostname] = []
	#else:
		#Since we've found "Hostname" as a key, we don't need to check if it's an FQDN again, we already checked once.

	if not IPAddr in HostIPs[Hostname]:		#If we haven't seen this IP address for this hostname,
		HostIPs[Hostname].append(IPAddr)	#Remember this new IP address for this hostname.



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




def ReportId(Type, CompressedIPAddr, Proto, State, Description, Warnings):
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

	global ManualServerDescription
	global ClientDescription
	global MacAddr
	global EtherManuf
	global LogFile
	global GenDesc
	global SuspiciousIPs
	global NewSuspiciousIPs

	IPAddr = explode_ip(CompressedIPAddr)

	Location = IPAddr + "," + Proto
	Description = Description.replace('\n', '').replace('\r', '').replace(',', ' ')

	if Warnings:		#Non-empty set of strings
		if Description:
			Description += ' '
		Description += 'Warnings:' + ':'.join(Warnings)

		if IPAddr in TrustedIPs:
			if Warnings == ['plaintext'] and Proto == 'UDP_514':
				pass
			elif Warnings == ['portpolicyviolation']:
				Debug("Attempt to add trusted IP " + IPAddr + " to SuspiciousIPs because of portpolicyviolation.")
			else:
				Debug("Attempt to add trusted IP " + IPAddr + " to SuspiciousIPs.")
				Debug("Attempt to add trusted IP " + IPAddr + " to SuspiciousIPs." + '|' + str(Type) + '|' + str(Proto) + '|' + str(State) + '|' + str(Description) + '|' + str(Warnings))
				#quit()
		elif 'spoofed' not in Warnings:
			#We have to add this warning to SuspiciousIPs, the master list of _all_ warnings for all IPs....
			if IPAddr not in SuspiciousIPs:
				SuspiciousIPs[IPAddr] = []
			for one_warning in Warnings:
				if one_warning not in SuspiciousIPs[IPAddr]:
					SuspiciousIPs[IPAddr].append(one_warning)

			#....and we have to add it to NewSuspiciousIPs, which only holds the new things we've discovered this session.
			if IPAddr not in NewSuspiciousIPs:
				NewSuspiciousIPs[IPAddr] = []
			for one_warning in Warnings:
				if one_warning not in NewSuspiciousIPs[IPAddr]:
					NewSuspiciousIPs[IPAddr].append(one_warning)



	ShouldPrint = True

	if Type not in GenDesc:
		GenDesc[Type] = {}

	if Type in ("TS", "US"):
		if Location not in GenDesc[Type]:
			GenDesc[Type][Location] = set()

		if State + ',' + Description in GenDesc[Type][Location]:
			ShouldPrint = False			#Don't print if we've already printed it with this state + description
		else:
			GenDesc[Type][Location].add(State + ',' + Description)

		if Description != '':
			ManualServerDescription[Location] = Description
	elif Type in ("TC", "UC"):
		if Location not in GenDesc[Type]:
			GenDesc[Type][Location] = set()

		if State + ',' + Description in GenDesc[Type][Location]:
			ShouldPrint = False			#Don't print if we've already printed it with this state + description
		else:
			GenDesc[Type][Location].add(State + ',' + Description)

		if Description != '':
			ClientDescription[Location] = Description
	elif Type in ("IP", "NA", "PC", "PS"):
		if Location not in GenDesc[Type]:
			GenDesc[Type][Location] = set()

		if State + ',' + Description in GenDesc[Type][Location]:
			ShouldPrint = False			#Don't print if we've already printed it with this state + description
		else:
			GenDesc[Type][Location].add(State + ',' + Description)
	elif Type == "DN":
		#FIXME - perhaps description could indicate low TTL?  <300?  <150?
		if Proto in ('A', 'AAAA', 'CNAME', 'PTR') and State == '':
			ShouldPrint = False
		elif Location in DNSRecord and State in DNSRecord[Location]:
			ShouldPrint = False
		else:
			RememberDNS(IPAddr, State, Proto)
	elif Type == "RO":
		if Description == '':
			description_string = Proto		#This holds the type of packet that causes us to believe it's a router, like "RouterAdv"
		else:
			description_string = Description

		if IPAddr not in GenDesc[Type]:			#If we ever need to test if an IP is a router, use IPAddr in GenDesc['RO']
			GenDesc[Type][IPAddr] = set()

		if description_string in GenDesc[Type][IPAddr]:
			ShouldPrint = False			#Don't print if we've already printed it with this description
		else:
			GenDesc[Type][IPAddr].add(description_string)
	elif Type == "MA":
		State = State.upper()
		if IPAddr in ('', '::', '0000:0000:0000:0000:0000:0000:0000:0000'):
			ShouldPrint = False			#Not registering :: as a null IP address
		elif (IPAddr in MacAddr) and (MacAddr[IPAddr] == State):
			ShouldPrint = False			#Already known, no need to reprint
		else:
			MacAddr[IPAddr] = State
			if State[:8] in EtherManuf:
				Description = EtherManuf[State[:8]].replace(',', ' ')

	if ShouldPrint:
		try:
			OutString = Type + "," + IPAddr + "," + Proto + "," + State + "," + Description
			print(OutString)
			if LogFile is not None:
				LogFile.write(OutString + '\n')
				LogFile.flush()
		except UnicodeDecodeError:
			pass


def ReportAll(output_tuple_set):
	"""Wrapper function for original passer script used to accept a set of tuples generated by {LAYER}_extract functions and send them to ReportId.
	Example call: ReportAll(ARP_extract(p, meta)) ."""

	for a_tuple in output_tuple_set
		ReportId(a_tuple[Type], a_tuple[IPAddr], a_tuple[Proto], a_tuple[State], a_tuple[Description], a_tuple[Warnings])


def isFQDN(Hostname):
	"""Boolean function: Checks to se if a hostname ends in a TLD.  Not a strict check, just some quick checks."""
	#https://en.wikipedia.org/wiki/List_of_Internet_top-level_domains
	#'..',
	if len(Hostname) < 5:		#Shortest I can think of is "h.uk.", technically a domain, but still a dns object
		Debug("Hostname " + Hostname + " too short, ignoring.")
		return False
	elif not Hostname.endswith('.'):
		Debug("Hostname " + Hostname + "doesn't end in '.', ignoring.")
		return False
	elif len(Hostname) >= 6 and Hostname.endswith(('.aaa.', '.abb.', '.abc.', '.aig.', '.art.', '.aws.', '.axa.', '.bar.', '.bet.', '.bid.', '.bio.', '.biz.', '.bot.', '.box.', '.bzh.', '.cab.', '.cat.', '.cbs.', '.ceo.', '.com.', '.dev.', '.dog.', '.eco.', '.edu.', '.eus.', '.fit.', '.frl.', '.fun.', '.fyi.', '.gal.', '.gdn.', '.gop.', '.gov.', '.hiv.', '.hot.', '.hkt.', '.ibm.', '.ink.', '.int.', '.ist.', '.jio.', '.jmp.', '.jnj.', '.jot.', '.kim.', '.krd.', '.law.', '.lds.', '.llc.', '.lol.', '.ltd.', '.men.', '.mil.', '.moe.', '.net.', '.ngo.', '.now.', '.nrw.', '.ntt.', '.nyc.', '.one.', '.ong.', '.onl.', '.org.', '.ovh.', '.pet.', '.pro.', '.pub.', '.pwc.', '.red.', '.rio.', '.rip.', '.run.', '.scb.', '.sex.', '.ski.', '.srl.', '.tel.', '.thd.', '.top.', '.uno.', '.uol.', '.vet.', '.vip.', '.win.', '.wow.', '.wtc.', '.wtf.', '.xin.', '.xxx.', '.xyz.', '.you.', '.aco.', '.ads.', '.aeg.', '.afl.', '.anz.', '.aol.', '.app.', '.bbc.', '.bbt.', '.bcg.', '.bcn.', '.bms.', '.bmw.', '.bnl.', '.bom.', '.boo.', '.buy.', '.cal.', '.cam.', '.car.', '.cba.', '.cbn.', '.ceb.', '.cfa.', '.cfd.', '.crs.', '.csc.', '.dad.', '.day.', '.dds.', '.dhl.', '.diy.', '.dnp.', '.dot.', '.dtv.', '.dvr.', '.eat.', '.esq.', '.fan.', '.fly.', '.foo.', '.fox.', '.ftr.', '.gap.', '.gea.', '.gle.', '.gmo.', '.gmx.', '.goo.', '.got.', '.hbo.', '.how.', '.htc.', '.ice.', '.icu.', '.ifm.', '.ing.', '.itv.', '.iwc.', '.jcb.', '.jcp.', '.jlc.', '.jll.', '.joy.', '.kfh.', '.kia.', '.kpn.', '.lat.', '.lpl.', '.man.', '.mba.', '.mcd.', '.med.', '.meo.', '.mit.', '.mlb.', '.mls.', '.mma.', '.moi.', '.mom.', '.mov.', '.msd.', '.mtn.', '.mtr.', '.nab.', '.nba.', '.nec.', '.new.', '.nfl.', '.nhk.', '.nra.', '.obi.', '.off.', '.ooo.', '.ott.', '.pay.', '.pid.', '.pin.', '.pnc.', '.pru.', '.qvc.', '.ren.', '.ril.', '.rwe.', '.sap.', '.sas.', '.sbi.', '.sbs.', '.sca.', '.ses.', '.sew.', '.sfr.', '.sky.', '.soy.', '.srt.', '.stc.', '.tab.', '.tax.', '.tci.', '.tdk.', '.tjx.', '.trv.', '.tui.', '.tvs.', '.ubs.', '.ups.', '.vig.', '.vin.', '.wed.', '.wme.', '.yun.', '.zip.')):
		return True
	elif len(Hostname) >= 7 and Hostname.endswith(('.BIND.', '.aarp.', '.able.', '.aero.', '.aigo.', '.amex.', '.arab.', '.arpa.', '.asia.', '.audi.', '.baby.', '.band.', '.bank.', '.beer.', '.best.', '.bike.', '.blog.', '.blue.', '.buzz.', '.cafe.', '.call.', '.camp.', '.care.', '.casa.', '.chat.', '.city.', '.club.', '.cool.', '.coop.', '.date.', '.diet.', '.fail.', '.fans.', '.farm.', '.fido.', '.film.', '.fish.', '.food.', '.free.', '.game.', '.gent.', '.gift.', '.gmbh.', '.golf.', '.guru.', '.haus.', '.help.', '.host.', '.hsbc.', '.ieee.', '.info.', '.itau.', '.jobs.', '.kiwi.', '.land.', '.lgbt.', '.life.', '.link.', '.live.', '.loan.', '.love.', '.ltda.', '.menu.', '.mobi.', '.moda.', '.name.', '.news.', '.nike.', '.pics.', '.pink.', '.plus.', '.porn.', '.prod.', '.qpon.', '.rent.', '.rest.', '.ruhr.', '.sale.', '.scot.', '.sexy.', '.shop.', '.show.', '.sina.', '.site.', '.surf.', '.taxi.', '.team.', '.tech.', '.test.', '.tips.', '.town.', '.vote.', '.wang.', '.wien.', '.wiki.', '.wine.', '.work.', '.yoga.', '.zara.', '.zero.', '.zone.', '.adac.', '.akdn.', '.ally.', '.army.', '.arte.', '.asda.', '.auto.', '.bbva.', '.bing.', '.bofa.', '.bond.', '.book.', '.cars.', '.case.', '.cash.', '.cbre.', '.cern.', '.citi.', '.cyou.', '.data.', '.dclk.', '.deal.', '.dell.', '.desi.', '.dish.', '.docs.', '.doha.', '.duck.', '.duns.', '.dvag.', '.erni.', '.fage.', '.fast.', '.fiat.', '.fire.', '.flir.', '.ford.', '.fund.', '.gbiz.', '.ggee.', '.gold.', '.goog.', '.guge.', '.hair.', '.hdfc.', '.here.', '.hgtv.', '.icbc.', '.imdb.', '.immo.', '.java.', '.jeep.', '.jprs.', '.kddi.', '.kpmg.', '.kred.', '.lego.', '.lidl.', '.like.', '.limo.', '.loft.', '.luxe.', '.maif.', '.meet.', '.meme.', '.mini.', '.mint.', '.moto.', '.mtpc.', '.navy.', '.next.', '.nico.', '.ollo.', '.open.', '.page.', '.pars.', '.pccw.', '.ping.', '.play.', '.pohl.', '.post.', '.prof.', '.raid.', '.read.', '.reit.', '.rich.', '.rmit.', '.room.', '.rsvp.', '.safe.', '.sapo.', '.sarl.', '.save.', '.saxo.', '.scor.', '.seat.', '.seek.', '.shaw.', '.shia.', '.silk.', '.skin.', '.sncf.', '.sohu.', '.song.', '.sony.', '.spot.', '.star.', '.talk.', '.teva.', '.tiaa.', '.toys.', '.tube.', '.vana.', '.visa.', '.viva.', '.vivo.', '.voto.', '.weir.', '.xbox.')):
		return True
	elif len(Hostname) >= 8 and Hostname.endswith(('.archi.', '.audio.', '.bingo.', '.black.', '.bosch.', '.build.', '.cisco.', '.click.', '.cloud.', '.coach.', '.codes.', '.cymru.', '.deals.', '.delta.', '.dodge.', '.earth.', '.edeka.', '.email.', '.faith.', '.fedex.', '.games.', '.green.', '.group.', '.gucci.', '.guide.', '.homes.', '.horse.', '.house.', '.hyatt.', '.irish.', '.iveco.', '.jetzt.', '.koeln.', '.kyoto.', '.legal.', '.lilly.', '.local.', '.lotto.', '.media.', '.miami.', '.money.', '.movie.', '.ninja.', '.nokia.', '.onion.', '.osaka.', '.paris.', '.parts.', '.party.', '.photo.', '.pizza.', '.place.', '.poker.', '.press.', '.promo.', '.rocks.', '.rugby.', '.shoes.', '.solar.', '.space.', '.sport.', '.store.', '.study.', '.style.', '.sucks.', '.swiss.', '.tatar.', '.tirol.', '.today.', '.tokyo.', '.tools.', '.tours.', '.trade.', '.trust.', '.tushu.', '.vegas.', '.video.', '.wales.', '.watch.', '.weibo.', '.works.', '.world.', '.yahoo.', '.zippo.', '.actor.', '.adult.', '.aetna.', '.amfam.', '.amica.', '.apple.', '.autos.', '.azure.', '.baidu.', '.beats.', '.bible.', '.boats.', '.boots.', '.canon.', '.cards.', '.chase.', '.cheap.', '.chloe.', '.citic.', '.crown.', '.dabur.', '.dance.', '.drive.', '.dubai.', '.epost.', '.epson.', '.final.', '.forex.', '.forum.', '.gallo.', '.gifts.', '.gives.', '.glade.', '.glass.', '.globo.', '.gmail.', '.gripe.', '.honda.', '.ikano.', '.intel.', '.lamer.', '.lease.', '.lexus.', '.linde.', '.lipsy.', '.lixil.', '.loans.', '.locus.', '.lotte.', '.lupin.', '.macys.', '.mango.', '.mopar.', '.nadex.', '.nexus.', '.nikon.', '.nowtv.', '.omega.', '.phone.', '.praxi.', '.prime.', '.quest.', '.radio.', '.rehab.', '.reise.', '.ricoh.', '.rodeo.', '.salon.', '.sener.', '.seven.', '.sharp.', '.shell.', '.skype.', '.sling.', '.smart.', '.smile.', '.stada.', '.tires.', '.tmall.', '.toray.', '.total.', '.tunes.', '.ubank.', '.vista.', '.vodka.', '.volvo.', '.weber.', '.xerox.')):
		return True
	elif len(Hostname) >= 9 and Hostname.endswith(('.abarth.', '.abbott.', '.abbvie.', '.agency.', '.author.', '.bayern.', '.berlin.', '.casino.', '.center.', '.church.', '.clinic.', '.coffee.', '.condos.', '.coupon.', '.dating.', '.dealer.', '.degree.', '.dental.', '.design.', '.energy.', '.estate.', '.events.', '.expert.', '.family.', '.global.', '.google.', '.gratis.', '.health.', '.hermes.', '.hiphop.', '.hockey.', '.hotels.', '.hughes.', '.insure.', '.intuit.', '.joburg.', '.kaufen.', '.lawyer.', '.london.', '.luxury.', '.market.', '.mattel.', '.mobile.', '.monash.', '.moscow.', '.museum.', '.natura.', '.online.', '.photos.', '.quebec.', '.racing.', '.realty.', '.repair.', '.report.', '.review.', '.rogers.', '.school.', '.social.', 'stream.', '.studio.', '.supply.', '.sydney.', '.taipei.', '.tattoo.', '.tienda.', '.travel.', '.viajes.', '.vision.', '.voting.', '.webcam.', '.yandex.', '.active.', '.africa.', '.airbus.', '.airtel.', '.alipay.', '.alsace.', '.alstom.', '.anquan.', '.aramco.', '.beauty.', '.bharti.', '.blanco.', '.bostik.', '.boston.', '.broker.', '.camera.', '.career.', '.caseih.', '.chanel.', '.chrome.', '.circle.', '.claims.', '.comsec.', '.credit.', '.cruise.', '.datsun.', '.direct.', '.doctor.', '.dunlop.', '.dupont.', '.durban.', '.emerck.', '.flickr.', '.futbol.', '.gallup.', '.garden.', '.george.', '.giving.', '.imamat.', '.jaguar.', '.juegos.', '.kinder.', '.kindle.', '.kosher.', '.lancia.', '.latino.', '.lefrak.', '.living.', '.locker.', '.madrid.', '.maison.', '.makeup.', '.mobily.', '.mormon.', '.mutual.', '.nagoya.', '.nissan.', '.nissay.', '.norton.', '.nowruz.', '.office.', '.olayan.', '.oracle.', '.orange.', '.otsuka.', '.pfizer.', '.physio.', '.piaget.', '.pictet.', '.reisen.', '.rocher.', '.ryukyu.', '.safety.', '.sakura.', '.sanofi.', '.schule.', '.secure.', '.select.', '.shouji.', '.soccer.', '.suzuki.', '.swatch.', '.taobao.', '.target.', '.tennis.', '.tjmaxx.', '.tkmaxx.', '.toyota.', '.unicom.', '.viking.', '.villas.', '.virgin.', '.voyage.', '.vuelos.', '.walter.', '.warman.', '.xihuan.', '.xperia.', '.yachts.', '.zappos.')):
		return True
	elif len(Hostname) >= 10 and Hostname.endswith(('.abogado.', '.academy.', '.audible.', '.bugatti.', '.capital.', '.caravan.', '.college.', '.cologne.', '.comcast.', '.company.', '.cooking.', '.country.', '.coupons.', '.cricket.', '.cruises.', '.digital.', '.domains.', '.exposed.', '.express.', '.fashion.', '.ferrari.', '.flights.', '.frogans.', '.gallery.', '.hamburg.', '.hosting.', '.invalid.', '.jewelry.', '.kitchen.', '.limited.', '.markets.', '.network.', '.neustar.', '.organic.', '.origins.', '.panerai.', '.recipes.', '.rentals.', '.reviews.', '.sandvik.', '.science.', '.shiksha.', '.support.', '.systems.', '.tickets.', '.wanggou.', '.weather.', '.website.', '.wedding.', '.whoswho.', '.winners.', '.agakhan.', '.alibaba.', '.android.', '.athleta.', '.auction.', '.auspost.', '.avianca.', '.banamex.', '.bauhaus.', '.bentley.', '.bestbuy.', '.booking.', '.brother.', '.careers.', '.cartier.', '.channel.', '.chintai.', '.citadel.', '.clubmed.', '.compare.', '.contact.', '.corsica.', '.courses.', '.dentist.', '.farmers.', '.ferrero.', '.finance.', '.fishing.', '.fitness.', '.florist.', '.flowers.', '.forsale.', '.fujitsu.', '.genting.', '.godaddy.', '.guitars.', '.hangout.', '.hitachi.', '.holiday.', '.hoteles.', '.hotmail.', '.hyundai.', '.iselect.', '.ismaili.', '.juniper.', '.komatsu.', '.lacaixa.', '.lancome.', '.lanxess.', '.lasalle.', '.latrobe.', '.leclerc.', '.liaison.', '.lincoln.', '.metlife.', '.monster.', '.netbank.', '.netflix.', '.okinawa.', '.oldnavy.', '.philips.', '.pioneer.', '.politie.', '.realtor.', '.rexroth.', '.samsung.', '.schmidt.', '.schwarz.', '.shriram.', '.singles.', '.spiegel.', '.staples.', '.starhub.', '.statoil.', '.storage.', '.surgery.', '.temasek.', '.theater.', '.theatre.', '.tiffany.', '.toshiba.', '.trading.', '.walmart.', '.watches.', '.windows.', '.xfinity.', '.yamaxun.', '.youtube.', '.zuerich.')):	#early-registration.of.surfnet.invalid.
		return True
	elif len(Hostname) >= 11 and Hostname.endswith(('.airforce.', '.attorney.', '.barclays.', '.brussels.', '.business.', '.capetown.', '.catering.', '.cleaning.', '.computer.', '.delivery.', '.deloitte.', '.diamonds.', '.discount.', '.discover.', '.download.', '.etisalat.', '.everbank.', '.feedback.', '.goodyear.', '.holdings.', '.istanbul.', '.lighting.', '.maserati.', '.mckinsey.', '.partners.', '.pharmacy.', '.pictures.', '.plumbing.', '.property.', '.reliance.', '.saarland.', '.security.', '.services.', '.showtime.', '.software.', '.training.', '.ventures.', '.xn--p1ai.', '.yokohama.', '.abudhabi.', '.allstate.', '.barefoot.', '.bargains.', '.baseball.', '.boutique.', '.bradesco.', '.broadway.', '.budapest.', '.builders.', '.catholic.', '.chrysler.', '.cipriani.', '.cityeats.', '.clinique.', '.clothing.', '.commbank.', '.democrat.', '.engineer.', '.ericsson.', '.esurance.', '.exchange.', '.fidelity.', '.firmdale.', '.football.', '.frontier.', '.grainger.', '.graphics.', '.guardian.', '.hdfcbank.', '.helsinki.', '.hospital.', '.infiniti.', '.ipiranga.', '.jpmorgan.', '.lundbeck.', '.marriott.', '.memorial.', '.mortgage.', '.movistar.', '.observer.', '.redstone.', '.samsclub.', '.shopping.', '.softbank.', '.stcgroup.', '.supplies.', '.symantec.', '.telecity.', '.uconnect.', '.vanguard.', '.verisign.', '.woodside.', '.xn--90ae.', '.xn--node.', '.xn--qxam.')):
		return True
	elif len(Hostname) >= 12 and Hostname.endswith(('.alfaromeo.', '.amsterdam.', '.barcelona.', '.christmas.', '.community.', '.directory.', '.education.', '.equipment.', '.homesense.', '.institute', '.insurance.', '.marketing.', '.melbourne.', '.solutions.', '.vacations.', '.xn--j1amh.', '.xn--p1acf.', '.accenture.', '.allfinanz.', '.analytics.', '.aquarelle.', '.bloomberg.', '.fairwinds.', '.financial.', '.firestone.', '.fresenius.', '.frontdoor.', '.fujixerox.', '.furniture.', '.goldpoint.', '.goodhands.', '.hisamitsu.', '.homedepot.', '.homegoods.', '.honeywell.', '.institute.', '.kuokgroup.', '.ladbrokes.', '.lancaster.', '.landrover.', '.lifestyle.', '.marshalls.', '.mcdonalds.', '.microsoft.', '.montblanc.', '.panasonic.', '.passagens.', '.pramerica.', '.richardli.', '.scjohnson.', '.shangrila.', '.statebank.', '.statefarm.', '.stockholm.', '.travelers.', '.xn--90ais.', '.xn--c1avg.', '.xn--d1alf.', '.xn--e1a4c.', '.xn--fhbei.', '.xn--j1aef.', '.xn--l1acc.', '.xn--ngbrx.', '.xn--nqv7f.', '.xn--tckwe.', '.xn--vhquv.', '.yodobashi.')):
		return True
	elif len(Hostname) >= 13 and Hostname.endswith(('.accountant.', '.bnpparibas.', '.consulting.', '.extraspace.', '.healthcare.', '.immobilien.', '.management.', '.newholland.', '.properties.', '.restaurant.', '.technology.', '.vlaanderen.', '.apartments.', '.associates.', '.basketball.', '.boehringer.', '.capitalone.', '.creditcard.', '.cuisinella.', '.eurovision.', '.foundation.', '.industries.', '.mitsubishi.', '.nationwide.', '.nextdirect.', '.onyourside.', '.protection.', '.prudential.', '.realestate.', '.republican.', '.schaeffler.', '.swiftcover.', '.tatamotors.', '.telefonica.', '.vistaprint.', '.volkswagen.', '.xn--30rr7y.', '.xn--3pxu8k.', '.xn--45q11c.', '.xn--4gbrim.', '.xn--55qx5d.', '.xn--5tzm5g.', '.xn--80aswg.', '.xn--90a3ac.', '.xn--9dbq2a.', '.xn--9et52u.', '.xn--c2br7g.', '.xn--cg4bki.', '.xn--czrs0t.', '.xn--czru2d.', '.xn--fiq64b.', '.xn--fiqs8s.', '.xn--fiqz9s.', '.xn--io0a7i.', '.xn--kput3i.', '.xn--mxtq1m.', '.xn--o3cw4h.', '.xn--pssy2u.', '.xn--unup4y.', '.xn--wgbh1c.', '.xn--wgbl6a.', '.xn--y9a3aq.')):
		return True
	elif len(Hostname) >= 14 and Hostname.endswith(('.accountants.', '.barclaycard.', '.blockbuster.', '.calvinklein.', '.engineering.', '.enterprises.', '.lamborghini.', '.photography.', '.productions.', '.williamhill.', '.university.', '.xn--6frz82g.', '.xn--9krt00a.', '.xn--g2xx48c.', '.xn--kpry57d.', '.xn--q9jyb4c.', '.xn--rovu88b.', '.blackfriday.', '.bridgestone.', '.contractors.', '.creditunion.', '.foodnetwork.', '.investments.', '.kerryhotels.', '.motorcycles.', '.olayangroup.', '.playstation.', '.progressive.', '.redumbrella.', '.rightathome.', '.xn--11b4c3d.', '.xn--1ck2e1b.', '.xn--1qqw23a.', '.xn--3bst00m.', '.xn--3ds443g.', '.xn--42c2d9a.', '.xn--45brj9c.', '.xn--55qw42g.', '.xn--80ao21a.', '.xn--cck2b3b.', '.xn--czr694b.', '.xn--d1acj3b.', '.xn--efvy88h.', '.xn--estv75g.', '.xn--fct429k.', '.xn--fjq720a.', '.xn--flw351e.', '.xn--gecrj9c.', '.xn--gk3at1e.', '.xn--h2brj9c.', '.xn--hxt814e.', '.xn--imr513n.', '.xn--j6w193g.', '.xn--jvr189m.', '.xn--kprw13d.', '.xn--kpu716f.', '.xn--mgbtx2b.', '.xn--mix891f.', '.xn--nyqy26a.', '.xn--pbt977c.', '.xn--pgbs0dh.', '.xn--rhqv96g.', '.xn--s9brj9c.', '.xn--ses554g.', '.xn--t60b56a.', '.xn--vuq861b.', '.xn--w4rs40l.', '.xn--xhq521b.', '.xn--zfr164b.')):
		return True
	elif len(Hostname) >= 15 and Hostname.endswith(('.construction.', '.versicherung.', '.xn--mgbt3dhd.', '.xn--ngbc5azd.', '.lplfinancial.', '.pamperedchef.', '.scholarships.', '.xn--3e0b707e.', '.xn--80adxhks.', '.xn--80asehdb.', '.xn--8y0a063a.', '.xn--gckr3f0f.', '.xn--mgb9awbf.', '.xn--mgbab2bd.', '.xn--mgbpl2fh.', '.xn--mk1bu44c.', '.xn--ngbe9e0a.', '.xn--ogbpf8fl.', '.xn--qcka1pmc.')):
		return True
	elif len(Hostname) >= 16 and Hostname.endswith(('.international.', '.lifeinsurance.', '.orientexpress.', '.spreadbetting.', '.travelchannel.', '.wolterskluwer.', '.xn--eckvdtc9d.', '.xn--fpcrj9c3d.', '.xn--fzc2c9e2c.', '.xn--tiq49xqyj.', '.xn--yfro4i67o.', '.xn--ygbi2ammx.')):
		return True
	elif len(Hostname) >= 17 and Hostname.endswith(('.cancerresearch.', '.weatherchannel.', '.xn--mgbb9fbpob.', '.afamilycompany.', '.americanfamily.', '.bananarepublic.', '.cookingchannel.', '.kerrylogistics.', '.xn--54b7fta0cc.', '.xn--6qq986b3xl.', '.xn--80aqecdr1a.', '.xn--b4w605ferd.', '.xn--fiq228c5hs.', '.xn--jlq61u9w7b.', '.xn--mgba3a3ejt.', '.xn--mgbaam7a8h.', '.xn--mgbayh7gpa.', '.xn--mgbbh1a71e.', '.xn--mgbca7dzdo.', '.xn--mgbi4ecexp.', '.xn--mgbx4cd0ab.')):
		return True
	elif len(Hostname) >= 18 and Hostname.endswith(('.americanexpress.', '.kerryproperties.', '.sandvikcoromant.', '.xn--i1b6b1a6a2e.', '.xn--kcrx77d1x4a.', '.xn--lgbbat1ad8j.', '.xn--mgba3a4f16a.', '.xn--mgbaakc7dvf.', '.xn--mgbc0a9azcg.', '.xn--nqv7fs00ema.')):
		return True
	elif len(Hostname) >= 19 and Hostname.endswith(('.xn--fzys8d69uvgm.', '.xn--mgba7c0bbn0a.', '.xn--xkc2al3hye2a.')):
		return True
	elif len(Hostname) >= 20 and Hostname.endswith(('.xn--3oq18vl8pn36a.', '.xn--5su34j936bgsg.', '.xn--bck1b9a5dre4c.', '.xn--mgbai9azgqp6j.', '.xn--mgberp4a5d4ar.', '.xn--xkc2dl3a5ee0h.')):
		return True
	elif len(Hostname) >= 21 and Hostname.endswith(('.northwesternmutual.', '.travelersinsurance.')):
		return True
	elif len(Hostname) >= 23 and Hostname.endswith(('.xn--w4r85el8fhu5dnra.')):
		return True
	elif len(Hostname) >= 25 and Hostname.endswith(('.xn--clchc0ea0b2g2a9gcd.')):
		return True
	elif len(Hostname) >= 26 and Hostname.endswith(('.xn--vermgensberater-ctb.')):
		return True
	elif len(Hostname) >= 27 and Hostname.endswith(('.xn--vermgensberatung-pwb.')):
		return True
	elif re.search('\.[a-z][a-z]\.$', Hostname) is not None:		#ends in 2 letter TLD
		return True
	else:
		if not Hostname.endswith(no_warn_name_tails):
			Debug("Hostname " + Hostname + " has invalid TLD, ignoring.")
		return False

def process_udp_dns_query(src_ip, dst_ip, dst_service, dst_port, p_dns, orig_packet):
	"""Note DNS queries that use type ANY."""
	#FIXME - copy and adapt this structure over to process_udp_dns_response too.

	amplified_query = False
	if dst_port == 5353:
		portname = 'mdns'
	else:
		portname = 'dns'

	DNSBlocks = []
	ANY_domains = ([])
	if p_dns.qdcount > 0:
		DNSBlocks.append(p_dns.qd)
	for OneQr in DNSBlocks:
		while isinstance(OneQr, DNSQR):
			if OneQr.qclass == 1:			#Class IN
				dns_object = OneQr.qname.lower()
				if OneQr.qtype == 255 and dns_object in amplified_any_dnsobjs:					#type ANY
					amplified_query = True
				elif OneQr.qtype == 255 and dns_object.endswith(amplified_any_domains):				#type ANY
					amplified_query = True
				elif OneQr.qtype in (1, 255) and dns_object in amplified_any_a_dnsobjs:				#type A or ANY
					amplified_query = True
				elif OneQr.qtype in (1, 46, 255) and dns_object in amplified_any_a_rrsig_dnsobjs:		#type A, RRSIG, or ANY
					amplified_query = True
				elif OneQr.qtype in (16, 28, 255) and dns_object in amplified_any_aaaa_txt_dnsobjs:		#type AAAA, TXT,  or ANY
					amplified_query = True
				elif OneQr.qtype in (48, 255) and dns_object in amplified_any_dnskey_dnsobjs:			#type DNSKEY or ANY
					amplified_query = True
				elif OneQr.qtype in (43, 46, 48, 255) and dns_object in amplified_any_dnskey_ds_rrsig_dnsobjs:	#type DS, DNSKEY, RRSIG, or ANY
					amplified_query = True
				elif OneQr.qtype in (43, 255) and dns_object in amplified_any_ds_dnsobjs:			#type DS or ANY
					amplified_query = True
				elif OneQr.qtype in (2, 255) and dns_object in amplified_any_ns_dnsobjs:			#type NS or ANY
					amplified_query = True
				elif OneQr.qtype in (16, 255) and dns_object in amplified_any_txt_dnsobjs:			#type TXT or ANY
					amplified_query = True
				elif OneQr.qtype == 255 and not dns_object.endswith(unamplified_any_domains) and not dns_object.endswith(unsure_any_domains):
					ShowPacket(orig_packet, "ANY domain requested", HonorQuit)

				if OneQr.qtype == 255 and not dns_object in ANY_domains:
					ANY_domains.append(dns_object)

			OneQr = OneQr.payload

	if amplified_query:
		ReportId("UC", src_ip, "UDP_" + dst_port, "open", portname + "/client ANY domains requested:" + ' '.join(ANY_domains), (['amplification', 'spoofed']))
		#ShowPacket(orig_packet, "malicious dns query", HonorQuit)
	else:
		ReportId("UC", src_ip, "UDP_" + dst_port, "open", portname + "/client", ([]))



def process_udp_dns_response(src_ip, dst_ip, src_service, src_port, p_dns, orig_packet):

	#FIXME - Also report the TLD from one of the query answers to show what it's willing to answer for?
	ReportId("US", src_ip, "UDP_" + src_port, "open", "dns/server", ([]))

	#Not sure if we need this:
	#mdns_service_scan = False

	#Now we extract dns answers.  First, check that there's no dns error:
### rcode=0 No Error
	if p_dns.rcode == 0:
		#Not sure if we need this:
		#DNSQueryBlocks = []
		DNSBlocks = []
		CNAMERecs = []				#We hold onto all cnames until we've processed all PTR's and A's here
		if p_dns.ancount > 0:		#If we have at least one answer from the answer block, process it
			DNSBlocks.append(p_dns.an)
		if p_dns.arcount > 0:		#Likewise for the "additional" block
			DNSBlocks.append(p_dns.ar)

		#Not sure if we need this:
		#if p_dns.qdcount > 0:		#If we have at least one answer from the question block, save it
		#	DNSQueryBlocks.append(p_dns.qd)
		#	for one_query in DNSQueryBlocks:
		#		while isinstance(one_query, DNSQR):
		#			if one_query.qname == '_services._dns-sd._udp.local.':
		#				mdns_service_scan = True
		#			elif one_query.qname.endswith('.local.'):
		#				ShowPacket(orig_packet, ".local. DNS response to NOT _services._dns-sd._udp.local", HonorQuit)

		#			#Move to the next DNS object in the "qd" block (there should only be one, but try anyways)
		#			one_query = one_query.payload

		for OneAn in DNSBlocks:
			#Thanks to Philippe Biondi for showing me how to extract additional records.
			#Debug("Start dns extract" + str(p_dns.ancount))
			#OneAn = p_dns.an
			#while OneAn is not NoPayload:		#This doesn't seem to stop at the end of the list; incorrect syntax.
			while isinstance(OneAn, DNSRR):		#Somewhat equivalent:	while not isinstance(an, NoPayload):

				#Type codes can be found in http://www.rfc-editor.org/rfc/rfc1035.txt
				#print "Type: " + str(type(OneAn))		#All of type scapy.DNSRR
				#Note: rclass 32769 appears to show up in mdns records from apple
				if OneAn.rclass in (1, 32769):
					if OneAn.type == 1:		#"IN" class and "A" type answer
						DNSIPAddr = OneAn.rdata
						DNSHostname = OneAn.rrname.lower()
						ReportId("DN", DNSIPAddr, "A", DNSHostname, "", ([]))
					elif OneAn.type == 2:			#"IN" class and "NS" answer
						pass							#Perhaps later
						#Like cnames, this is object -> nameserver hostname, so these would need to be queued like cnames until we're done with A's and PTR's.
					elif OneAn.type == 5:			#"IN" class and "CNAME" answer
						CNAMERecs.append(OneAn)					#Remember the record; we'll process these after the PTR's and A's
					elif OneAn.type == 6:			#"IN" class and "SOA" answer
						pass							#Not immediately useful, perhaps later
					elif OneAn.type == 12:		#"IN" class and "PTR" type answer
						DNSHostname = OneAn.rdata.lower()
														#For input of '182.111.59.66.in-addr.arpa.'  :
						DNSIPAddr = OneAn.rrname.upper()				# '182.111.59.66.IN-ADDR.ARPA.'
						DNSIPAddr = DNSIPAddr.replace(".IN-ADDR.ARPA.", "")		# '182.111.59.66'
						DNSIPAddr = DNSIPAddr.replace(".IP6.ARPA.", "")			# (Strip off the suffix used for ipv6)
						DNSIPAddr = DNSIPAddr.split('.')				# ['182', '111', '59', '66']
						DNSIPAddr.reverse()						# ['66', '59', '111', '182']
						DNSIPAddr = string.join(DNSIPAddr, '.')				# '66.59.111.182'
						#Check that we end up with a legal IP address before continuing; we're getting garbage.
						if re.search('^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*$', DNSIPAddr) is not None:
							#Legal IPv4 address
							ReportId("DN", DNSIPAddr, "PTR", DNSHostname, "", ([]))
						elif re.search('^[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]$', DNSIPAddr) is not None:
							#Legal IPv6 address such as 0.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.9.2.4.E.1.4.0.0.2.2.F.7.0.6.2.ip6.arpa.
							ReportId("DN", DNSIPAddr, "PTR", DNSHostname, "", ([]))
						elif OneAn.rrname.endswith('.local.'):
							if OneAn.rrname == '_services._dns-sd._udp.local.':	#https://www.akamai.com/us/en/about/our-thinking/threat-advisories/akamai-mdns-reflection-ddos-threat-advisory.jsp
								#FIXME Check if ttl not 0,1,255 and report as external in warnings, otherwise no warning.
								#http://www.dns-sd.org/ServiceTypes.html
								if OneAn.rdata in ('_afpovertcp.', '_afpovertcp._tcp.', '_afpovertcp._tcp.local.'):
									ReportId("TS", src_ip, "TCP_427", "listening", 'svrloc/server not confirmed', ([]))
									ReportId("US", src_ip, "UDP_427", "listening", 'svrloc/server not confirmed', ([]))
									ReportId("TS", src_ip, "TCP_548", "listening", 'afpovertcp/server not confirmed', ([]))
								elif OneAn.rdata in ('_airdrop.', '_airdrop._tcp.', '_airdrop._tcp.local.'):			#https://stackoverflow.com/questions/10693411/implementing-the-airdrop-protocol
									ReportId("IP", src_ip, "IP", "Airdrop server (likely Mac OS)", '', ([]))
								elif OneAn.rdata in ('_airplay.', '_airplay._tcp.', '_airplay._tcp.local.'):			#https://www.cisco.com/c/en/us/td/docs/solutions/Enterprise/Borderless_Networks/Unified_Access/BYOD_Bonjour_EntMob.html
									ReportId("IP", src_ip, "IP", "Apple TV or Apple Airport Express", OneAn.rdata, ([]))
								elif OneAn.rdata in ('_amzn-wplay.', '_amzn-wplay._tcp.', '_amzn-wplay._tcp.local.'):
									ReportId("IP", src_ip, "IP", "Amazon Fire TV not confirmed", '', ([]))			#https://github.com/soef/mdns-discovery
								elif OneAn.rdata in ('_apple-mobdev2.', '_apple-mobdev2._tcp.', '_apple-mobdev2._tcp.local.'):
									ReportId("IP", src_ip, "IP", "Apple mobile device possible iphone with wifi sync", '', ([]))
								elif OneAn.rdata in ('_atc.', '_atc._tcp.', '_atc._tcp.local.'):
									ReportId("IP", src_ip, "IP", "Shared iTunes Library service", '', ([]))
								elif OneAn.rdata in ('_bowtie.', '_bowtie._tcp.', '_bowtie._tcp.local.', '_bttouch.', '_bttouch._tcp.', '_bttouch._tcp.local.', '_bttremote.', '_bttremote._tcp.', '_bttremote._tcp.local.'):	#https://github.com/sgentle/MPDTie/blob/master/rbowtie.rb
									ReportId("IP", src_ip, "IP", "Bowtie Remote", '', ([]))					#http://bowtieapp.com/
								elif OneAn.rdata in ('_coremediamgr.', '_coremediamgr._tcp.', '_coremediamgr._tcp.local.'):	#http://www.inmethod.com/airvideohd/index.html
									ReportId("IP", src_ip, "IP", "Air Video HD", '', ([]))
									ReportId("TS", src_ip, "TCP_45633", "listening", 'airvideohd/server not confirmed', ([]))
								elif OneAn.rdata in ('_cros_p2p.', '_cros_p2p._tcp.', '_cros_p2p._tcp.local.'):			#https://chromium.googlesource.com/chromiumos/platform/p2p/+/master/README
									ReportId("TS", src_ip, "TCP_16725", "listening", 'cros_p2p/server not confirmed', ([]))
								elif OneAn.rdata in ('_daap.', '_daap._tcp.', '_daap._tcp.local.', '_dacp.', '_dacp._tcp.', '_dacp._tcp.local.'):	#https://nto.github.io/AirPlay.html
									ReportId("TS", src_ip, "TCP_3689", "listening", 'daap_dacp/server not confirmed', ([]))
								elif OneAn.rdata in ('_dlaccess.', '_dlaccess._tcp.', '_dlaccess._tcp.local.', '_dlattachmentd.', '_dlattachmentd._tcp.', '_dlattachmentd._tcp.local.', '_dltouch.', '_dltouch._tcp.', '_dltouch._tcp.local.'):	#Dylite CRM https://www.marketcircle.com/help/article/what-processes-in-the-os-x-firewall-must-be-allowed-to-use-daylite/
									ReportId("TS", src_ip, "TCP_2021", "listening", 'daylite/server not confirmed', ([]))
									ReportId("TS", src_ip, "TCP_4243", "listening", 'daylite/server not confirmed', ([]))
									ReportId("TS", src_ip, "TCP_11000", "listening", 'daylite/server not confirmed', ([]))
									ReportId("TS", src_ip, "TCP_443", "listening", 'daylite/server not confirmed', ([]))
								elif OneAn.rdata in ('_eppc.', '_eppc._tcp.', '_eppc._tcp.local.'):				#https://developer.apple.com/library/archive/qa/qa1312/_index.html
									ReportId("IP", src_ip, "IP", "Remote AppleEvents", OneAn.rdata, ([]))
								elif OneAn.rdata in ('_ftp.', '_ftp._tcp.', '_ftp._tcp.local.'):
									ReportId("TS", src_ip, "TCP_21", "listening", 'ftp/server not confirmed', ([]))
								elif OneAn.rdata in ('_gntp.', '_gntp._tcp.', '_gntp._tcp.local.'):				#http://www.growlforwindows.com/gfw/help/gntp.aspx
									ReportId("TS", src_ip, "TCP_23053", "listening", 'growl/server not confirmed', ([]))
								elif OneAn.rdata in ('_home-sharing.', '_home-sharing._tcp.', '_home-sharing._tcp.local.'):
									ReportId("IP", src_ip, "IP", "iTunes Home Sharing", OneAn.rdata, ([]))
								elif OneAn.rdata in ('_homekit.', '_homekit._tcp.', '_homekit._tcp.local.', '_hap.', '_hap._tcp.', '_hap._tcp.local.'):	#http://dev.iachieved.it/iachievedit/an-in-depth-look-at-apples-homekit/
									ReportId("IP", src_ip, "IP", "Apple Homekit server", '', ([]))
								elif OneAn.rdata in ('_http.', '_http._tcp.', '_http._tcp.local.'):
									ReportId("TS", src_ip, "TCP_80", "listening", 'http/server not confirmed', ([]))
								elif OneAn.rdata in ('_http-alt.', '_http-alt._tcp.', '_http-alt._tcp.local.'):
									ReportId("IP", src_ip, "IP", 'http/server on alternate port not confirmed', '', ([]))
								elif OneAn.rdata in ('_fax-ipp.', '_fax-ipp._tcp.', '_fax-ipp._tcp.local.', '_ipp.', '_ipp._tcp.', '_ipp._tcp.local.', '_sub._ipp._tcp.local.', '_print._sub._ipp._tcp.local.', '_cups._sub._ipp._tcp.local.', '_ipps.', '_ipps._tcp.', '_ipps._tcp.local.', '_sub._ipps._tcp.local.', '_print._sub._ipps._tcp.local.', '_cups._sub._ipps._tcp.local.', '_printer.', '_printer._tcp.', '_printer._tcp.local.'):
									ReportId("TS", src_ip, "TCP_515", "listening", 'printer/server not confirmed', ([]))
									ReportId("US", src_ip, "UDP_515", "listening", 'printer/server not confirmed', ([]))
									ReportId("TS", src_ip, "TCP_631", "listening", 'ipp/server not confirmed', ([]))
									ReportId("US", src_ip, "UDP_631", "listening", 'ipp/server not confirmed', ([]))
									ReportId("TS", src_ip, "TCP_9100", "listening", 'hp-pdl-datastr/server not confirmed', ([]))
									ReportId("US", src_ip, "UDP_9100", "listening", 'hp-pdl-datastr/server not confirmed', ([]))
								elif OneAn.rdata in ('_mediaremotetv.', '_mediaremotetv._tcp.', '_mediaremotetv._tcp.local.'):	#https://github.com/jeanregisser/mediaremotetv-protocol
									ReportId("IP", src_ip, "IP", "Apple TV Remote client or server", '', ([]))
									ReportId("TS", src_ip, "TCP_49152", "listening", 'mediaremotetv/server not confirmed', ([]))	#May not be on this port
								elif OneAn.rdata in ('_mpd.', '_mpd._tcp.', '_mpd._tcp.local.'):				#https://www.musicpd.org/doc/html/user.html#chapter-3-configuration
									ReportId("TS", src_ip, "TCP_6600", "listening", 'musicplayerdaemon/server not confirmed', ([]))
								elif OneAn.rdata in ('_nfs.', '_nfs._tcp.', '_nfs._tcp.local.'):
									ReportId("TS", src_ip, "TCP_111", "listening", 'sunrpc/server not confirmed', ([]))
									ReportId("US", src_ip, "UDP_111", "listening", 'sunrpc/server not confirmed', ([]))
									ReportId("TS", src_ip, "TCP_1110", "listening", 'nfsd-status/server not confirmed', ([]))
									ReportId("US", src_ip, "UDP_1110", "listening", 'nfsd-keepalive/server not confirmed', ([]))
									ReportId("TS", src_ip, "TCP_2049", "listening", 'nfsd/server not confirmed', ([]))
									ReportId("US", src_ip, "UDP_2049", "listening", 'nfsd/server not confirmed', ([]))
									ReportId("TS", src_ip, "TCP_4045", "listening", 'nfslock/server not confirmed', ([]))
									ReportId("US", src_ip, "UDP_4045", "listening", 'nfslock/server not confirmed', ([]))
								elif OneAn.rdata in ('_nvstream_dbd.', '_nvstream_dbd._tcp.', '_nvstream_dbd._tcp.local.'):	#https://www.nvidia.com/en-us/shield/games/gamestream/
									ReportId("IP", src_ip, "IP", "NVidia Gamestream server", '', ([]))
								elif OneAn.rdata in ('_odisk.', '_odisk._tcp.', '_odisk._tcp.local.'):
									ReportId("IP", src_ip, "IP", "Mac OS sharing optical disk not confirmed", '', ([]))
								elif OneAn.rdata in ('_odproxy.', '_odproxy._tcp.', '_odproxy._tcp.local.'):			#https://support.apple.com/en-us/HT202944
									ReportId("TS", src_ip, "TCP_625", "listening", 'odproxy/server not confirmed', ([]))
								elif OneAn.rdata in ('_pdl-datastream.', '_pdl-datastream._tcp.', '_pdl-datastream._tcp.local.'):
									ReportId("TS", src_ip, "TCP_9100", "listening", 'pdl-datastream/server not confirmed', ([]))
								elif OneAn.rdata in ('_presence.', '_presence._tcp.', '_presence._tcp.local.'):
									ReportId("IP", src_ip, "IP", 'xmpp_jabber/server not confirmed', '', ([]))
								elif OneAn.rdata in ('_printer._sub._privet._tcp.local.', '_sub._privet._tcp.local.', '_privet._tcp.local.', '_privet._tcp.', '_privet.'):	#https://developers.google.com/cloud-print/docs/privet
									ReportId("IP", src_ip, "IP", "Google Cloud Print server", '', ([]))
								elif OneAn.rdata in ('_raop.', '_raop._tcp.', '_raop._tcp.local.'):				#https://blog.hyperiongray.com/multicast-dns-service-discovery/
									ReportId("IP", src_ip, "IP", 'AirTunes not confirmed', '', ([]))
								elif OneAn.rdata in ('_remotemouse.', '_remotemouse._tcp.', '_remotemouse._tcp.local.'):	#https://www.informatics.indiana.edu/xw7/papers/bai2016staying.pdf  https://itunes.apple.com/us/app/remote-mouse/id403195710?mt=12  http://www.remotemouse.net/
									ReportId("TS", src_ip, "TCP_1978", "listening", 'remotemouse/server not confirmed', ([]))
									ReportId("US", src_ip, "UDP_1978", "listening", 'remotemouse/server not confirmed', ([]))
									ReportId("TS", src_ip, "TCP_2007", "listening", 'remotemouse/server not confirmed', ([]))
									ReportId("TS", src_ip, "TCP_2008", "listening", 'remotemouse/server not confirmed', ([]))
								elif OneAn.rdata in ('_scanner.', '_scanner._tcp.', '_scanner._tcp.local.'):
									ReportId("IP", src_ip, "IP", 'Scanner not confirmed', '', ([]))
								elif OneAn.rdata in ('_sftp-ssh.', '_sftp-ssh._tcp.', '_sftp-ssh._tcp.local.', '_ssh.', '_ssh._tcp.', '_ssh._tcp.local.', '_udisks-ssh.', '_udisks-ssh._tcp.', '_udisks-ssh._tcp.local.'):
									ReportId("TS", src_ip, "TCP_22", "listening", 'ssh/server not confirmed', ([]))
								elif OneAn.rdata in ('_sleep-proxy.', '_sleep-proxy._udp.', '_sleep-proxy._udp.local.'):	#http://stuartcheshire.org/sleepproxy/
									ReportId("IP", src_ip, "IP", 'Sleep proxy - wake on demand - not confirmed', '', ([]))
								elif OneAn.rdata in ('_smb.', '_smb._tcp.', '_smb._tcp.local.'):
									ReportId("TS", src_ip, "TCP_137", "listening", 'smb/server not confirmed', ([]))
									ReportId("TS", src_ip, "TCP_139", "listening", 'smb/server not confirmed', ([]))
									ReportId("TS", src_ip, "TCP_445", "listening", 'smb/server not confirmed', ([]))
									ReportId("US", src_ip, "UDP_137", "listening", 'smb/server not confirmed', ([]))
									ReportId("US", src_ip, "UDP_138", "listening", 'smb/server not confirmed', ([]))
								elif OneAn.rdata in ('_teamviewer.', '_teamviewer._tcp.', '_teamviewer._tcp.local.'):		#https://superuser.com/questions/387821/how-do-i-tell-if-employees-are-using-teamviewer-at-work/1049611
									ReportId("TS", src_ip, "TCP_5938", "listening", 'teamviewer/server not confirmed', ([]))
									#<DNSRR  rrname='_teamviewer._tcp.local.' type=PTR rclass=IN ttl=4500 rdata='....'		#rdata is digits followed by a periond
								elif OneAn.rdata in ('_touch-able.', '_touch-able._tcp.', '_touch-able._tcp.local.'):
									ReportId("IP", src_ip, "IP", "Apple TV Remote App", OneAn.rdata, ([]))
								elif OneAn.rdata in ('_tunnel.', '_tunnel._tcp.', '_tunnel._tcp.local.'):			#https://tools.ietf.org/html/rfc3620  One system that advertised _tunnel also advertised _bp2p - any relationship?
									ReportId("TS", src_ip, "TCP_604", "listening", 'tunnel/server not confirmed', (['tunnel']))
								elif OneAn.rdata in ('_xcs2p.', '_xcs2p._tcp.', '_xcs2p._tcp.local.'):				#https://github.com/buildasaurs/Buildasaur/issues/166
									ReportId("IP", src_ip, "IP", "XCode Server (likely Mac OS)", OneAn.rdata, ([]))
									ReportId("TS", src_ip, "TCP_22", "listening", 'ssh/server not confirmed', ([]))		#https://support.apple.com/en-us/HT202944
									ReportId("TS", src_ip, "TCP_80", "listening", 'http/server not confirmed', ([]))
									ReportId("TS", src_ip, "TCP_443", "listening", 'https/server not confirmed', ([]))
									ReportId("TS", src_ip, "TCP_3690", "listening", 'svn/server not confirmed', ([]))
									ReportId("US", src_ip, "UDP_3690", "listening", 'svn/server not confirmed', ([]))
									ReportId("TS", src_ip, "TCP_9418", "listening", 'git/server not confirmed', ([]))
									ReportId("US", src_ip, "UDP_9418", "listening", 'git/server not confirmed', ([]))
								elif OneAn.rdata in ('', '_bp2p.', '_bp2p._tcp.', '_bp2p._tcp.local.', '_chat-files.', '_chat-files._tcp.', '_chat-files._tcp.local.', '_companion-link.', '_companion-link._tcp.', '_companion-link._tcp.local.', '_coupon_printer.', '_coupon_printer._tcp.', '_coupon_printer._tcp.local', '_dltouch.', '_dltouch._tcp.', '_dltouch._tcp.local.', '_hearing.', '_hearing._tcp.', '_hearing._tcp.local.', '_mamp.', '_mamp._tcp.', '_mamp._tcp.local.', '_net-assistant.', '_parentcontrol.', '_parentcontrol._tcp.', '_parentcontrol._tcp.local.', '_ptService.', '_ptService._tcp.', '_qmobile.', '_qdiscover.', '_rfb.', '_rfb._tcp.', '_rfb._tcp.local', '_tw-multipeer.', '_tw-multipeer._tcp.', '_tw-multipeer._tcp.local.', '_uscan.', '_uscan._tcp.', '_uscan._tcp.local.', '_uscans.', '_uscans._tcp.', '_uscans._tcp.local.', '_workstation.', '_workstation._tcp.', '_workstation._tcp.local.'):
									pass
								else:
									Debug("service scan reply:" + str(OneAn.rdata))
									ShowPacket(orig_packet, "service scan reply", HonorQuit)
									#quit()

							#<DNSRR  rrname='_kerberos.{machine_name}.local.' type=TXT rclass=IN ttl=4500 rdata='LKDC:SHA1.......' (hash removed)
							elif OneAn.rrname.startswith('_kerberos.') and OneAn.rrname.startswith('.local.') and OneAn.rdata.startswith('LKDC:'):
								#FIXME - extract hostname from the center
								ReportId("DN", src_ip, "PTR", str(OneAn.rrname), 'Kerberos', ([]))
							#<DNSRR  rrname='{machine_name}._device-info._tcp.local.' type=TXT rclass=IN ttl=4500 rdata='model=MacBookPro11,4osxvers=16'
							elif OneAn.rrname.endswith('._device-info._tcp.local.'):
								device_name = OneAn.rrname.replace('._device-info._tcp.local.', '')
								ReportId("IP", src_ip, "IP", device_name, OneAn.rdata, ([]))
							elif OneAn.rrname in ('_presence.', '_presence._tcp.', '_presence._tcp.local.'):			#Book: XMPP: The Definitive Guide: Building Real-Time Applications with Jabber
								#Debug("_presence reply:" + str(OneAn.rdata))
								#ShowPacket(orig_packet, "_presence reply", HonorQuit)
								#Appears to be used by jabber with _presence._tcp.local. PTR username@machine._presence._tcp.local.
								#Requesting a SRV record for username@machine._presence._tcp.local. returns a port and machine to use
								ReportId("IP", src_ip, "IP", "XMPP/Jabber/_presence Owner ID", str(OneAn.rdata), ([]))
							else:
								ReportId("DN", src_ip, "PTR", str(OneAn.rrname), str(OneAn.rdata), ([]))
						else:
							Debug("Odd PTR rrname: " + OneAn.rrname)
					elif OneAn.type == 13:		#"IN" class and "HINFO" answer	https://tools.ietf.org/html/rfc1035
						if OneAn.rrname.endswith('.local.'):
							cpu_name, remainder = extract_len_string(OneAn.rdata)
							os_name, remainder = extract_len_string(remainder)
							ReportId("DN", src_ip, "HINFO", str(OneAn.rrname), "cpu=" + cpu_name + " os=" + os_name, ([]))
						else:
							pass						#Possibly later, save as raw text
							UnhandledPacket(orig_packet)
					elif OneAn.type == 15:		#"IN" class and "MX" answer
						pass							#Possibly later
					elif OneAn.type == 16:		#"IN" class and "TXT" answer
						if OneAn.rrname.endswith('.local.'):
							#Note, this is technically a TXT record, but it's converting an IP address into a hostname (possibly with other stuff), so I'm calling it a PTR
							ReportId("DN", src_ip, "PTR", str(OneAn.rrname), str(OneAn.rdata), ([]))
						else:
							pass						#Possibly later, save as raw text
							UnhandledPacket(orig_packet)
					elif OneAn.type == 17:		#"IN" class and "RP" answer.
						dns_object = str(OneAn.rrname)
						resp_person = OneAn.rdata

						readable_person = ''
						first_word, remainder = extract_len_string(resp_person)
						while first_word:
							readable_person += first_word + '.'
							first_word, remainder = extract_len_string(remainder)

						ReportId("NA", '0.0.0.0', "RP", dns_object, readable_person, ([]))
					elif OneAn.type == 28:		#"IN" class and "AAAA" answer
						DNSIPAddr = OneAn.rdata.upper()
						DNSHostname = OneAn.rrname.lower()
						ReportId("DN", DNSIPAddr, "AAAA", DNSHostname, "", ([]))
					elif OneAn.type == 33:		#"IN" class and "SRV" answer
						if OneAn.rrname.endswith('_presence._tcp.local.'):
							ReportId("DN", src_ip, "SRV", str(OneAn.rrname), str(OneAn.rdata).strip(' \t\r\n\0'), ([]))
						elif OneAn.rrname.endswith('.local.'):
							ReportId("DN", src_ip, "SRV", str(OneAn.rrname), '', ([]))			#Too much garbage in OneAn.rdata to include it as additional info: str(OneAn.rdata).strip(' \t\r\n\0')
						else:
							pass									#Possibly later, save as raw text
							UnhandledPacket(orig_packet)
					elif OneAn.type == 39:		#"IN" class and "DNAME" answer					https://tools.ietf.org/html/rfc6672
						#Similar to a CNAME, but for an entire tree.  A RHS substitution for the request (replace "example.com" with "example.net")
						pass
					elif OneAn.type == 41:		#"IN" class and "OPT" answer used to support EDNS		https://tools.ietf.org/html/rfc6891
						pass
					elif OneAn.type == 46:		#"IN" class and "RRSIG" answer					https://tools.ietf.org/html/rfc4034
						pass
					elif OneAn.type == 50:		#"IN" class and "NSEC3" answer					https://tools.ietf.org/html/rfc5155
						pass
					elif OneAn.type == 52:		#"IN" class and "TLSA" answer					https://tools.ietf.org/html/rfc6698
						pass
					elif OneAn.type == 99:		#"IN" class and "SPF" answer					https://tools.ietf.org/html/rfc7208
						pass
					else:
						ShowPacket(orig_packet, "IN, but unhandled type", HonorQuit)
						Debug("PUDR: IN, but unhandled type: " + str(OneAn.type))
				elif (OneAn.rclass == 0) and (OneAn.type == 255):					#"Reserved" class and "ANY" answer.  WTF?
					UnhandledPacket(orig_packet)
				elif OneAn.rclass == 0:									#"Reserved" class
					UnhandledPacket(orig_packet)
				elif (OneAn.rclass == 3) and (OneAn.type == 16):					#Chaos/CH domain and type TXT
					if OneAn.rrname.upper() == 'VERSION.BIND.':
						ReportId("DN", src_ip, "TXT", OneAn.rdata, 'Chaos/' + OneAn.rrname, ([]))
						ReportId("UC", dst_ip, "TXT", 'open', 'dns/client Chaos/' + OneAn.rrname, (['scan']))
					elif OneAn.rrname.upper() == 'HOSTNAME.BIND.':
						ReportId("DN", src_ip, "PTR", OneAn.rdata, 'Chaos/' + OneAn.rrname, ([]))
						ReportId("UC", dst_ip, "TXT", 'open', 'dns/client Chaos/' + OneAn.rrname, (['scan']))
					else:
						ShowPacket(orig_packet, "DNS Chaos/OTHER answer", HonorQuit)
				elif (OneAn.rclass == 3) and (OneAn.type == 2) and OneAn.rrname.upper() == 'VERSION.BIND.':	#Chaos/CH domain and type NS
					pass
				elif (OneAn.rclass == 254) and (OneAn.type == 5):					#254 => QCLASS NONE and type=CNAME
					UnhandledPacket(orig_packet)
				elif (OneAn.rclass == 255) and (OneAn.type == 250):					#"ANY" class and "TSIG" answer.
					UnhandledPacket(orig_packet)
				elif (OneAn.rclass == 256) and (OneAn.type == 256):					#WTF?
					UnhandledPacket(orig_packet)
				elif (OneAn.type == 41) and OneAn.rrname in ('.', ''):	#OPT AR record for EDNS0; see https://tools.ietf.org/html/rfc6891 . Class holds the UDP payload size
					pass
				else:
					ShowPacket(orig_packet, "unhandled rclass", HonorQuit)
					Debug("PUDR: unhandled rclass: " + str(OneAn.type))

				#Move to the next DNS object in the "an" block
				OneAn = OneAn.payload
		for OneCNAME in CNAMERecs:		#Now that we have all A/PTR's, go back and turn cname records into pseudo-A's
			if isinstance(OneCNAME, DNSRR):
				Alias = OneCNAME.rrname.lower()
				Existing = OneCNAME.rdata.lower()
				if isFQDN(Alias) and isFQDN(Existing):
					if Existing in HostIPs:
						for OneIP in HostIPs[Existing]:				#Loop through each of the IPs for the canonical name, and
							ReportId("DN", OneIP, "CNAME", Alias, "", ([]))	#report them as kind-of A records for the Alias.		#FIXME - change last field to Existing?
					#If we don't have a A/PTR record for "Existing", just ignore it.  Hopefully we'll get the Existing A/PTR in the next few answers, and will re-ask for the CNAME later, at which point we'll get a full cname record.
					#else:
					#	Debug("CNAME " + Alias + " -> " + Existing + " requested, but no IP's for the latter, skipping.")
				else:
					Debug("One of " + Alias + " and " + Existing + " isn't an FQDN, skipping cname processing.")
### rcode=1 FormErr: server responding to an improperly formatted request
	elif p_dns.rcode == 1:
		pass
### rcode=2 ServFail: domain exists, root nameservers list authoritative name servers, but authNS's won't answer queries
	elif p_dns.rcode == 2:
		pass
### rcode=3 NXDOMAIN: root nameservers don't have any listing (domain doesn't exist or is on hold)
	elif p_dns.rcode == 3:
		if ReportNXDomain:
			DNSBlocks = []
			if p_dns.qdcount == 1:		#If we have one question from the question record, process it
				DNSBlocks.append(p_dns.qd)
			else:
				ShowPacket(orig_packet, "DNS Answer with NXDOMAIN, qdcount not equal to 1", KeepGoing)
			for OneAn in DNSBlocks:
				if isinstance(OneAn, DNSQR):
					if OneAn.qclass in (1, 32769):
						#FIXME - add more DNS record types
						if OneAn.qtype == 1:		#"IN" class and "A" type answer
							DNSQuery = OneAn.qname.lower()
							ReportId("DN", "0.0.0.0", "A", DNSQuery, "NXDOMAIN", ([]))
						elif OneAn.qtype == 2:		#"IN" class and "NS" type answer
							DNSQuery = OneAn.qname.lower()
							ReportId("DN", "0.0.0.0", "NS", DNSQuery, "NXDOMAIN", ([]))
						elif OneAn.qtype == 12:		#"IN" class and "PTR" type answer
							DNSQuery = OneAn.qname.lower()
							ReportId("DN", "0.0.0.0", "PTR", DNSQuery, "NXDOMAIN", ([]))
						elif OneAn.qtype == 15:		#"IN" class and "MX" type answer
							DNSQuery = OneAn.qname.lower()
							ReportId("DN", "0.0.0.0", "MX", DNSQuery, "NXDOMAIN", ([]))
						elif OneAn.qtype == 28:		#"IN" class and "AAAA" type answer
							DNSQuery = OneAn.qname.lower()
							ReportId("DN", "0000:0000:0000:0000:0000:0000:0000:0000", "AAAA", DNSQuery, "NXDOMAIN", ([]))
						else:
							ShowPacket(orig_packet, "DNS Answer with NXDOMAIN", KeepGoing)
					else:
						UnhandledPacket(orig_packet)
### rcode=4 Not implemented
	elif p_dns.rcode == 4:
		UnhandledPacket(orig_packet)
### rcode=5 Query refused
	elif p_dns.rcode == 5:
		pass
### rcode=7 YXRRSET - RRset exists when it should not.
	elif p_dns.rcode == 7:
		pass
### rcode=8 NXRRSet - RRset that should exist does not.
	elif p_dns.rcode == 8:
		pass
### rcode=9 Not authoritative https://tools.ietf.org/html/rfc2136 (note, also used as Not Authorized in TSIG update response https://tools.ietf.org/html/rfc2845 )
	elif p_dns.rcode == 9:
		pass
	else:	#rcode indicates an error
		ShowPacket(orig_packet, "process_udp_dns_response/unhandled rcode", HonorQuit)



def process_udp_ports(meta, SrcService, DstService, SrcClient, Payload, p):
	"""Process a UDP packet (ipv4 or ipv6)."""

	#Transition variables
	sIP = meta['sIP']
	dIP = meta['dIP']
	sport = meta['sport']
	dport = meta['dport']


	if dport in PolicyViolationUDPPorts:
		ReportId("UC", sIP, "UDP_" + dport, "open", '', (['portpolicyviolation']))
	if sport in PolicyViolationUDPPorts:
		ReportId("US", sIP, "UDP_" + sport, "open", '', (['portpolicyviolation']))

	if dport == "0":
		ReportId("UC", sIP, "UDP_" + dport, "open", 'Invalid destination port 0', (['noncompliant']))
	if sport == "0":
		ReportId("US", sIP, "UDP_" + sport, "open", 'Invalid source port 0', (['noncompliant']))

	if dport == "0" and Payload == cacti_payload:
		ReportId("UC", sIP, "UDP_" + dport, "open", 'Cacti monitor', (['noncompliant']))
### IP/UDP/qualys
	elif sIP in qualys_scan_ips and dport in qualys_udp_scan_port_names and Payload == nullbyte:
		ReportId("UC", sIP, "UDP_" + dport, "open", qualys_udp_scan_port_names[dport] + "/clientscanner qualys", (['scan']))
	elif sIP in qualys_scan_ips:
		ReportId("UC", sIP, "UDP_" + dport, "open", "udp" + dport + "/clientscanner qualys unregistered port", (['scan']))
	elif sIP.startswith(qualys_subnet_starts) and dport in qualys_udp_scan_port_names and Payload == nullbyte:
		ReportId("UC", sIP, "UDP_" + dport, "open", qualys_udp_scan_port_names[dport] + "/clientscanner qualys unregistered scanner IP address", (['scan']))
	elif sIP.startswith(qualys_subnet_starts):
		ReportId("UC", sIP, "UDP_" + dport, "open", "udp" + dport + "/clientscanner qualys unregistered scanner IP address and unregistered port", (['scan']))
#__ haslayer(DNS)
### IP/UDP/Multicast DNS, placed next to normal dns, out of numerical order
	elif p.haslayer(DNS) and (isinstance(p[DNS], DNS)):
		if (sport == "5353") and (dport == "5353") and (p[DNS].qr == 1):		#qr == 1 is a response
			process_udp_dns_response(sIP, dIP, SrcService, sport, p[DNS], p)
		elif (sport == "5353") and (dport == "5353") and (p[DNS].qr == 0):		#qr == 0 is a request
			process_udp_dns_query(sIP, dIP, DstService, dport, p[DNS], p)
		elif (sport != "5353") and (dport == "5353") and (p[DNS].qr == 0) and meta['ttl'] != 255:	#query from outside local lan; see https://tools.ietf.org/html/rfc6762 section 5.5
			process_udp_dns_query(sIP, dIP, DstService, dport, p[DNS], p)
			ReportId("UC", sIP, "UDP_" + dport, "open", "mdns/client", (['external']))
		elif (sport == "5353") and (dport != "5353") and (p[DNS].qr == 1):		#response to outside local lan; see https://tools.ietf.org/html/rfc6762 section 5.5
			ReportId("US", sIP, "UDP_" + sport, "open", "mdns/server", ([]))
			process_udp_dns_response(sIP, dIP, SrcService, sport, p[DNS], p)
### IP/UDP/DNS=53
		elif (sport == "53") and (p[DNS].qr == 1):					#qr == 1 is a response.  Note, case where sport=53 but no dns layer is at the end of the udp ports
			process_udp_dns_response(sIP, dIP, SrcService, sport, p[DNS], p)
		elif (dport == "53") and (p[DNS].qr == 0):	#dns query
			process_udp_dns_query(sIP, dIP, DstService, dport, p[DNS], p)
			ReportId("UC", sIP, "UDP_" + dport, "open", "dns/client", ([]))	#FIXME - removeme
		elif (sport != "53") and (dport == "53") and (p[DNS].qr == 1):			#dns response coming in from what looks like a DNS client.
			UnhandledPacket(p)
		elif (sport == "53") and (p[DNS].rcode == 2):					#source port 53, but the server is sending back server-failure.
			UnhandledPacket(p)
		else:
			ShowPacket(p, "IP/UDP/unhandled packet with DNS layer", HonorQuit)

	#FIXME - copy over to mdns and ipv6
	elif (sport == "5353") and (dport == "5353") and not p.haslayer(DNS):									#No dns layer for some reason
		UnhandledPacket(p)
	elif (dport == "5353") and ((meta['ttl'] == 1) or (meta['ttl'] == 2) or (meta['ttl'] == 255)):		#2 may not be rfc-legal, but I'm seeing it on the wire.
		if dIP in ("224.0.0.251", "ff02::fb", "ff02:0000:0000:0000:0000:0000:0000:00fb"):
			ReportId("UC", sIP, "UDP_" + dport, "open", "mdns/broadcastclient", ([]))
		else:
			ReportId("UC", sIP, "UDP_" + dport, "open", "mdns/client", ([]))


	#FIXME - add check for "if isinstance(p[DNS],  whatevertype):	here and at all p[] accesses.
	elif (sport != "53") and (dport == "53") and not p.haslayer(DNS):						#non-dns coming in from what looks like a DNS client.
		UnhandledPacket(p)
#Handle easily categorized services early
	elif dport in PriUDPPortNames:								#Client talking to server
		warning_list = []
		if dport in udp_port_warnings:
			warning_list = [udp_port_warnings[dport]]
		ReportId("UC", sIP, "UDP_" + dport, "open", str(PriUDPPortNames[dport]) + "/client", (warning_list))	#'portonlysignature'
	elif sport in PriUDPPortNames:								#server talking to client
		warning_list = []
		if dport in udp_port_warnings:
			warning_list = [udp_port_warnings[dport]]
		ReportId("US", sIP, "UDP_" + sport, "open", str(PriUDPPortNames[sport]) + "/server", (warning_list))	#'portonlysignature'
### IP/UDPv4/bootp_dhcp=67
	elif meta['ip_class'] == '4' and (sport == "67") and (dport == "68"):		#Bootp/dhcp server talking to client
		ReportId("US", sIP, "UDP_" + sport, "open", "bootpordhcp/server", ([]))
	elif meta['ip_class'] == '4' and (sport == "68") and (dport == "67"):		#Bootp/dhcp client talking to server
		#FIXME - pull ID field out as a name to report
		if sIP != "0.0.0.0":				#If the client is simply renewing an IP, remember it.
			ReportId("UC", sIP, "UDP_" + dport, "open", "bootpordhcp/client", ([]))
			for one_opt in p[DHCP].options:				#Can't directly access p.haslayer(DHCPOptions) because it's a list of tuples.  https://stackoverflow.com/questions/22152130/how-can-i-get-option-number-from-an-dhcp-header-in-scapy
				if one_opt[0] == 'hostname':
					ReportId("NA", sIP, "DHCP", one_opt[1], "dhcp", ([]))
		#else:						#If you want to record which macs are asking for addresses, do it here.
		#	pass

#__ haslayer(TFTP)
### IP/UDP/TFTP=69
	elif p.haslayer(TFTP):
		if (dport == "69"):
			ReportId("UC", sIP, "UDP_" + dport, "open", 'tftp/client', (['plaintext', 'portpolicyviolation']))
		elif (sport == "69"):
			ReportId("US", sIP, "UDP_" + sport, "open", 'tftp/server', (['plaintext', 'portpolicyviolation']))
		else:
			ShowPacket(p, "IP/UDP/unhandled packet with TFTP layer", HonorQuit)

### IP/UDP/udp_http=80 nmap quic scan
	elif (dport == "80") and (Payload == '\r12345678Q999' + nullbyte):
		ReportId("UC", sIP, "UDP_" + dport, "open", "udp-http/client nmap QUIC scan", (['scan']))
### IP/UDP/udp_http=80 with empty payload
	elif (dport == "80") and ((Payload is None) or (Payload == '')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "null-udp-http/client", ([]))
### IP/UDP/udp_http=80 with torrent current connection id payload		https://gist.github.com/xboston/6130535
	elif (dport == "80") and Payload and (Payload.startswith(torrent_connection_id)):
		ReportId("UC", sIP, "UDP_" + dport, "open", "udp-http/client torrent current connection id", ([]))
### IP/UDP/udp_http=80
	elif sport == "80":							#udp http response
		ReportId("US", sIP, "UDP_" + sport, "open", "udp-http/server", ([]))				#'portonlysignature'
	elif dport == "80":							#udp http request
		ReportId("UC", sIP, "UDP_" + dport, "open", "udp-http/client", ([]))				#'portonlysignature'
### IP/UDP/ntp=123
	elif dport == "123" and Payload.startswith(ntp_get_monlist):		#https://www.micron21.com/blog/2014/03/mechanics-of-ntp-ddos/ http://www.korznikov.com/2014/08/amplified-denial-of-service-with.html
		ReportId("UC", sIP, "UDP_" + dport, "open", 'ntp/client REQ_MON_GETLIST_1: Likely spoofed and DDOSed source IP', (['amplification', 'spoofed', 'dos']))
	elif (dport == "123") and dIP in vonage_ntp:
		ReportId("UC", sIP, "UDP_" + dport, "open", "ntp/vonageclient", ([]))
	elif (sport == "123") and sIP in vonage_ntp:
		ReportId("US", sIP, "UDP_" + sport, "open", "ntp/vonageserver", ([]))

#__ haslayer(NTPHeader)
	elif has_advanced_ntp_headers and p.haslayer(NTPHeader):
		if sport != "123" and dport == "123" and str(p.getlayer(NTPHeader)).find('>/dev/null 2>&1\nchmod 777') > -1:
			ReportId("UC", sIP, "UDP_" + dport, "open", "udp123/client sending shellcode", (['malicious']))
		elif (sport == "123") or (dport == "123"):
			ntp_stratum = p[NTPHeader].stratum
			#What comes back in the "id" field is either an IPv4 address of sIP's primary reference (good!) or
			#the first 4 bytes of the MD5 hash of the IPv6 address of sIP's primary reference (bad.)  Without actively
			#checking, there's no way to distinguish the two cases.  https://www.nwtime.org/ntps-refid/
			ntp_id = p[NTPHeader].id
			ntp_ref_id = str(p[NTPHeader].ref_id).rstrip(' \t\r\n\0')
			if ntp_id:
				ReportId("US", sIP, "UDP_" + sport, "open", 'ntp/server stratum=' + str(ntp_stratum) + ' reference=' + str(ntp_id), ([]))
				ReportId("US", ntp_id, "UDP_" + sport, "open", 'ntp/server inferred from being a reference but must be checked.', ([]))
			elif ntp_ref_id in known_ntp_refs:
				ReportId("US", sIP, "UDP_" + sport, "open", 'ntp/server stratum=' + str(ntp_stratum), ([]))
			else:
				ReportId("US", sIP, "UDP_" + sport, "open", 'ntp/server stratum=' + str(ntp_stratum), ([]))
				#ShowPacket(p, "IP/UDP/ntp with null reference:_" + str(ntp_ref_id) + "_", HonorQuit)				#Even after adding 'i' to known_ntp_refs, this still kept tripping.
		else:
			ShowPacket(p, "IP/UDP/unhandled packet with NTPHeader layer", HonorQuit)

#__ haslayer(NTPPrivate)
	elif has_advanced_ntp_headers and p.haslayer(NTPPrivate):
		if (dport == "123") and p[NTPPrivate].response == 0:				#response == 0 is a request
			if p[NTPPrivate].request_code == 42:					#REQ_MON_GETLIST_1
				ReportId("UC", sIP, "UDP_123", "open", 'ntp/client REQ_MON_GETLIST_1: Likely spoofed and DDOSed source IP', (['amplification', 'spoofed']))
			elif p[NTPPrivate].request_code == 32:					#REQ_REQUEST_KEY
				ReportId("UC", sIP, "UDP_123", "open", 'ntp/client', ([]))
			else:
				ShowPacket(p, "IPv4/UDPv4/ntp Mode 7 request but not REQ_MON_GETLIST_1", HonorQuit)
		elif (sport == "123") and p[NTPPrivate].response == 1:					#response == 1 is a reply
			if p[NTPPrivate].request_code == 42:						#REQ_MON_GETLIST_1
				ReportId("US", sIP, "UDP_123", "open", 'ntp/server REQ_MON_GETLIST_1: Likely middleman in DDOS', (['amplification', 'dos']))
			else:
				ShowPacket(p, "IPv4/UDPv4/ntp Mode 7 reply but not REQ_MON_GETLIST_1", HonorQuit)
		else:
			ShowPacket(p, "IP/UDP/unhandled packet with NTPPrivate layer", HonorQuit)

#__ haslayer(NTPControl)
	elif has_advanced_ntp_headers and p.haslayer(NTPControl):
		if dport == "123":
			ReportId("UC", sIP, "UDP_123", "open", 'ntp_control/client', ([]))
		else:
			ShowPacket(p, "IP/UDP/unhandled packet with NTPControl layer", HonorQuit)

	elif (not has_advanced_ntp_headers) and ((sport == "123") or (dport == "123")):
		UnhandledPacket(p)							#Unfortunately, this version of scapy is too old to handle the new NTP headers.
### IP/UDP/pwdgen=129		https://tools.ietf.org/html/rfc972
	elif (dport == "129") and (Payload == "\n"):
		ReportId("UC", sIP, "UDP_" + dport, "open", "pwdgen/client", ([]))
### IP/UDP/135
	elif sIP.startswith('64.39.99.') and dport == "135" and Payload.endswith('QUALYSGUARD123'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "epmap/clientscanner", (['scan']))
	elif dport == "135" and Payload.find('NTLMSSP') > -1:
		ReportId("UC", sIP, "UDP_" + dport, "open", "epmap/client", ([]))

#__ haslayer(NBNSQueryRequest)
### IP/UDP/netbios-ns=137 query
	elif p.haslayer(NBNSQueryRequest):
		if dport == "137":
			if meta['dMAC'] == "ff:ff:ff:ff:ff:ff":				#broadcast
				ReportId("UC", sIP, "UDP_" + dport, "open", "netbios-ns/broadcastclient", ([]))
			elif Payload and (Payload.find('CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA') > -1):	#wildcard
				ReportId("UC", sIP, "UDP_" + dport, "open", "netbios-ns/wildcardclient", (['amplification', 'spoofed']))
			else:
				ReportId("UC", sIP, "UDP_" + dport, "open", "netbios-ns/unicastclient", ([]))
				UnhandledPacket(p)
		else:
			ShowPacket(p, "IP/UDP/unhandled packet with NBNSQueryRequest layer", HonorQuit)

#__ haslayer(NBNSQueryResponse)
### IP/UDP/netbios-ns=137 response
	elif p.haslayer(NBNSQueryResponse):
		if sport == "137":
			netbios_hostname = p[NBNSQueryResponse].RR_NAME.rstrip().rstrip(nullbyte)
			netbios_address = p[NBNSQueryResponse].NB_ADDRESS.rstrip()
			ReportId("US", sIP, "UDP_" + sport, "open", "netbios-ns", ([]))
			ReportId("NA", netbios_address, "PTR", netbios_hostname, "netbios-ns", ([]))
		else:
			ShowPacket(p, "IP/UDP/unhandled packet with NBNSQueryResponse layer", HonorQuit)

#__ haslayer(NBTDatagram)
### IP/UDP/netbios-dgm=138 query
	elif p.haslayer(NBTDatagram):
		netbios_hostname = p[NBTDatagram].SourceName.rstrip()
		ReportId("NA", sIP, "PTR", netbios_hostname, "netbios-dgm", ([]))
		if (sport == "138") and (dport == "138"):
			ReportId("US", sIP, "UDP_" + dport, "open", "netbios-dgm", ([]))
		elif sport == "138":
			ReportId("US", sIP, "UDP_" + sport, "open", "netbios-dgm", ([]))
		elif dport == "138":
			ReportId("UC", sIP, "UDP_" + dport, "open", "netbios-dgm/" + meta['cast_type'] +  "client", ([]))
		else:
			ShowPacket(p, "IP/UDP/unhandled packet with NBTDatagram layer", HonorQuit)

#__ haslayer(SNMP)
### IP/UDP/SNMP=161
	elif p.haslayer(SNMP):
		snmp_community_string = remove_control_characters(str(p[SNMP].community)).strip(' \t\r\n\0')
		if dport == "161" and (p.haslayer(SNMPget) or p.haslayer(SNMPbulk) or p.haslayer(SNMPvarbind)):
			if ShowCredentials:
				ReportId("UC", sIP, "UDP_" + dport, "open", "snmp/client community string:" + snmp_community_string, (['plaintext']))
			else:
				ReportId("UC", sIP, "UDP_" + dport, "open", 'snmp/client', (['plaintext']))
		elif sport == "161" and p.haslayer(SNMPresponse):
			if ShowCredentials:
				ReportId("US", sIP, "UDP_" + sport, "open", "snmp/server community string:" + snmp_community_string, (['plaintext']))
			else:
				ReportId("US", sIP, "UDP_" + sport, "open", 'snmp/server', (['plaintext']))
		else:
			ShowPacket(p, "IP/UDP/unhandled packet with SNMP layer", HonorQuit)

	elif sport == "161" or dport == "161":
		UnhandledPacket(p)
### IP/UDP/svrloc=427	https://tools.ietf.org/html/rfc2608
	elif dport == "427" and Payload and (Payload.find('service:') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "svrloc/client", ([]))
### IP/UDP/isakmp=500
	elif (sport == "500") and (dport == "500") and isinstance(p[ISAKMP], ISAKMP) and (p[ISAKMP].init_cookie != ''):
		ReportId("US", sIP, "UDP_" + sport, "open", "isakmp/generic", ([]))
### IP/UDP/biff=512
	elif dport == "512" and Payload and (Payload.find('@') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "biff/client", ([]))
### IP/UDP/syslog=514	https://www.ietf.org/rfc/rfc3164.txt
	elif dport == "514" and Payload and Payload.startswith('<') and (Payload[2] == '>' or Payload[3] == '>' or Payload[4] == '>'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "syslog/client", (['plaintext']))
		ReportId("US", dIP, "UDP_" + dport, "open", "syslog/server not confirmed", (['plaintext']))

		hostname_and_process = SyslogMatch.search(Payload)
		if (hostname_and_process is not None) and (len(hostname_and_process.groups()) >= 2):
			syslog_hostname = hostname_and_process.group(1)
			ReportId("NA", sIP, "PTR", syslog_hostname, "syslog", (['plaintext']))
			process_name = hostname_and_process.group(2)
			ReportId("IP", sIP, "IP", "live", 'running process: ' + process_name, (['plaintext']))
		else:
			#ShowPacket(p, "Syslog that does not match regex", HonorQuit)
			UnhandledPacket(p)
### IP/UDP/snmp on alternate ports
	elif (dport in snmp_altport) and Payload and (Payload.find('public') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "snmp-altport/client", (['nonstandardport']))
### IP/UDP/ibm-db2=523 client
	elif (dport == "523") and Payload and (Payload.find('DB2GETADDR') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "ibm-db2/clientscanner", (['scan']))
### IP/UDP/DHCPv6=547 request
	elif meta['ip_class'] == '6' and (sport == "546") and (dport == "547") and dIP in ("ff02::1:2", "ff02:0000:0000:0000:0000:0000:0001:0002"):
		ReportId("UC", sIP, "UDP_" + dport, "open", "UDP DHCPv6", ([]))
	elif meta['ip_class'] == '6' and (sport == "546") and (dport == "547"):	#dhcp request
		ShowPacket(p, "IPv6/UDPv6/546-547-ff02::1:2 DHCP Request", HonorQuit)
### IP/UDP/DHCPv6=547 reply
	elif meta['ip_class'] == '6' and (sport == "547") and (dport == "546"):
		pass
### IP/UDP/SIP sipvicious scanner and other SIP clients.  https://www.nurango.ca/blog/sipvicious-the-not-so-friendly-scanner , http://www.hackingvoip.com/presentations/sample_chapter3_hacking_voip.pdf p54
#We used to look for 'User-Agent: friendly-scanner', but this is for sipvicious only.  'Via: SIP/2.0/UDP ' is more general.
# https://github.com/EnableSecurity/sipvicious
	elif (dport in sip_altport) and Payload and Payload.startswith(('100@', '19179001661@', 'CANCEL sip:', 'INVITE sip:', 'OPTIONS sip:', 'REGISTER sip:')) and (Payload.find(': SIP/2.0/UDP ') > -1):		#Looking for 'Via: SIP/2.0/UDP ' or 'v: SIP/2.0/UDP'
		if dport == "5061":
			base_description = "sip-tls/client"
		else:
			base_description = "sip/client"
		additional_info = ""
		num_1111s = 0
		FromMatch = SIPFromMatch.search(Payload)
		if (FromMatch is not None) and (len(FromMatch.groups()) >= 2):
			additional_info = additional_info + " From:" + FromMatch.group(1) + "(" + FromMatch.group(2) + ")"
			if FromMatch.group(1) in ("100", "132") and FromMatch.group(2) == "1.1.1.1":
				num_1111s += 1
		ToMatch = SIPToMatch.search(Payload)
		if (ToMatch is not None) and (len(ToMatch.groups()) >= 2):
			additional_info = additional_info + " To:" + ToMatch.group(1) + "(" + ToMatch.group(2) + ")"
			if ToMatch.group(1) in ("100", "132") and ToMatch.group(2) == "1.1.1.1":
				num_1111s += 1
		if num_1111s == 2:
			base_description = 'sipscanner/client'
		if dport in ("5060", "5061"):
			ReportId("UC", sIP, "UDP_" + dport, "open", base_description + additional_info, (['scan']))
		else:
			ReportId("UC", sIP, "UDP_" + dport, "open", base_description + additional_info, (['nonstandardport', 'scan']))
### IP/UDP/626 serialnumberd	https://svn.nmap.org/nmap/nmap-payloads
	elif (dport == "626") and (Payload == 'SNQUERY: 127.0.0.1:AAAAAA:xsvr'):		#nmap serialnumberd scan
		ReportId("UC", sIP, "UDP_" + dport, "open", "serialnumberd/clientscanner likely nmap scan", (['scan']))
### IP/UDP/636,992,993 make sure this follows snmp_altport line  Payload contains \x03www\x03163\x03com
	elif dport in www163com_ports and Payload and (Payload.find(www163com_payload) > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "scan_www163com/client", (['scan']))
### IP/UDP/udp-ldaps=636
	elif dport in fenull_scan_names and Payload.startswith("8") and Payload.endswith(fenulls):
		ReportId("UC", sIP, "UDP_" + dport, "open", fenull_scan_names[dport] + "/client", (['scan']))
### IP/UDP/loadav=750
	elif dport == '750' and Payload and Payload.find(nullbyte + 'NESSUS.ORG' + nullbyte) > -1:
		if sIP in nessus_scan_ips:
			ReportId("UC", sIP, "UDP_" + dport, "open", "loadav/clientscanner nessus scanner", (['scan']))
		else:
			ReportId("UC", sIP, "UDP_" + dport, "open", "loadav/clientscanner nessus unregistered scanner IP address", (['scan']))
### IP/UDP/winpopup	winpopup spam client
	elif dport in ("1026", "1027", "1028") and Payload and ((Payload.find('Download Registry Update from:') > -1) or (Payload.find('CRITICAL ERROR MESSAGE! - REGISTRY DAMAGED AND CORRUPTED.') > -1) or (Payload.find('Your system registry is corrupted and needs to be cleaned immediately.') > -1) or (Payload.find('CRITICAL SYSTEM ERRORS') > -1)):
		ReportId("UC", sIP, "UDP_" + dport, "open", "winpopup/spamclient", (['malicious']))
### IP/UDP/sharemouse=1046 rc_iamhere sharemouse	https://www.hybrid-analysis.com/sample/ca51df55d9c938bf0dc2ecbc10b148ec5ab8d259f3ea97f719a1a498e128ee05?environmentId=100
	elif sport == "1046" and dport == "1046" and (meta['dMAC'] == "ff:ff:ff:ff:ff:ff") and Payload and Payload.startswith('rc_iamhere:6555:0:0:'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "sharemouse/broadcastclient rc_iamhere sharemouse trojan", (['malicious']))
		ReportId("NA", sIP, "NA", Payload[20:], "sharemouse trojan", (['malicious']))
### IP/UDP/udp1124=1124 used by printers
	elif (dport == "1124") and (meta['dMAC'] == "ff:ff:ff:ff:ff:ff") and Payload and (Payload.find('std-scan-discovery-all') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "udp1124/broadcast", ([]))
### IP/UDP/search-agent=1234 used by stora NAS
	elif (dport == "1234") and (meta['dMAC'] == "ff:ff:ff:ff:ff:ff") and Payload and (Payload.find('Hello there. I am at ') > -1):
		HostnameMatch = StoraHostnameMatch.search(Payload)
		if (HostnameMatch is not None) and (len(HostnameMatch.groups()) >= 1):
			ReportId("UC", sIP, "UDP_" + dport, "open", "stora_nas_scan/broadcast hostname: " + HostnameMatch.group(1), ([]))
		else:
			ReportId("UC", sIP, "UDP_" + dport, "open", "stora_nas_scan/broadcast", ([]))
### IP/UDP/mssql=1434	Probable mssql attack
	elif dport == "1434" and Payload and (Payload.find('Qh.dll') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "mssql/clientattack", (['malicious']))
	elif dport == "1434" and Payload and Payload in (twobyte, twozero):		#https://portunus.net/2015/01/21/mc-sqlr-amplification/ .  Text refers to a one-byte \x02, but I've seen \x02\x00 as well.
		ReportId("UC", sIP, "UDP_" + dport, "open", "mssql/client nmap ping scan", (['amplification', 'ddos', 'scan']))
### IP/UDP/kdeconnect=1716
	elif sport == "1716" and dport == "1716" and (meta['dMAC'] == "ff:ff:ff:ff:ff:ff") and Payload and (Payload.find('kdeconnect.') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "kdeconnect/broadcast", ([]))
	elif sport == "1716" and dport == "1716" and Payload and (Payload.find('kdeconnect.') > -1):
		ReportId("US", sIP, "UDP_" + sport, "open", 'kdeconnect/server', ([]))

#__ haslayer(Radius)
### IP/UDP/radius=1812
	elif p.haslayer(Radius):
		if sport == "1812":
			ReportId("US", sIP, "UDP_1812", "open", 'radius/server', ([]))
		elif dport == "1812":
			ReportId("UC", sIP, "UDP_1812", "open", 'radius/client', ([]))
		else:
			ShowPacket(p, "IP/UDP/unhandled packet with Radius layer", HonorQuit)

	elif (sport == "1813") and (dport == "1900"):		#Scapy misparses this as Radius accounting, when it's SSDP.  Ignore.
		pass
### IP/UDP/ssdp=1900	https://embeddedinn.wordpress.com/tutorials/upnp-device-architecture/
	elif dport in ("1900", "1990", "32412", "32414") and dIP in ("255.255.255.255", "239.255.255.250", "ff02:0000:0000:0000:0000:0000:0000:000c", "ff05:0000:0000:0000:0000:0000:0000:000c", "ff08:0000:0000:0000:0000:0000:0000:000c", "ff0e:0000:0000:0000:0000:0000:0000:000c") and Payload and (Payload.startswith(('M-SEARCH', 'B-SEARCH'))):		#ssdp discover
		if dport == "1900":
			ssdp_warns = []
		else:
			ssdp_warns = ['nonstandardport']
		ReportId("UC", sIP, "UDP_" + dport, "open", "ssdp-discovery/broadmulticastclient", (ssdp_warns))
	elif (dport == "1900") and Payload and (Payload.startswith(('M-SEARCH', 'B-SEARCH'))):		#ssdp discover
		ReportId("UC", sIP, "UDP_" + dport, "open", "ssdp-discovery/client", ([]))
	elif (dport == "1900") and dIP in ("255.255.255.255", "239.255.255.250", "ff02:0000:0000:0000:0000:0000:0000:000c", "ff05:0000:0000:0000:0000:0000:0000:000c", "ff08:0000:0000:0000:0000:0000:0000:000c", "ff0e:0000:0000:0000:0000:0000:0000:000c") and Payload and (Payload.startswith('NOTIFY')):		#ssdp announcement
		additional_info = ''
		LocationMatch = SSDPLocationMatch.search(Payload)
		if (LocationMatch is not None) and (len(LocationMatch.groups()) >= 1):
			additional_info = additional_info + ' SSDP Location: ' + str(LocationMatch.group(1)).strip()
		ServerMatch = SSDPServerMatch.search(Payload)
		if (ServerMatch is not None) and (len(ServerMatch.groups()) >= 1):
			additional_info = additional_info + ' SSDP Server: ' + str(ServerMatch.group(1)).replace(',', ' ').strip()
		ReportId("UC", sIP, "UDP_" + dport, "open", "ssdp-announce/client" + additional_info, ([]))
	elif dport in ("1900", "11211") and Payload and (Payload == 'GET / HTTP/1.1\r\n\r\n'):		#bogus GET packet
		ReportId("UC", sIP, "UDP_" + dport, "open", "ssdp-bogus-get/clientscanner", (['scan']))
	elif (dport == "1900") and dIP in ("239.255.255.250", "ff02:0000:0000:0000:0000:0000:0000:000c", "ff05:0000:0000:0000:0000:0000:0000:000c", "ff08:0000:0000:0000:0000:0000:0000:000c", "ff0e:0000:0000:0000:0000:0000:0000:000c"):		#ssdp
		ShowPacket(p, "IP/UDP/1900-multicast SSDP unknown method", HonorQuit)
### IP/UDP/hsrp=1985	https://en.wikipedia.org/wiki/Hot_Standby_Router_Protocol	https://tools.ietf.org/html/rfc2281
	elif sport in ("1985", "2029") and dport in ("1985", "2029") and meta['ttl'] == 1 and dIP in ('224.0.0.2', '224.0.0.102', 'ff02::66', 'ff02:0000:0000:0000:0000:0000:0000:0066'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "hsrp/multicastclient", ([]))
		ReportId("RO", sIP, "HSRP", "router", "", ([]))
### IP/UDP/ethernetip=2222	http://kazanets.narod.ru/files/Acro_ethernetIP_747a.pdf , see "CIP Encapsulation Message"
	elif (dport == "2222") and Payload and Payload.startswith(ethernetip_list_identity):
		ReportId("UC", sIP, "UDP_" + dport, "open", "ethernetip/clientscanner", (['scan']))
### IP/UDP/msopid=2223	http://www.crufty.net/sjg/blog/osx-and-office-do-not-mix.htm
	elif (dport == "2223") and (meta['cast_type'] == "broadcast") and Payload and Payload.startswith('MSOPID'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "msopid/clientscanner", (['scan']))
### IP/UDP/digiman=2362
	elif (dport == "2362") and Payload and Payload.startswith('DIGI'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "digiman/client", ([]))
### IP/UDP/sybase=2638
	elif (dport == "2638") and Payload and (Payload.find('CONNECTIONLESS_TDS') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "sybase/client", (['scan']))
### IP/UDP/mdap-port=3235
	elif (dport == "3235") and Payload and Payload.startswith('ANT-SEARCH MDAP/1.1'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "mdap-port/client", ([]))
### IP/UDP/enpc=3289
	elif (dport == "3289") and (meta['dMAC'] == "ff:ff:ff:ff:ff:ff"):
		if Payload and (Payload.startswith('EPSON')):
			ReportId("UC", sIP, "UDP_" + dport, "open", "enpc/broadcast", ([]))
		else:
			UnhandledPacket(p)
### IP/UDP/teredo=3544	https://tools.ietf.org/html/rfc4380
	elif (dport == "3544") and Payload:	#and Payload.startswith(fournulls):	#Signature needs improvement
		ReportId("UC", sIP, "UDP_" + dport, "open", "teredo/client", ([]))
		UnhandledPacket(p)
### IP/UDP/upnp-discovery=3702
	elif (dport == "3702") and Payload and (Payload.startswith('<?xml') or Payload.find('://schemas.xmlsoap.org/') > -1):
		if dIP in ("239.255.255.250", "ff02::c", "ff02:0000:0000:0000:0000:0000:0000:000c"):
			ReportId("UC", sIP, "UDP_" + dport, "open", "upnp-discovery/broadcastclient", ([]))
		else:
			ReportId("UC", sIP, "UDP_" + dport, "open", "upnp-discovery/client", ([]))
### IP/UDP/bfd-control=3784		https://tools.ietf.org/html/rfc5881
	elif (dport == "3784") and (meta['ttl'] == 255):
		#FIXME - add check that sport must be between 49152 and 65535
		ReportId("UC", sIP, "UDP_" + dport, "open", "bfd-control/client", ([]))
### IP/UDP/xpl=3865
	elif (dport == "3865") and (dIP == "255.255.255.255"):					#XPL, http://wiki.xplproject.org.uk/index.php/Main_Page
		ReportId("UC", sIP, "UDP_" + dport, "open", "xpl/client", ([]))
### IP/UDP/vertx=4070	https://github.com/brad-anton/VertX/blob/master/VertX_Query.py
	elif (dport == "4070") and (Payload == 'discover;013;'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "vertx/client", (['scan']))

#__ haslayer(ESP)
### IP/UDP/esp=4500	https://learningnetwork.cisco.com/thread/76175
	elif p.haslayer(ESP):
		if dport == "4500":
			if p[ESP].data == 'TP/1.1\r\nHost: www\r\n\r\n':
				ReportId("UC", sIP, "UDP_" + dport, "open", "esp/client", (['scan', 'tunnel']))
			else:
				ReportId("UC", sIP, "UDP_" + dport, "open", "esp/client", (['tunnel']))
		elif sport == "4500":
			ReportId("US", sIP, "UDP_" + sport, "open", "esp/server", (['tunnel']))
		else:
			ShowPacket(p, "IP/UDP/unhandled packet with ESP layer", HonorQuit)

### IP/UDP/drobo=5002 used by drobo NAS
	elif (dport == "5002") and Payload and Payload.startswith('DRINETTM'):
			ReportId("UC", sIP, "UDP_" + dport, "open", "drobo_nas_scan/" + meta['cast_type'] + "client", ([]))
### IP/UDP/vonage
	elif (sport == "5061") and (dport == "5061") and (dIP in vonage_sip_servers):		#Vonage SIP client
		if Payload and (Payload.find('.vonage.net:5061 SIP/2.0') > -1):
			SipMatch = SipPhoneMatch.search(Payload)
			if (SipMatch is not None) and (len(SipMatch.groups()) >= 1):
				ReportId("UC", sIP, "UDP_" + dport, "open", "sip/vonage_client, phone number: " + SipMatch.group(1), ([]))
			else:
				ReportId("UC", sIP, "UDP_" + dport, "open", "sip/vonage_client", ([]))
		else:
			UnhandledPacket(p)
	elif (sport == "5061") and (dport == "5061") and (sIP in vonage_sip_servers):	#Vonage SIP server
		if Payload and (Payload.find('.vonage.net:5061>') > -1):
			ReportId("US", sIP, "UDP_" + sport, "open", "sip/vonage_server", ([]))
		else:
			UnhandledPacket(p)
### IP/UDP/nat-pmp=5351	http://miniupnp.free.fr/nat-pmp.html , https://tools.ietf.org/html/rfc6886
	elif dport == "5351":
		if Payload and Payload.startswith(nullbyte * 2):						#\x00\x00 is Public address request
			ReportId("UC", sIP, "UDP_" + dport, "open", "nat-pmp-public-address-discovery/client", (['scan']))
		elif Payload and Payload.startswith((zeroone, zerotwo)):					#\x00\x0[12] is mapping request
			ReportId("UC", sIP, "UDP_" + dport, "open", "nat-pmp-mapping-request/client", ([]))
		else:
			ShowPacket(p, "IPv4/UDPv4/5351 nat-pmp unknown payload", HonorQuit)

#__ haslayer(LLMNRQuery)
### IP/UDP/llmnr=5355 query
	elif p.haslayer(LLMNRQuery):
		if (dport == "5355") and dIP in ("224.0.0.252", "ff02::1:3", "ff02:0000:0000:0000:0000:0000:0001:0003") and (meta['ttl'] in (1, 255)) and (p[LLMNRQuery].qr == 0): #llmnr (link-local multicast node resolution)
			UnhandledPacket(p)
		else:
			ShowPacket(p, "IP/UDP/unhandled packet with LLMNRQuery layer", HonorQuit)

### IP/UDP/llmnr=5355 response
	elif (dport == "5355") and dIP in ("224.0.0.252", "ff02::1:3", "ff02:0000:0000:0000:0000:0000:0001:0003") and (meta['ttl'] in (1, 255)): #llmnr (link-local multicast node resolution)
		ShowPacket(p, "IP/UDP/5355-224.0.0.252,ff02::1:3 llmnr not query", HonorQuit)
		#Can we pass this off to PUDR?
	elif dport == "5355":							#unicast fe80->fe80 llmnr (link-local multicast node resolution)
		ShowPacket(p, "IP/UDP/5355 unicast llmnr not to 224.0.0.252,1:3", HonorQuit)
### IP/UDP/corosync=5405 used by corosync
	elif (dport == "5405") and (meta['dMAC'] == "ff:ff:ff:ff:ff:ff"):
		ReportId("UC", sIP, "UDP_" + dport, "open", "corosync/broadcast", ([]))
### IP/UDP/pcanywherestat=5632 client
	elif (dport == "5632") and Payload and (Payload.find('NQ') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "pcanywherestat/clientscanner", (['scan']))
	elif (sport == "6515") and (dport == "6514") and (dIP == "255.255.255.255"):		#mcafee ASaP broadcast, looking for a proxy out.  http://www.myasap.de/intl/EN/content/virusscan_asap/faq_new.asp
		if Payload and (Payload.find('<rumor version=') > -1):
			ReportId("UC", sIP, "UDP_" + dport, "open", "asap/client", ([]))
		else:
			UnhandledPacket(p)
### IP/UDP/coap=5683	https://tools.ietf.org/html/rfc6690 , http://www.herjulf.se/download/coap-2013-fall.pdf , https://tools.ietf.org/html/rfc7252#section-3
	elif (dport == "5683") and Payload and (Payload.startswith(('@', 'P', '`', 'p')) or (Payload.find('.well-known') > -1)):		# '@' confirmable, 'P' non-confirmable, '`' acknowledgement, or 'p' Reset  (The acknowledgment and reset may have to go in sport == "5683" instead)
		ReportId("UC", sIP, "UDP_" + dport, "open", "coap/client", ([]))
### IP/UDP/bt-lpd=6771	https://security.stackexchange.com/questions/102766/wireshark-reveals-suspicious-udp-traffic-sending-to-a-bogon-ip-address
	elif (dport == "6771") and (dIP == "239.192.152.143") and Payload and (Payload.startswith('BT-SEARCH * HTTP/1.1')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "bt-lpd/client", ([]))
### IP/UDP/unreal_status=7778	https://arp242.net/weblog/online_unreal_tournament_server_browser_with_pcntl_fork()
	elif (dport == "7778") and Payload and Payload.startswith('\\status\\'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "unreal_status/client", ([]))
### IP/UDP/kissdvd=8000	https://www.tapatalk.com/groups/helplinedirect/getting-linksys-kiss-1600-to-work-with-ubuntu-t35.html
	elif (dport == "8000") and Payload and Payload == 'ARE_YOU_KISS_PCLINK_SERVER?':
		ReportId("UC", sIP, "UDP_" + dport, "open", "kissdvd/client", (['scan']))
### IP/UDP/canon-bjnp2=8610
	elif (dport == "8610") and meta['cast_type'] and Payload and (Payload.startswith('MFNP')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "udp8610/" + meta['cast_type'], ([]))
### IP/UDP/canon-bjnp2=8612		https://support.usa.canon.com/kb/index?page=content&id=ART109227
	elif dport in ("8612", "8613") and meta['cast_type'] and Payload and (Payload.startswith('BJNP')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "canon-bjnp2/" + meta['cast_type'], ([]))
	elif dport in ("8612", "8613") and dIP in ('ff02::1', 'ff02:0000:0000:0000:0000:0000:0000:0001') and Payload and (Payload.startswith('BJNP')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "canon-bjnp2/client", ([]))
### IP/UDP/canon-bjnb-bnjb=8612
	elif (dport == "8612") and meta['cast_type'] and Payload and (Payload.startswith(('BNJB', 'BJNB'))):
		ReportId("UC", sIP, "UDP_" + dport, "open", "canon-bjnb-bnjb/" + meta['cast_type'], ([]))
### IP/UDP/itunesdiscovery=8765
	elif dport == "8765":									#XPL, http://wiki.xplproject.org.uk/index.php/Main_Page
		ReportId("UC", sIP, "UDP_" + dport, "open", "itunesdiscovery/broadcast", ([]))		#'portonlysignature'
### IP/UDP/sunwebadmin=8800
	elif dport == "8800" and Payload and Payload.startswith('DHGET'):				#http://sites.ieee.org/neworleans/files/2016/12/12052016-Presentation-IoT-security-website-copy.pdf
		ReportId("UC", sIP, "UDP_" + dport, "open", "sunwebadmin/client possibly Mirai", (['dos']))
### IP/UDP/aoldns
	elif (sport in ("9052", "9053", "9054")) and (sIP in aol_dns_servers):	#Possibly AOL dns response
		if Payload and (Payload.find('dns-01') > -1):
			ReportId("US", sIP, "UDP_" + sport, "open", "aoldns/server", ([]))
		else:
			UnhandledPacket(p)
### IP/UDP/teamspeak3=9987,59596 client	https://github.com/TeamSpeak-Systems/ts3init_linux_netfilter_module
	elif dport in ("9987", "59596") and Payload and (Payload.startswith('TS3INIT1')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "teamspeak3/clientscanner", (['scan', 'dos']))
### UP/UDP/ubnt-discover=10001	https://github.com/headlesszeke/ubiquiti-probing
	elif dport == "10001" and Payload and (Payload == ubiquiti_discover):
		ReportId("UC", sIP, "UDP_" + dport, "open", "ubnt-discover/clientscanner", (['scan']))
### IP/UDP/memcached=11211		https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/	https://github.com/memcached/memcached/blob/master/doc/protocol.txt
	elif dport in ("1121", "11211") and Payload:
		if ((Payload.find('gets ') > -1) or (Payload.find('stats') > -1)):
			ReportId("UC", sIP, "UDP_" + dport, "open", 'memcached/client: Likely spoofed and DDOSed source IP', (['amplification', 'malicious', 'spoofed']))
		elif Payload.find('version') > -1:
			ReportId("UC", sIP, "UDP_" + dport, "open", 'memcached/client', (['scan']))
		else:
			ShowPacket(p, "IP/UDP/memcached=1121 or 11211 request but non-gets/stats/version", HonorQuit)
	elif sport == "11211":
		ReportId("US", sIP, "UDP_11211", "open", 'memcached server', ([]))
### IP/UDP/zmapscanner=1707,3269,3544,6619,1121[45]								https://zmap.io/ , https://github.com/zmap/zmap
	elif dport in zmap_host_www_ports and (Payload == 'GET / HTTP/1.1\r\nHost: www\r\n\r\n'):
		ReportId("UC", sIP, "UDP_" + dport, "open", 'zmapscanner/client', (['scan']))
### IP/UDP/makerbotdiscovery=12307		https://github.com/gryphius/mini-makerbot-hacking/blob/master/doc/makerbotmini.md
	elif (sport == "12309") and (dport == "12307") and meta['cast_type']:
		if Payload and (Payload.startswith('{"command": "broadcast"')):
			ReportId("UC", sIP, "UDP_" + dport, "open", "makerbotdiscovery/" + meta['cast_type'], ([]))
### IP/UDP/12314
	elif dport == "12314" and Payload and Payload.startswith(fournulls):					#Actually,lots more nulls than 4.
		ReportId("UC", sIP, "UDP_" + dport, "open", 'udp12314/client', (['scan']))
### IP/UDP/dropbox=17500	http://whatportis.com/ports/17500_dropbox-lansync-protocol-db-lsp-used-to-synchronize-file-catalogs-between-dropbox-clients-on-your-local-network
	elif (sport == "17500") and (dport == "17500"):
		if Payload and (Payload.find('"host_int"') > -1):
			ReportId("UC", sIP, "UDP_" + dport, "open", "dropbox/client", ([]))
		else:
			UnhandledPacket(p)
### IP/UDP/googlemeet=19302-19309
	elif (dport in meet_ports) and (dIP in meet_hosts):
		ReportId("UC", sIP, "UDP_" + dport, "open", "googlemeet/client", ([]))
	elif (sport in meet_ports) and (sIP in meet_hosts):
		ReportId("US", sIP, "UDP_" + sport, "open", "googlemeet/server", ([]))
	elif dport in meet_ports:
		ReportId("UC", sIP, "UDP_" + dport, "open", "googlemeet/client missing dIP:" + dIP, ([]))		#'portonlysignature'
	elif sport in meet_ports:
		ReportId("US", sIP, "UDP_" + sport, "open", "googlemeet/server missing sIP:" + sIP, ([]))		#'portonlysignature'
### IP/UDP/develo=19375	https://flambda.de/2013/06/18/audioextender/	https://ubuntuforums.org/showthread.php?t=1942539	https://www2.devolo.com/products/dLAN-Powerline-1485-Mbps/dLAN-Wireless-extender/data/Data-sheet-dLAN-Wireless-extender-Starter-Kit-com.pdf
	elif dport == "19375" and meta['cast_type'] and Payload.startswith('whoisthere'):
		ReportId("UC", sIP, "UDP_" + dport, "open", "develo/" + meta['cast_type'] + "client", ([]))		#Note, payload is "whoisthere\x00' + str(ip.address) + '\x00' + str(subnet_mask) + '\x00\x001\x00'
### IP/UDP/skype=all over the place
	elif (dport in skype_ports) and (dIP in skype_hosts):
		ReportId("UC", sIP, "UDP_" + dport, "open", "skype/client", ([]))
	elif (sport in skype_ports) and (sIP in skype_hosts):
		ReportId("US", sIP, "UDP_" + sport, "open", "skype/server", ([]))
	elif dIP in skype_hosts:
		ReportId("UC", sIP, "UDP_" + dport, "open", "skype/client, missing dport:" + dport, ([]))
	elif sIP in skype_hosts:
		ReportId("US", sIP, "UDP_" + sport, "open", "skype/server, missing sport:" + sport, ([]))
	elif dport in skype_ports:
		ReportId("UC", sIP, "UDP_" + dport, "open", "skype/client missing dIP:" + dIP, ([]))		#'portonlysignature'
	elif sport in skype_ports:
		ReportId("US", sIP, "UDP_" + sport, "open", "skype/server missing sIP:" + sIP, ([]))		#'portonlysignature'
### IP/UDP/pyzor=24441
	elif dport == "24441":											#Pyzor
		if Payload and (Payload.find('User:') > -1):
			ReportId("UC", sIP, "UDP_" + dport, "open", "pyzor/client", ([]))
		else:
			UnhandledPacket(p)
### IP/UDP/unknown26079
	elif (sport == "26079") or (dport == "26079") or sIP in ("52.179.141.141", "100.112.42.45") or dIP in ("52.179.141.141", "100.112.42.45"):
		UnhandledPacket(p)
### IP/UDP/halflife=27005 and others
	elif (sport == "27005") and (dport in ('27015', '27016', '27017')):					#Halflife client live game
		ReportId("UC", sIP, "UDP_" + dport, "open", "halflife/client", ([]))				#'portonlysignature'
	elif (dport == "27013") and (dIP == "207.173.177.12"):							#variable payload, so can't Payload and (Payload.find('Steam.exe') > -1)				#Halflife client
		ReportId("UC", sIP, "UDP_" + dport, "open", "halflife/client", ([]))
	elif (sport == "27013") and (sIP == "207.173.177.12"):							#halflife server
		ReportId("US", sIP, "UDP_" + sport, "open", "halflife/server", ([]))
	elif (sport in '27015', '27016', '27017') and (dport == "27005"):					#halflife server live game
		ReportId("US", sIP, "UDP_" + sport, "open", "halflife/server", ([]))				#'portonlysignature'
	elif dport in ("27015", "27016", "27025", "27026"):							#Variable payload, so can't: Payload and (Payload.find('basic') > -1)	#Halflife client
		ReportId("UC", sIP, "UDP_" + dport, "open", "halflife/client", ([]))				#'portonlysignature'
	elif sport in ("27015", "27016", "27025", "27026"):							#Variable payload, so can't: Payload and (Payload.find('basic') > -1)	#Halflife client
		ReportId("US", sIP, "UDP_" + sport, "open", "halflife/server", ([]))				#'portonlysignature'
	elif (dport == "27017") and (dIP in SteamFriendsServers):	#Steamfriends client
		if Payload and (Payload.find('VS01') > -1):
			ReportId("UC", sIP, "UDP_" + dport, "open", "steamfriends/client", ([]))
		else:
			UnhandledPacket(p)
	elif (sport == "27017") and (sIP in SteamFriendsServers):	#Steamfriends server
		if Payload and (Payload.find('VS01') > -1):
			ReportId("US", sIP, "UDP_" + sport, "open", "steamfriends/server", ([]))
		else:
			UnhandledPacket(p)
	elif sport in ("21020", "21250", "27016", "27017", "27018", "27030", "27035", "27040", "28015"):	#halflife server
		if Payload and (Payload.find('Team Fortress') > -1):
			ReportId("US", sIP, "UDP_" + sport, "open", "halflife/server", ([]))			#'portonlysignature'
		else:
			UnhandledPacket(p)
	elif sport == "27019":											#halflife server
		ReportId("US", sIP, "UDP_" + sport, "open", "halflife/server", ([]))				#'portonlysignature'

### IP/UDP/steam-ihs-discovery=27036		https://codingrange.com/blog/steam-in-home-streaming-discovery-protocol
	elif (sport == "27036") and (dport == "27036") and (dIP == "255.255.255.255"):
		if Payload and (Payload.startswith(stream_ihs_discovery_header)):
			ReportId("UC", sIP, "UDP_" + dport, "open", "stream-ihs-discovery-broadcast/client", ([]))
		else:
			UnhandledPacket(p)
	elif (dport == "27036") and Payload and (Payload.startswith(stream_ihs_discovery_header)):
		ReportId("UC", sIP, "UDP_" + dport, "open", "stream-ihs-discovery/client", ([]))
	elif dport in halflife_altport:										#Halflife client
		if Payload and (Payload.find('Source Engine Query') > -1):
			ReportId("UC", sIP, "UDP_" + dport, "open", "halflife/client", ([]))			#'portonlysignature'
		else:
			UnhandledPacket(p)
### IP/UDP/lima=25213	https://support.meetlima.com/hc/en-us/articles/115004950326-README-document
	elif dport == "25213" and Payload and (Payload.startswith('ZVPN')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "limavpn/client", (['tunnel']))
### IP/UDP/openarena=27960	https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=665656 , http://openarena.ws/board/index.php?topic=4391.0 , http://blog.alejandronolla.com/2013/06/24/amplification-ddos-attack-with-quake3-servers-an-analysis-1-slash-2/
	elif (dport == "27960") and Payload and Payload.startswith(eight_fs + 'getstatus'):
		ReportId("UC", sIP, "UDP_" + dport, "open", 'openarena-quake3/client getstatus: Likely spoofed and DDOSed source IP', (['amplification', 'dos', 'spoofed']))
### IP/UDP/hap=28784	https://hal.inria.fr/hal-01456891/document
	elif (dport == "28784") and Payload and Payload.startswith('HAP'):
		ReportId("UC", sIP, "UDP_" + dport, "open", 'hap/client', (['scan']))
### IP/UDP/traceroute
	elif ((dport >= "33434") and (dport <= "33524")):	#udptraceroute client
		ReportId("UC", sIP, "UDP_33434", "open", "udptraceroute/client", ([]))				#'portonlysignature'
### IP/UDP/lima=33612	https://support.meetlima.com/hc/en-us/articles/115004950326-README-document
	elif dport == "33612" and Payload and (Payload.startswith('LIMA')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "lima/client", ([]))
### IP/UDP/halflife=40348
	elif dport == "40348" and Payload and (Payload.find('HLS') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "halflife/client", ([]))
### IP/UDP/crestron-cip=41794	https://media.defcon.org/DEF%20CON%2026/DEF%20CON%2026%20presentations/Ricky%20Lawshae/DEFCON-26-Lawshae-Who-Controls-the-Controllers-Hacking-Crestron.pdf
	elif (sport == "41794") and (dport == "41794") and Payload and Payload.startswith(crestron_prelude + 'hostname'):
		ReportId("UC", sIP, "UDP_" + dport, "open", 'crestron-cip/clientscanner', (['scan']))
### IP/UDP/zengge-bulb=48899 client https://github.com/vikstrous/zengge-lightcontrol/blob/master/README.md
	elif (dport == "48899") and Payload and (Payload.find('HF-A11ASSISTHREAD') > -1):
		ReportId("UC", sIP, "UDP_" + dport, "open", "zengge-bulb/clientscanner", (['scan']))
### IP/UDP/linkproof=49153 client	https://eromang.zataz.com/2010/04/28/suc007-activities-on-49153udp-linkproof-proximity-advanced/
	elif (dport == "49153") and Payload and (Payload.startswith('linkproof.proximity.advanced')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "radware-linkproof/clientscanner", (['scan']))
### IP/UDP/netis-backdoor-53413=53413 client, exploting Netis router backdoor: https://isc.sans.edu/forums/diary/Surge+in+Exploit+Attempts+for+Netis+Router+Backdoor+UDP53413/21337/
	elif dport == "53413":							#To limit this signature to just shellcode, add the following tests to this line:   and Payload and (Payload.find('; chmod 777 ') > -1)
		ReportId("UC", sIP, "UDP_" + dport, "open", "netis-backdoor-53413/client", (['malicious']))	#'portonlysignature'
### IP/UDP/logitech-arx=54915		http://support.moonpoint.com/network/udp/port_54915/
	elif sport == "54915" and dport == "54915" and meta['cast_type']:
		ReportId("UC", sIP, "UDP_" + dport, "open", "logitech-arx/" + meta['cast_type'] + "client", ([]))	#'portonlysignature'
### IP/UDP/brother-announce=54925 and 54926 used by brother printers		http://ww2.chemistry.gatech.edu/software/Drivers/Brother/MFC-9840CDW/document/ug/usa/html/sug/index.html?page=chapter7.html
	elif (dport in ("54925", "54926")) and meta['cast_type'] and Payload and (Payload.find('NODENAME=') > -1):
		BrotherMatch = BrotherAnnounceMatch.search(Payload)
		if (BrotherMatch is not None) and (len(BrotherMatch.groups()) >= 4):
			#In the packets I've seen, groups 1, 2, and 3 are ip addresses (1 ipv4 and 2 ipv6).  Group 4 is a nodename ("BRWF" + uppercase mac address, no colons)
			ReportId("UC", sIP, "UDP_" + dport, "open", "brother-announce/" + meta['cast_type'] + " nodename: " + BrotherMatch.group(4), ([]))
			ReportId("UC", BrotherMatch.group(1), "UDP_" + dport, "open", "brother-announce/" + meta['cast_type'] + " nodename: " + BrotherMatch.group(4), ([]))
			ReportId("UC", BrotherMatch.group(2), "UDP_" + dport, "open", "brother-announce/" + meta['cast_type'] + " nodename: " + BrotherMatch.group(4), ([]))
			ReportId("UC", BrotherMatch.group(3), "UDP_" + dport, "open", "brother-announce/" + meta['cast_type'] + " nodename: " + BrotherMatch.group(4), ([]))
		else:
			ReportId("UC", sIP, "UDP_" + dport, "open", "brother-announce/" + meta['cast_type'], ([]))
### IP/UDP/spotify-broadcast=57621		https://mrlithium.blogspot.com/2011/10/spotify-and-opting-out-of-spotify-peer.html
	elif (dport == "57621") and Payload and (Payload.startswith('SpotUdp')):
		ReportId("UC", sIP, "UDP_" + dport, "open", "spotify/" + meta['cast_type'] + "client", ([]))
### IP/UDP/probes with empty payloads
	elif dport in empty_payload_ports and Payload == '':
		ReportId("UC", sIP, "UDP_" + dport, "open", "empty-payload/client", ([]))
	elif Payload == '':
		ReportId("UC", sIP, "UDP_" + dport, "open", "empty-payload/client Port not registered", ([]))
		UnhandledPacket(p)
### IP/UDP/quake3 disconnect amplification		http://blog.alejandronolla.com/2013/08/05/amplification-ddos-attack-with-quake3-servers-an-analysis-2-slash-2/
	elif Payload == quake3_disconnect:
		ReportId("UC", sIP, "UDP_" + dport, "open", 'quake3/client: Disconnect, likely spoofed and DDOSed source IP', (['amplification', 'malicious', 'spoofed']))
		UnhandledPacket(p)
### IP/UDP/bt-dht		http://www.bittorrent.org/beps/bep_0005.html , https://isc.sans.edu/forums/diary/Identifying+applications+using+UDP+payload/6031/
	elif Payload and Payload.find(':id') > -1 and ((Payload.find(':info_hash') > -1 and Payload.find(':get_peers') > -1) or Payload.find(':ping') > -1 or Payload.find('9:find_node') > -1):	#Unfortunately, can run on any port
		ReportId("UC", sIP, "UDP_" + dport, "open", 'bt-dht-scan/clientscanner', (['scan']))
	elif Payload and Payload.find(':id') > -1 and Payload.find(':token') > -1 and (Payload.find(':nodes') > -1 or Payload.find(':values')):
		ReportId("US", sIP, "UDP_" + sport, "open", 'bt-dht/server', ([]))
	elif Payload and Payload.find('; wget ') > -1 and Payload.find('; sh ') > -1 and Payload.find('; rm -rf ') > -1:
		ReportId("UC", sIP, "UDP_" + dport, "open", 'shellcode/clientscanner', (['scan', 'malicious']))
	elif Payload and Payload.startswith(a0_string):									#Payload starting with A\x00
		UnhandledPacket(p)
	elif dport in SecUDPPortNames:
		warning_list = []
		if dport in udp_port_warnings:
			warning_list = [udp_port_warnings[dport]]
		UnhandledPacket(p)
		ReportId("UC", sIP, "UDP_" + dport, "open", str(SecUDPPortNames[dport]) + "/client", (warning_list))	#'portonlysignature'
	elif sport in SecUDPPortNames:
		warning_list = []
		if dport in udp_port_warnings:
			warning_list = [udp_port_warnings[dport]]
		UnhandledPacket(p)
		ReportId("US", sIP, "UDP_" + sport, "open", str(SecUDPPortNames[sport]) + "/server", (warning_list))	#'portonlysignature'
	elif meta['ip_class'] == '4' and p[IP].frag > 0:
		UnhandledPacket(p)
	elif (sport == "53") and not p.haslayer(DNS):									#source port 53, but no parsed DNS layer.  Seen this in large packets with Raw immediately following UDP.
		UnhandledPacket(p)
	elif sport == "53":												#source port 53.  I've seen some coming back from port 53 with qr=0, request.  Hmmm.
		UnhandledPacket(p)
	elif sIP in shodan_hosts and Payload == fournulls + 'abcdefgh':
		ReportId("UC", sIP, "UDP_" + dport, "open", "shodan_host/clientscanner abcdefgh", (['scan']))
	elif sIP in shodan_hosts:
		ReportId("UC", sIP, "UDP_" + dport, "open", "shodan_host/clientscanner", (['scan']))
	elif Payload == fournulls + 'abcdefgh':
		ReportId("UC", sIP, "UDP_" + dport, "open", "shodan_host/clientscanner abcdefgh Unlisted host", (['scan']))
	elif sIP in known_scan_ips:
		ReportId("UC", sIP, "UDP_" + dport, "open", "udp/clientscanner known scanner", (['scan']))

	elif meta['dMAC'] == "ff:ff:ff:ff:ff:ff" and dport in broadcast_udp_ports:
		ReportId("UC", sIP, "UDP_" + dport, "open", "udp" + dport + "/broadcastclient", ([]))			#'portonlysignature'
	elif sport in broadcast_udp_ports:
		ReportId("US", sIP, "UDP_" + sport, "open", 'udp' + sport + '/server', ([]))				#'portonlysignature'
	elif meta['dMAC'] == "ff:ff:ff:ff:ff:ff":
		ShowPacket(p, "IP/UDP/unhandled broadcast", HonorQuit)
	else:
		ShowPacket(p, "IP/UDP/unhandled port", HonorQuit)


def processpacket(p):
	"""Extract information from a single packet off the wire."""

	global SynSentToTCPService
	global SynAckSentToTCPClient
	global LiveTCPService
	global LiveTCPClient
	global NmapServerDescription
	global ManualServerDescription
	global ClientDescription
	global ServiceFPs
	global SipPhoneMatch
	global HostIPs
	global ClosedPortsReceived
	global start_stamp
	global start_string
	global end_stamp
	global end_string

	if debug_known_layer_lists:
		p_layers = list(ReturnLayers(p))
		if p_layers not in known_layer_lists:
			Debug('>>>>>>>> ' + str(p_layers))
			ShowPacket(p, "Unknown layer list", HonorQuit)
			quit()

		for one_layer in p_layers:
			if one_layer not in layer_label_to_key:
				Debug('>>>>>>>> ' + str(one_layer) + ' not in layer_label_to_key')
				ShowPacket(p, "Unknown layer list", HonorQuit)
				quit()

	this_stamp, this_string = packet_timestamps(p)
	if not start_stamp or this_stamp < start_stamp:
		start_stamp = this_stamp
		start_string = this_string
	if not end_stamp or this_stamp > end_stamp:
		end_stamp = this_stamp
		end_string = this_string

	meta = generate_meta_from_packet(p)
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


### Spanning Tree Protocol
	if isinstance(p, Dot3) and p.haslayer(LLC) and isinstance(p[LLC], LLC):
		pass	#Nothing really to learn from it.
### 802.3 without LLC
	elif isinstance(p, Dot3):
		pass	#Nothing really to learn from it.
### Need more details on how to handle.
	elif p.haslayer(Ether) and p[Ether] is None:
		ShowPacket(p, "non-ethernet packet: " + str(type(p)), HonorQuit)
### ARP
	elif (p.haslayer(Ether) and p[Ether].type == 0x0806) and p.haslayer(ARP) and isinstance(p[ARP], ARP):		#ARP
		#pull arp data from here instead of tcp/udp packets, as these are all local
		if p[ARP].op == 1:			#1 is request ("who-has")
			pass
		elif p[ARP].op == 2:			#2 is reply ("is-at")
			if (p[ARP].psrc is not None) and (p[ARP].hwsrc is not None):
				IPAddr = p[ARP].psrc
				MyMac = p[ARP].hwsrc.upper()
				ReportId("MA", IPAddr, 'Ethernet', MyMac, '', ([]))
			else:
				UnhandledPacket(p)
		else:
			UnhandledPacket(p)
### ARP, truncated
	elif p.haslayer(Ether) and p[Ether].type == 0x0806:		#2054: ARP, apparently truncated
		UnhandledPacket(p)
### IPv4 ethertype but not ipv4 in the ip header
	elif ((p.haslayer(CookedLinux) and p[CookedLinux].proto == 0x800) or (p.haslayer(Ether) and ((p[Ether].type == 0x0800) or (p[Ether].type == 0x8100))) or not p.haslayer(Ether)) and p.haslayer(IP) and isinstance(p[IP], IP) and p[IP].version != 4:
		#ShowPacket(p, "IPV4 packet with version != 4", HonorQuit)
		UnhandledPacket(p)
### IPv4
	elif ((p.haslayer(CookedLinux) and p[CookedLinux].proto == 0x800) or (p.haslayer(Ether) and ((p[Ether].type == 0x0800) or (p[Ether].type == 0x8100))) or not p.haslayer(Ether)) and p.haslayer(IP) and isinstance(p[IP], IP):

		if meta['sMAC'] == 'ff:ff:ff:ff:ff:ff':
			ReportId("IP", sIP, "Broadcast_source_mac", "open", "Source mac address is broadcast", (['noncompliant']))

		#Best to get these from arps instead; if we get them from here, we get router macs for foreign addresses.
		#ReportId("MA", sIP, "Ethernet", meta['sMAC'], '', ([]))
		#ReportId("MA", dIP, "Ethernet", dMAC, '', ([]))

		if p.getlayer(Raw):
			Payload = p.getlayer(Raw).load
		else:
			Payload = ""

### IPv4/IP
		if p[IP].proto == 0:
			ShowPacket(p, "IPv4/Protocol 0", HonorQuit)
### IPv4/ICMPv4
		elif (p[IP].proto == 1) and p.haslayer(ICMP) and isinstance(p[ICMP], ICMP):
			Type = p[ICMP].type
			Code = p[ICMP].code

### IPv4/ICMPv4/Echo Reply=0
			if Type == 0:
				ReportId("IP", sIP, "IP", "live", 'icmp echo reply', ([]))
### IPv4/ICMPv4/Unreachable=3
			elif (Type == 3) and p.haslayer(IPerror) and isinstance(p[IPerror], IPerror):	#Unreachable, check that we have an actual embedded packet
				if type(p[IPerror]) != IPerror:
					ShowPacket(p, "IPv4/ICMPv4/Unreachable=type3/Not IPError: " + str(type(p[IPerror])), HonorQuit)

				if Code == 0:					#Net unreachable
					ReportId("IP", meta['OrigdIP'], "IP", "dead", 'net unreachable', ([]))
					ReportId("RO", sIP, "NetUn", "router", "client_ip=" + dIP, ([]))
				elif Code == 1:					#Host unreachable
					ReportId("IP", meta['OrigdIP'], "IP", "dead", 'host unreachable', ([]))
					ReportId("RO", sIP, "HostUn", "router", "client_ip=" + dIP, ([]))
				elif Code == 2:					#Protocol unreachable
					ReportId("RO", sIP, "ProtoUn", "router", "client_ip=" + dIP, ([]))
				#Following codes are Port unreachable, Network/Host Administratively Prohibited, Network/Host unreachable for TOS, Communication Administratively prohibited
				elif Code in (3, 9, 10, 11, 12, 13) and (p[IPerror].proto == 17) and p.haslayer(UDPerror) and isinstance(p[UDPerror], UDPerror):	#Port unreachable and embedded protocol = 17, UDP, as it should be
					DNSServerLoc = meta['OrigsIP'] + ",UDP_53"
					if (p[UDPerror].sport == 53) and (DNSServerLoc in ManualServerDescription) and (ManualServerDescription[DNSServerLoc] == "dns/server"):
						#If orig packet coming from 53 and coming from a dns server, don't do anything (closed port on client is a common effect)
						#Don't waste time on port unreachables going back to a dns server; too common, and ephemeral anyways.
						pass
					else:
						#If orig packet coming from something other than 53, or coming from 53 and NOT coming from a dns server, log as closed
						OrigDPort = str(p[UDPerror].dport)
						ReportId("US", meta['OrigdIP'], "UDP_" + OrigDPort, "closed", "port unreachable", ([]))

						if include_udp_errors_in_closed_ports:
							#Prober is dIP.  Probed port is: meta['OrigdIP'] + ",UDP_" + OrigDPort
							if dIP not in ClosedPortsReceived:
								ClosedPortsReceived[dIP] = set()
							ClosedPortsReceived[dIP].add(meta['OrigdIP'] + ",UDP_" + OrigDPort)
							if len(ClosedPortsReceived[dIP]) >= min_closed_ports_for_scanner:
								ReportId("IP", dIP, "IP", "suspicious", 'Scanned closed ports.', (['scan']))
				elif Code in (3, 9, 10, 11, 12, 13) and (p[IPerror].proto == 6) and isinstance(p[TCPerror], TCPerror):	#Port unreachable and embedded protocol = 6, TCP, which it shouldn't.  May be the same firewall providing the TCP FR's
					#Now we _could_ claim the machine sending the error is a linux firewall.
					OrigDPort = str(p[TCPerror].dport)
					Service = meta['OrigdIP'] + ",TCP_" + OrigDPort
					if Service in SynSentToTCPService and ((Service not in LiveTCPService) or LiveTCPService[Service]):
						LiveTCPService[Service] = False
						ReportId("TS", meta['OrigdIP'], "TCP_" + OrigDPort, "closed", '', ([]))

					if Service in SynSentToTCPService:
						#Prober is dIP.  Probed port is Service (= meta['OrigdIP'] + ",TCP_" + OrigDPort)
						if dIP not in ClosedPortsReceived:
							ClosedPortsReceived[dIP] = set()
						ClosedPortsReceived[dIP].add(Service)
						if len(ClosedPortsReceived[dIP]) >= min_closed_ports_for_scanner:
							ReportId("IP", dIP, "IP", "suspicious", 'Scanned closed ports.', (['scan']))
				elif (Code == 3) and (p[IPerror].proto == 1) and isinstance(p[ICMPerror], ICMPerror):	#Port unreachable and embedded protocol = 1, ICMP; not sure if this is legit or not.
					#Now we _could_ claim the machine sending the error is a linux firewall.
					pass
				elif Code == 3:					#Port unreachable, but we do not have (complete) underlying layers below IPerror or IPerror6
					pass
				elif Code == 4:					#Fragmentation needed
					pass
				elif Code == 6:					#Net unknown
					ReportId("IP", meta['OrigdIP'], "IP", "dead", 'net unknown', ([]))
				elif Code == 7:					#Host unknown
					ReportId("IP", meta['OrigdIP'], "IP", "dead", 'host unknown', ([]))
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
					ShowPacket(p, "IPv4/ICMPv4/Type=3/unhandled code: " + str(Code), HonorQuit)
### IPv4/ICMPv3/Source Quench=4		https://tools.ietf.org/html/rfc6633 - ipv4 source quench deprecated since 2012, does not exist in ipv6
			elif Type == 4:
				UnhandledPacket(p)
### IPv4/ICMPv4/Redirect=5
			elif (Type == 5) and isinstance(p[IPerror], IPerror):	#Unreachable, check that we have an actual embedded packet
				if type(p[IPerror]) != IPerror:
					ShowPacket(p, "IPv4/ICMPv4/Redirect=type5/Not IPError: " + str(type(p[IPerror])), HonorQuit)
				elif Code in (0, 1, 2, 3):			#Network, Host, TOS+Network, TOS+Host
					ReportId("RO", sIP, "Redirect", "router", "attempted_router client_ip=" + dIP, ([]))
					better_router = p[ICMP].gw
					ReportId("RO", better_router, "Redirect", "router", "recommended_router client_ip=" + dIP, ([]))
				else:
					UnhandledPacket(p)
### IPv4/ICMPv4/Echo Request=8
			elif Type == 8:
				#FIXME - check payload for ping sender type, perhaps
				if Payload.find('liboping -- ICMP ping library') > -1:
					ReportId("IP", sIP, "IP", "live", 'oping icmp echo request scanner', (['scan']))
				else:
					ReportId("IP", sIP, "IP", "live", 'icmp echo request scanner', (['scan']))
### IPv4/ICMPv4/Router Advertisement=9		https://tools.ietf.org/html/rfc1256
			elif Type == 9:
				ReportId("RO", sIP, "RouterAdv", "router", '', ([]))
### IPv4/ICMPv4/Time exceeded=11
			elif Type == 11:
				if Code == 0:					#TTL exceeded
					#FIXME - put original target IP as column 5?
					ReportId("RO", sIP, "TTLEx", "router", "client_ip=" + dIP, ([]))
				else:
					UnhandledPacket(p)
			elif Type in (6, 15, 16, 17, 18, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39):	#https://tools.ietf.org/html/rfc6918
				ReportId("IP", sIP, "ICMP_type_" + str(Type), "open", "Deprecated ICMP type scanner", (['noncompliant', 'scan']))
			elif Type >= 44 and Type <= 252:			#https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
				ReportId("IP", sIP, "ICMP_type_" + str(Type), "open", "Reserved ICMP type scanner", (['noncompliant', 'scan']))
			else:
				UnhandledPacket(p)
				ShowPacket(p, 'Unhandled ipv4 ICMP packet', HonorQuit)
		elif p[IP].proto == 1:
			UnhandledPacket(p)
### IPv4/IGMPv4
		elif p[IP].proto == 2:		#IGMP
			UnhandledPacket(p)
### IPv4/TCPv4
		elif p[IP].proto == 6 and p.haslayer(TCP) and isinstance(p[TCP], TCP):		#TCP
			sport = str(p[TCP].sport)
			dport = str(p[TCP].dport)

			if (sIP == dIP) and (sport == dport):
				ReportId("TS", sIP, "TCP_" + sport, "attack", 'land attack IP address spoofed', (['malicious', 'spoofed']))

			#print meta['sIP'] + ":" + meta['sport'] + " -> ", meta['dIP'] + ":" + meta['dport'],
			if (p[TCP].flags & 0x17) == 0x12:	#SYN/ACK (RST and FIN off)
				CliService = dIP + ",TCP_" + sport
				if CliService not in SynAckSentToTCPClient:
					SynAckSentToTCPClient[CliService] = True

				#If we've seen a syn sent to this port and have either not seen any SA/R, or we've seen a R in the past:
				#The last test is for a service that was previously closed and is now open; report each transition once.
				Service = sIP + ",TCP_" + sport
				if Service in SynSentToTCPService and ((Service not in LiveTCPService) or (not LiveTCPService[Service])):
					LiveTCPService[Service] = True
					if sport in PolicyViolationTCPPorts:
						ReportId("TS", sIP, "TCP_" + sport, "listening", '', (['portpolicyviolation']))
					else:
						ReportId("TS", sIP, "TCP_" + sport, "listening", '', ([]))
			elif (p[TCP].flags & 0x17) == 0x02:	#SYN (ACK, RST, and FIN off)
				Service = dIP + ",TCP_" + dport
				if Service not in SynSentToTCPService:
					SynSentToTCPService[Service] = True

				if dport in PolicyViolationTCPPorts:
					ReportId("TC", sIP, "TCP_" + dport, "open", '', (['portpolicyviolation']))

				#Debug("trying to fingerprint " + sIP)
#ZZZZ
#				try:
					#p0fdata = p0f(p)
					##FIXME - reasonably common occurence, don't whine, just fix it.
					##if (len(p0fdata) >1):
					##	Debug("More than one OS fingerprint for " + sIP + ", using the first.")
					#if (len(p0fdata) >=1):
					#	PDescription = p0fdata[0][0] + " " + p0fdata[0][1] + " (" + str(int(p0fdata[0][2]) + 1)	#FIXME - Grabbing just the first candidate, may need to compare correlation values; provided?
					#	if (p0fdata[0][2] == 0):
					#		PDescription = PDescription + " hop away)"
					#	else:
					#		PDescription = PDescription + " hops away)"
					#								#[N][2] param appears to be distance away in hops (but add 1 to this to get real hop count?)
					#	PDescription = PDescription.replace(',', ';')		#Commas are delimiters in output
					#	ReportId("IP", sIP, "IP", "live", PDescription, ([]))
#				except:
#					PDescription = 'p0f failure'
#						Debug("P0f failure in " + sIP + ":" + sport + " -> " + dIP + ":" + dport)
#						ReportId("IP", sIP, "IP", "live", PDescription, ([]))
			elif (p[TCP].flags & 0x07) == 0x01:	#FIN (SYN/RST off)
				CliService = sIP + ",TCP_" + dport
				if CliService in SynAckSentToTCPClient and ((CliService not in LiveTCPClient) or (not LiveTCPClient[CliService])):
					LiveTCPClient[CliService] = True
					ReportId("TC", sIP, "TCP_" + dport, "open", '', ([]))
			elif (p[TCP].flags & 0x07) == 0x04:	#RST (SYN and FIN off)
				#FIXME - handle rst going in the other direction?
				Service = sIP + ",TCP_" + sport
				if Service in SynSentToTCPService and ((Service not in LiveTCPService) or LiveTCPService[Service]):
					LiveTCPService[Service] = False
					ReportId("TS", sIP, "TCP_" + sport, "closed", '', ([]))

				if Service in SynSentToTCPService:
					#Prober is dIP.  Probed port is Service (= sIP + ",TCP_" + sport)
					if dIP not in ClosedPortsReceived:
						ClosedPortsReceived[dIP] = set()
					ClosedPortsReceived[dIP].add(Service)
					if len(ClosedPortsReceived[dIP]) >= min_closed_ports_for_scanner:
						ReportId("IP", dIP, "IP", "suspicious", 'Scanned closed ports.', (['scan']))
			elif ((p[TCP].flags & 0x3F) == 0x15) and (sport == "113"):	#FIN, RST, ACK (SYN, PSH, URG off)
				#This may be a firewall or some other device stepping in for 113 with a FIN/RST.
				pass
			elif (p[TCP].flags & 0x17) == 0x10:	#ACK (RST, SYN, and FIN off)
				#FIXME - check for UnhandledPacket placement in ACK
				FromPort = sIP + ",TCP_" + sport
				ToPort = dIP + ",TCP_" + dport

				if FromPort in LiveTCPService and LiveTCPService[FromPort] and (ToPort in LiveTCPService) and LiveTCPService[ToPort]:
					ShowPacket(p, "IPv4/TCPv4/ACK (RST, SYN, FIN off) Logic failure: both " + FromPort + " and " + ToPort + " are listed as live services.", HonorQuit)
				elif FromPort in LiveTCPService and LiveTCPService[FromPort]:			#If the "From" side is a known TCP server:
					if FromPort not in NmapServerDescription:				#Check nmap fingerprint strings for this server port
						if int(sport) in ServiceFPs:
							for OneTuple in ServiceFPs[int(sport)]:
								MatchObj = OneTuple[0].search(Payload)
								if MatchObj is not None:
									#Debugging:
									#FIXME - removeme once understood:
									#File "/home/wstearns/med/programming/python/passer/passer.py", line 504, in processpacket
									#OutputDescription = OutputDescription.replace('$' + str(Index), MatchObj.group(Index))
									#TypeError: expected a character buffer object
									if OneTuple[1] is None:
										Debug("Null description for " + OneTuple[0])
										#quit()
									OutputDescription = OneTuple[1]
									if len(MatchObj.groups()) >= 1:
										#We have subexpressions matched, these need to be inserted into the description string
										for Index in range(1, len(MatchObj.groups())+1):
											#Example: Replace "$1" with MatchObj.group(1)
											OutputDescription = OutputDescription.replace('$' + str(Index), str(MatchObj.group(Index)))
									ReportId("TS", sIP, "TCP_" + sport, "listening", OutputDescription, ([]))
									NmapServerDescription[sIP + ",TCP_" + sport] = OutputDescription
									break					#Exit for loop, no need to check any more fingerprints now that we've found a match

					if FromPort not in NmapServerDescription:			#If the above loop didn't find a server description
						if 'all' in ServiceFPs:					#Now recheck against regexes not associated with a specific port (port 'all').
							for OneTuple in ServiceFPs['all']:
								MatchObj = OneTuple[0].search(Payload)
								if MatchObj is not None:
									OutputDescription = OneTuple[1]
									if len(MatchObj.groups()) >= 1:
										#We have subexpressions matched, these need to be inserted into the description string
										for Index in range(1, len(MatchObj.groups())+1):
											OutputDescription = OutputDescription.replace('$' + str(Index), MatchObj.group(Index))
									ReportId("TS", sIP, "TCP_" + sport, "listening", OutputDescription, ([]))
									NmapServerDescription[sIP + ",TCP_" + sport] = OutputDescription
									break

					#FIXME - limit to just the ports we care about below too.
					if FromPort not in ManualServerDescription and Payload:
						#FIXME - change to startswith in this and other blocks
						if (sport == "22") and Payload.startswith('SSH-'):
							if Payload.startswith('SSH-1.99-OpenSSH_') or Payload.startswith('SSH-2.0-OpenSSH_'):
								ReportId("TS", sIP, "TCP_" + sport, "listening", "ssh/openssh", ([]))
								#FIXME - replace with FromPort?
								ManualServerDescription[sIP + ",TCP_" + sport] = "ssh/openssh"
							elif Payload.find('SSH-1.5-') > -1:
								ReportId("TS", sIP, "TCP_" + sport, "listening", "ssh/generic", ([]))
								ManualServerDescription[sIP + ",TCP_" + sport] = "ssh/generic"
								#LogNewPayload(ServerPayloadDir, FromPort, Payload)
							else:
								if SaveUnhandledAcks:
									UnhandledPacket(p)
									#LogNewPayload(ServerPayloadDir, FromPort, Payload)
						elif (sport == "25") and (Payload.find(' ESMTP Sendmail ') > -1):
							ReportId("TS", sIP, "TCP_" + sport, "listening", "smtp/sendmail", ([]))
							ManualServerDescription[sIP + ",TCP_" + sport] = "smtp/sendmail"
						elif (sport == "25") and (Payload.find(' - Welcome to our SMTP server ESMTP') > -1):
							ReportId("TS", sIP, "TCP_" + sport, "listening", "smtp/generic", ([]))
							ManualServerDescription[sIP + ",TCP_" + sport] = "smtp/generic"
							if SaveUnhandledAcks:
								UnhandledPacket(p)
								#LogNewPayload(ServerPayloadDir, FromPort, Payload)
						#Check for port 80 and search for "Server: " once
						elif (sport == "80") and (Payload.find('Server: ') > -1):
							if Payload.find('Server: Apache') > -1:
								ReportId("TS", sIP, "TCP_" + sport, "listening", "http/apache", ([]))
								ManualServerDescription[sIP + ",TCP_" + sport] = "http/apache"
							elif Payload.find('Server: Embedded HTTP Server') > -1:
								ReportId("TS", sIP, "TCP_" + sport, "listening", "http/embedded", ([]))
								ManualServerDescription[sIP + ",TCP_" + sport] = "http/embedded"
							elif Payload.find('Server: gws') > -1:
								ReportId("TS", sIP, "TCP_" + sport, "listening", "http/gws", ([]))
								ManualServerDescription[sIP + ",TCP_" + sport] = "http/gws"
							elif Payload.find('Server: KFWebServer') > -1:
								ReportId("TS", sIP, "TCP_" + sport, "listening", "http/kfwebserver", ([]))
								ManualServerDescription[sIP + ",TCP_" + sport] = "http/kfwebserver"
							elif Payload.find('Server: micro_httpd') > -1:
								ReportId("TS", sIP, "TCP_" + sport, "listening", "http/micro-httpd", ([]))
								ManualServerDescription[sIP + ",TCP_" + sport] = "http/micro-httpd"
							elif Payload.find('Server: Microsoft-IIS') > -1:
								ReportId("TS", sIP, "TCP_" + sport, "listening", "http/iis", ([]))
								ManualServerDescription[sIP + ",TCP_" + sport] = "http/iis"
							elif Payload.find('Server: lighttpd') > -1:
								ReportId("TS", sIP, "TCP_" + sport, "listening", "http/lighttpd", ([]))
								ManualServerDescription[sIP + ",TCP_" + sport] = "http/lighttpd"
							elif Payload.find('Server: MIIxpc') > -1:
								ReportId("TS", sIP, "TCP_" + sport, "listening", "http/mirrorimage", ([]))
								ManualServerDescription[sIP + ",TCP_" + sport] = "http/mirrorimage"
							elif Payload.find('Server: mini_httpd') > -1:
								ReportId("TS", sIP, "TCP_" + sport, "listening", "http/mini-httpd", ([]))
								ManualServerDescription[sIP + ",TCP_" + sport] = "http/mini-httpd"
							elif Payload.find('Server: nc -l -p 80') > -1:
								ReportId("TS", sIP, "TCP_" + sport, "listening", "http/nc", ([]))
								ManualServerDescription[sIP + ",TCP_" + sport] = "http/nc"
							elif Payload.find('Server: nginx/') > -1:
								ReportId("TS", sIP, "TCP_" + sport, "listening", "http/nginx", ([]))
								ManualServerDescription[sIP + ",TCP_" + sport] = "http/nginx"
							elif Payload.find('Server: Nucleus') > -1:
								ReportId("TS", sIP, "TCP_" + sport, "listening", "http/nucleus", ([]))
								ManualServerDescription[sIP + ",TCP_" + sport] = "http/nucleus"
							elif Payload.find('Server: RomPager') > -1:
								ReportId("TS", sIP, "TCP_" + sport, "listening", "http/rompager", ([]))
								ManualServerDescription[sIP + ",TCP_" + sport] = "http/rompager"
							elif Payload.find('Server: Server') > -1:
								ReportId("TS", sIP, "TCP_" + sport, "listening", "http/server", ([]))
								ManualServerDescription[sIP + ",TCP_" + sport] = "http/server"
							elif Payload.find('Server: Sun-ONE-Web-Server/') > -1:
								ReportId("TS", sIP, "TCP_" + sport, "listening", "http/sun-one", ([]))
								ManualServerDescription[sIP + ",TCP_" + sport] = "http/sun-one"
							elif Payload.find('Server: TrustRank Frontend') > -1:
								ReportId("TS", sIP, "TCP_" + sport, "listening", "http/trustrank", ([]))
								ManualServerDescription[sIP + ",TCP_" + sport] = "http/trustrank"
							elif Payload.find('Server: YTS/') > -1:
								ReportId("TS", sIP, "TCP_" + sport, "listening", "http/yahoo", ([]))
								ManualServerDescription[sIP + ",TCP_" + sport] = "http/yahoo"
							elif (Payload.find('HTTP/1.0 404 Not Found') > -1) or (Payload.find('HTTP/1.1 200 OK') > -1):
								ReportId("TS", sIP, "TCP_" + sport, "listening", "http/generic", ([]))
								ManualServerDescription[sIP + ",TCP_" + sport] = "http/generic"
								if SaveUnhandledAcks:
									UnhandledPacket(p)
									#LogNewPayload(ServerPayloadDir, FromPort, Payload)
							else:
								if SaveUnhandledAcks:
									UnhandledPacket(p)
									#LogNewPayload(ServerPayloadDir, FromPort, Payload)
						elif (sport == "110") and (Payload.find('POP3 Server Ready') > -1):
							ReportId("TS", sIP, "TCP_" + sport, "listening", "pop3/generic", ([]))
							ManualServerDescription[sIP + ",TCP_" + sport] = "pop3/generic"
						elif (sport == "143") and (Payload.find('* OK dovecot ready') > -1):
							ReportId("TS", sIP, "TCP_" + sport, "listening", "imap/dovecot", ([]))
							ManualServerDescription[sIP + ",TCP_" + sport] = "imap/dovecot"
						elif (sport == "143") and (Payload.find(' IMAP4rev1 ') > -1):
							ReportId("TS", sIP, "TCP_" + sport, "listening", "imap/generic", ([]))
							ManualServerDescription[sIP + ",TCP_" + sport] = "imap/generic"
							if SaveUnhandledAcks:
								UnhandledPacket(p)
								#LogNewPayload(ServerPayloadDir, FromPort, Payload)
						elif (sport == "783") and (Payload.find('SPAMD/1.1 ') > -1):
							ReportId("TS", sIP, "TCP_" + sport, "listening", "spamd/spamd", ([]))
							ManualServerDescription[sIP + ",TCP_" + sport] = "spamd/spamd"
						elif ((sport == "3128") or (sport == "80")) and (Payload.find('Via: ') > -1) and (Payload.find(' (squid/') > -1):
							ReportId("TS", sIP, "TCP_" + sport, "listening", "proxy/squid", ([]))
							ManualServerDescription[sIP + ",TCP_" + sport] = "proxy/squid"
						else:
							if SaveUnhandledAcks:
								UnhandledPacket(p)
								#LogNewPayload(ServerPayloadDir, FromPort, Payload)
				elif ToPort in LiveTCPService and LiveTCPService[ToPort]:			#If the "To" side is a known TCP server:
					ClientKey = sIP + ",TCP_" + dport	#Note: CLIENT ip and SERVER port
					if ClientKey not in ClientDescription and Payload:
						if (dport == "22") and (Payload.find('SSH-Latency-Measurement') > -1):
							ReportId("TC", sIP, "TCP_" + dport, "open", "ssh/smokeping-latency-scanner", ([]))
						elif (dport == "22") and (Payload.find('SSH-2.-check_ssh_1.5') > -1):
							ReportId("TC", sIP, "TCP_" + dport, "open", "ssh/nagios-check_ssh", ([]))
						elif (dport == "22") and ((Payload.find('SSH-2.0-OpenSSH_') > -1) or (Payload.find('SSH-1.5-OpenSSH_') > -1)):
							ReportId("TC", sIP, "TCP_" + dport, "open", "ssh/openssh", ([]))
						#As cute as it is to catch this, it miscatches any relay that's carrying a pine-generated mail.
						#elif (dport == "25") and (Payload.find('Message-ID: <Pine.') > -1):
						#	ReportId("TC", sIP, "TCP_" + dport, "open", "smtp/pine", ([]))
						elif ((dport == "80") or (dport == "3128")) and (Payload.find('User-Agent: libwww-perl/') > -1):
							ReportId("TC", sIP, "TCP_" + dport, "open", "http/libwww-perl", ([]))
						elif ((dport == "80") or (dport == "3128")) and (Payload.find('User-Agent: Lynx') > -1):
							ReportId("TC", sIP, "TCP_" + dport, "open", "http/lynx", ([]))
						elif ((dport == "80") or (dport == "3128")) and (Payload.find('User-Agent: Mozilla') > -1)  and (Payload.find(' Firefox/') > -1):
							ReportId("TC", sIP, "TCP_" + dport, "open", "http/firefox", ([]))
						elif ((dport == "80") or (dport == "3128")) and (Payload.find('User-Agent: Wget/') > -1):
							ReportId("TC", sIP, "TCP_" + dport, "open", "http/wget", ([]))
						elif (dport == "143") and (Payload.find('A0001 CAPABILITY') > -1):
							ReportId("TC", sIP, "TCP_" + dport, "open", "imap/generic", ([]))
							#LogNewPayload(ClientPayloadDir, ClientKey, Payload)
						elif (dport == "783") and (Payload.find('PROCESS SPAMC') > -1):
							ReportId("TC", sIP, "TCP_" + dport, "open", "spamd/spamc", ([]))
						else:
							if SaveUnhandledAcks:
								UnhandledPacket(p)
								#LogNewPayload(ClientPayloadDir, ClientKey, Payload)
				#else:	#Neither port pair is known as a server
				#	ShowPacket(p, "IPv4/TCPv4/ACK (RST, SYN, FIN off)/Neither port pair is known as a server", HonorQuit)
				#	#Following is debugging at best; it should only show up early on as the sniffer listens to conversations for which it didn't hear the SYN/ACK
				#	#print "note: neither " + FromPort + " nor " + ToPort + " is listed as a live service."
			elif (p[TCP].flags & 0x17) == 0x00:	#(ACK, RST, SYN, and FIN off)
				UnhandledPacket(p)
				ReportId("TC", sIP, "TCP_" + dport, "open", "TCP Null flag scanner", (['noncompliant', 'scan']))
			elif (p[TCP].flags & 0x17) == 0x03:	#SYN/FIN (ACK and RST off)
				UnhandledPacket(p)
				ReportId("TC", sIP, "TCP_" + dport, "open", "TCP SYN/FIN flag scanner", (['noncompliant', 'scan']))
			elif (p[TCP].flags & 0x17) == 0x05:	#RST/FIN (ACK and SYN off)
				UnhandledPacket(p)
				ReportId("TC", sIP, "TCP_" + dport, "open", "TCP RST/FIN flag scanner", (['noncompliant', 'scan']))
			elif (p[TCP].flags & 0x17) == 0x06:	#SYN/RST (ACK and FIN off)
				UnhandledPacket(p)
				ReportId("TC", sIP, "TCP_" + dport, "open", "TCP SYN/RST flag scanner", (['noncompliant', 'scan']))
			elif (p[TCP].flags & 0x17) == 0x07:	#SYN/RST/FIN (ACK off)
				UnhandledPacket(p)
				ReportId("TC", sIP, "TCP_" + dport, "open", "TCP SYN/RST/FIN flag scanner", (['noncompliant', 'scan']))
			elif (p[TCP].flags & 0x17) == 0x13:	#ACK/SYN/FIN (RST off)
				UnhandledPacket(p)
				ReportId("TC", sIP, "TCP_" + dport, "open", "TCP ACK/SYN/FIN flag scanner", (['noncompliant', 'scan']))
			elif (p[TCP].flags & 0x17) == 0x15:	#ACK/RST/FIN (SYN off)
				UnhandledPacket(p)
				ReportId("TC", sIP, "TCP_" + dport, "open", "TCP ACK/RST/FIN flag scanner", (['noncompliant', 'scan']))
			elif (p[TCP].flags & 0x17) == 0x17:	#SYN/FIN/ACK/RST
				UnhandledPacket(p)
				ReportId("TC", sIP, "TCP_" + dport, "open", "TCP SYN/FIN/ACK/RST flag scanner", (['noncompliant', 'scan']))
			else:	#Other TCP flag combinations here
				ShowPacket(p, "IPv4/TCPv4/Unhandled TCP flag combination", HonorQuit)
### IPv4/TCPv4, probably truncated/fragmented
		elif p[IP].proto == 6:		#TCP, but haslayer fails.  Quite possibly a fragment; either way we can't do anything with it.
			UnhandledPacket(p)
			#ShowPacket(p, "IPv4/TCPv4/no TCP layer", HonorQuit)
### IPv4/UDPv4
		elif p[IP].proto == 17 and p.haslayer(UDP):			#old form: (type(p[UDP]) == UDP):
			#UDP.  We have to check the object type as well as we do get (corrupted? truncated?) packets with type 17 that aren't udp:  AttributeError: 'NoneType' object has no attribute 'sport'
			#Change over to p.getlayer(ICMPv6DestUnreach) ?  We're getting crashes on elif p[IP].proto == 17 and (type(p[UDP]) == UDP):
			#FIXME - possibly run udp packets through ServiceFPs as well?
			#FIXME - use this *_layer = p.getlayer(*) format in all sections
			#FIXME - pull all the extractions as high as possible in their section so we only look them up once
			udp_layer = p.getlayer(UDP)
			sport = str(udp_layer.sport)				#Formerly sport=str(p[UDP].sport)
			dport = str(udp_layer.dport)

			if (sIP == dIP) and (sport == dport):
				ReportId("US", sIP, "UDP_" + sport, "attack", 'land attack', (['malicious', 'spoofed']))

			SrcService = sIP + ",UDP_" + sport
			DstService = dIP + ",UDP_" + dport
			SrcClient = sIP + ",UDP_" + dport

			process_udp_ports(meta, SrcService, DstService, SrcClient, Payload, p)

### IPv4/UDPv4, probably truncated/fragmented
		elif p[IP].proto == 17:					#This is the case where the protocol is listed as 17, but there's no complete UDP header.  Quite likely a 2nd or future fragment.
			UnhandledPacket(p)
### IPv4/UDPv4/ipencap
		elif p[IP].proto == 4:					#ipencap, IP encapsulated in IP.
			outer_ip = p.getlayer(IP, nb=1)
			inner_layer = outer_ip.payload
			if isinstance(inner_layer, IP):
				if inner_layer.getlayer(Raw).load == "this is not an attack":
					ReportId("IP", sIP, "ipencap", "open", 'ipencap/client', (['tunnel', 'scan']))
				else:
					ReportId("IP", sIP, "ipencap", "open", 'ipencap/client', (['tunnel']))
			else:
				ShowPacket(p, "ipencap with non-IP inner layer", HonorQuit)

### IPv4/IPSecv4/GRE	#GRE
		elif p[IP].proto == 47 and p.haslayer(GRE):
			ReportId("PC", sIP, "PROTO_" + str(p[IP].proto), "open", "gre/client", (['tunnel']))
			if p[GRE].proto == 2048:		#0x800==2048==IPv4
				if p[GRE].payload:
					encap_packet = p[GRE].payload
					processpacket(encap_packet)
				else:
					UnhandledPacket(p)
			elif p[GRE].proto == 25944:		#0x6558==25944==Trans Ether Bridging
				if p.haslayer(Raw):
					encap_packet_raw = p[Raw].load
					encap_packet = Ether(encap_packet_raw)
					processpacket(encap_packet)
				else:
					UnhandledPacket(p)
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
						ShowPacket(p, "GRE raw does not appear to have E\x00\x00", HonorQuit)
				else:
					UnhandledPacket(p)
			else:
				ShowPacket(p, "GRE unhandled proto", HonorQuit)

### IPv4/IPSecv4/ESP	#ESP (IPSEC)
		elif p[IP].proto == 50:
			ReportId("PC", sIP, "PROTO_" + str(p[IP].proto), "open", "ipsec-esp/client", (['tunnel']))
			ReportId("PS", dIP, "PROTO_" + str(p[IP].proto), "open", "ipsec-esp/server unconfirmed", (['tunnel']))
			UnhandledPacket(p)
### IPv4/IPSecv4/AH	#AH (IPSEC)
		elif p[IP].proto == 51:
			ReportId("PC", sIP, "PROTO_" + str(p[IP].proto), "open", "ipsec-ah/client", (['tunnel']))
			ReportId("PS", dIP, "PROTO_" + str(p[IP].proto), "open", "ipsec-ah/server unconfirmed", (['tunnel']))
			UnhandledPacket(p)
### IPv4/EIGRPv4	EIGRP = Enhanced Interior Gateway Routing Protocol
		elif (p[IP].proto == 88) and dIP in ("224.0.0.10", "FF02:0:0:0:0:0:0:A"):
			#224.0.0.10 for IPv4 EIGRP Routers, FF02:0:0:0:0:0:0:A for IPv6 EIGRP Routers
			ReportId("RO", sIP, "EIGRP", "router", "", ([]))
		elif p[IP].proto == 88:					#Different target address format, perhaps?
			ShowPacket(p, "IPv4/EIGRP unknown target IP", HonorQuit)
### IPv4/OSPFv4
		elif (p[IP].proto == 89) and (dIP == "224.0.0.5"):		#OSPF = Open Shortest Path First
			UnhandledPacket(p)
### IPv4/PIMv4
		elif (p[IP].proto == 103) and (dIP == "224.0.0.13"):		#PIM = Protocol Independent Multicast
			UnhandledPacket(p)
### IPv4/VRRPv4
		elif (p[IP].proto == 112) and (dIP == "224.0.0.18"):		#VRRP = virtual router redundancy protocol
			UnhandledPacket(p)
### IPv4/SSCOPMCE
		elif p[IP].proto == 128:
			UnhandledPacket(p)
		else:		#http://www.iana.org/assignments/protocol-numbers
			#Look up protocol in /etc/protocols
			ShowPacket(p, "Other IP protocol (" + meta['sIP'] + "->" + meta['dIP'] + "): " + str(p[IP].proto), HonorQuit)
	#Look up other ethernet types in:
	# http://en.wikipedia.org/wiki/EtherType
	# /etc/ethertypes
	# http://www.iana.org/assignments/ethernet-numbers
	# http://standards.ieee.org/develop/regauth/ethertype/eth.txt
	# http://www.cavebear.com/archive/cavebear/Ethernet/type.html
		if SuspiciousIPs:
			#We do not need to explode IPv4 addresses with explode_ip(
			if sIP in SuspiciousIPs or dIP in SuspiciousIPs:
				SuspiciousPacket(p)
	elif ((p.haslayer(CookedLinux) and p[CookedLinux].proto == 0x800) or (p.haslayer(Ether) and ((p[Ether].type == 0x0800) or (p[Ether].type == 0x8100)))):
		#Like above, but has no IP layer.  Probably truncated packet at the end of a still-running capture.
		UnhandledPacket(p)
### 2114: Wake-on-lan
	elif p.haslayer(Ether) and p[Ether].type == 0x0842:
		UnhandledPacket(p)
### 9728: Unknown
	elif p.haslayer(Ether) and p[Ether].type == 0x2600:
		UnhandledPacket(p)
	#FIXME - add checks for CookedLinux and Ipv6 as well as Ether+IPv6
### IPv6 ethertype but not ipv6 in the ip header
	elif (p.haslayer(Ether) and p[Ether].type == 0x86DD) and p.haslayer(IPv6) and isinstance(p[IPv6], IPv6) and p[IPv6].version != 6:
		#ShowPacket(p, "IPV6 packet with version != 6", HonorQuit)
		UnhandledPacket(p)
### IPv6
	elif (p.haslayer(Ether) and p[Ether].type == 0x86DD) and p.haslayer(IPv6) and isinstance(p[IPv6], IPv6):
		dIP = explode_ip(str(p[IPv6].dst))

		if meta['sMAC'] == 'ff:ff:ff:ff:ff:ff':
			ReportId("IP", sIP, "Broadcast_source_mac", "open", "Source mac address is broadcast", (['noncompliant']))

		if p.getlayer(Raw):
			Payload = p.getlayer(Raw).load
		else:
			Payload = ""

### IPv6/IPv6ExtHdrHopByHop=0  Hop-by-hop option header
		if p[IPv6].nh == 0 and meta['ttl'] == 1 and p.getlayer(IPv6ExtHdrHopByHop) and p[IPv6ExtHdrHopByHop].nh == 58 and (p.haslayer(ICMPv6MLQuery) or p.haslayer(ICMPv6MLReport) or p.haslayer(ICMPv6MLDone)):	#0 is Hop-by-hop options
			UnhandledPacket(p)
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
			UnhandledPacket(p)
		elif p[IPv6].nh == 0:
			ShowPacket(p, "IPv6/IPv6ExtHdrHopByHop = 0; FIXME, intermediate header on its way to the real header", HonorQuit)
			#https://tools.ietf.org/html/rfc2711 (router alert option)
			#Specifically "router contains a MLD message": https://tools.ietf.org/html/rfc2710
### IPv6/TCPv6=6
		elif p[IPv6].nh == 6:
			sport = str(p[TCP].sport)
			dport = str(p[TCP].dport)

			if (sIP == dIP) and (sport == dport):
				ReportId("TS", sIP, "TCP_" + sport, "attack", 'land attack IP address spoofed', (['malicious', 'spoofed']))

			if (p[TCP].flags & 0x17) == 0x12:	#SYN/ACK	(RST and FIN off)
				CliService = dIP + ",TCP_" + sport
				if CliService not in SynAckSentToTCPClient:
					SynAckSentToTCPClient[CliService] = True

				#If we've seen a syn sent to this port and have either not seen any SA/R, or we've seen a R in the past:
				#The last test is for a service that was previously closed and is now open; report each transition once.
				Service = sIP + ",TCP_" + sport
				if (Service in SynSentToTCPService) and ((Service not in LiveTCPService) or (not LiveTCPService[Service])):
					LiveTCPService[Service] = True
					if sport in PolicyViolationTCPPorts:
						ReportId("TS", sIP, "TCP_" + sport, "listening", '', (['portpolicyviolation']))
					else:
						ReportId("TS", sIP, "TCP_" + sport, "listening", '', ([]))
			elif (p[TCP].flags & 0x17) == 0x02:	#SYN		(RST, ACK, and FIN off)
				Service = dIP + ",TCP_" + dport
				if Service not in SynSentToTCPService:
					SynSentToTCPService[Service] = True
				if dport in PolicyViolationTCPPorts:
					ReportId("TC", sIP, "TCP_" + dport, "open", '', (['portpolicyviolation']))
			elif (p[TCP].flags & 0x07) == 0x01:	#FIN		(RST and SYN off, ignore ACK)
				CliService = sIP + ",TCP_" + dport
				if CliService in SynAckSentToTCPClient and ((CliService not in LiveTCPClient) or (not LiveTCPClient[CliService])):
					LiveTCPClient[CliService] = True
					ReportId("TC", sIP, "TCP_" + dport, "open", '', ([]))
			elif (p[TCP].flags & 0x07) == 0x04:	#RST		(SYN and FIN off, ignore ACK)
				#FIXME - handle rst going in the other direction?
				Service = sIP + ",TCP_" + sport
				if Service in SynSentToTCPService and ((Service not in LiveTCPService) or LiveTCPService[Service]):
					LiveTCPService[Service] = False
					ReportId("TS", sIP, "TCP_" + sport, "closed", '', ([]))

				if Service in SynSentToTCPService:
					#Prober is dIP.  Probed port is Service (= sIP + ",TCP_" + sport)
					if dIP not in ClosedPortsReceived:
						ClosedPortsReceived[dIP] = set()
					ClosedPortsReceived[dIP].add(Service)
					if len(ClosedPortsReceived[dIP]) >= min_closed_ports_for_scanner:
						ReportId("IP", dIP, "IP", "suspicious", 'Scanned closed ports.', (['scan']))
			elif (p[TCP].flags & 0x17) == 0x10:	#ACK		(RST, SYN, and FIN off)
				pass
				#print meta['sIP'] + ":" + sport + " -> ", meta['dIP'] + ":" + dport
			elif (p[TCP].flags & 0x17) == 0x05:	#RST/FIN (ACK and SYN off)
				UnhandledPacket(p)
				ReportId("TC", sIP, "TCP_" + dport, "open", "TCP RST/FIN flag scanner", (['noncompliant', 'scan']))
			elif (p[TCP].flags & 0x17) == 0x06:	#SYN/RST (ACK and FIN off)
				UnhandledPacket(p)
				ReportId("TC", sIP, "TCP_" + dport, "open", "TCP SYN/RST flag scanner", (['noncompliant', 'scan']))
			elif (p[TCP].flags & 0x17) == 0x07:	#SYN/RST/FIN (ACK off)
				UnhandledPacket(p)
				ReportId("TC", sIP, "TCP_" + dport, "open", "TCP SYN/RST/FIN flag scanner", (['noncompliant', 'scan']))
			elif (p[TCP].flags & 0x17) == 0x15:	#ACK/RST/FIN (SYN off)
				UnhandledPacket(p)
				ReportId("TC", sIP, "TCP_" + dport, "open", "TCP ACK/RST/FIN flag scanner", (['noncompliant', 'scan']))
			else:
				ShowPacket(p, "IPv6/TCPv6/UnhandledFlags: " + str(p[TCP].flags), HonorQuit)
### IPv6/UDPv6=17
		elif (p[IPv6].nh == 17) and p.haslayer(UDP):
			udp_layer = p.getlayer(UDP)
			sport = str(udp_layer.sport)
			dport = str(udp_layer.dport)

			if (sIP == dIP) and (sport == dport):
				ReportId("US", sIP, "UDP_" + sport, "attack", 'land attack IP address spoofed', (['malicious', 'spoofed']))

			SrcService = sIP + ",UDP_" + sport
			DstService = dIP + ",UDP_" + dport
			SrcClient = sIP + ",UDP_" + dport

			process_udp_ports(meta, SrcService, DstService, SrcClient, Payload, p)

### IPv6/Fragmentation=44
		elif p[IPv6].nh == 44: 		#Fragment header.  Not worth trying to extract info from following headers.
			#https://tools.ietf.org/html/rfc5798
			UnhandledPacket(p)
### IPv6/ICMPv6=58
		elif p[IPv6].nh == 58:
			#Layer names; see layers/inet6.py ( /opt/local/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages/scapy/layers/inet6.py ), hash named icmp6typescls
### IPv6/ICMPv6=58/DestUnreach=1
			if p.getlayer(ICMPv6DestUnreach) and p.getlayer(IPerror6) and isinstance(p[IPerror6], IPerror6):   	#https://tools.ietf.org/html/rfc4443#section-3.1
				Code = p[ICMPv6DestUnreach].code
### IPv6/ICMPv6=58/DestUnreach=1/No route to dest=0	No route to destination; appears equivalent to IPv4 net unreachable
				if Code == 0:
					ReportId("IP", meta['OrigdIP'], "IP", "dead", 'net unreachable', ([]))
					ReportId("RO", sIP, "NetUn", "router", "client_ip=" + dIP, ([]))
### IPv6/ICMPv6=58/DestUnreach=1/AdminProhib=1		Communication with destination administratively prohibited (blocked by firewall)
				elif Code == 1:
					pass
### IPv6/ICMPv6=58/DestUnreach=1/BeyondScope=2		Beyond scope of source address					https://tools.ietf.org/html/rfc4443
				elif Code == 2:
					pass
### IPv6/ICMPv6=58/DestUnreach=1/AddressUnreach=3	Address unreachable (general, used when there is no more specific reason); appears equivalent to host unreachable
				elif Code == 3:
					ReportId("IP", meta['OrigdIP'], "IP", "dead", 'host unreachable', ([]))
					ReportId("RO", sIP, "HostUn", "router", "client_ip=" + dIP, ([]))
### IPv6/ICMPv6=58/DestUnreach=1/PortUnreach=4		Port unreachable and embedded protocol = 17, UDP, as it should be.  Appears equivalent to port unreachable
				elif (Code == 4) and (p[IPerror6].nh == 17) and p.haslayer(UDPerror) and isinstance(p[UDPerror], UDPerror):
					DNSServerLoc = meta['OrigsIP'] + ",UDP_53"
					if (p[UDPerror].sport == 53) and (DNSServerLoc in ManualServerDescription) and (ManualServerDescription[DNSServerLoc] == "dns/server"):
						#If orig packet coming from 53 and coming from a dns server, don't do anything (closed port on client is a common effect)
						#Don't waste time on port unreachables going back to a dns server; too common, and ephemeral anyways.
						pass
					else:
						#If orig packet coming from something other than 53, or coming from 53 and NOT coming from a dns server, log as closed
						OrigDPort = str(p[UDPerror].dport)
						OrigDstService = meta['OrigdIP'] + ",UDP_" + OrigDPort
						ReportId("US", meta['OrigdIP'], "UDP_" + OrigDPort, "closed", "port unreachable", ([]))

						if include_udp_errors_in_closed_ports:
							#Prober is dIP.  Probed port is: meta['OrigdIP'] + ",UDP_" + OrigDPort
							if dIP not in ClosedPortsReceived:
								ClosedPortsReceived[dIP] = set()
							ClosedPortsReceived[dIP].add(OrigDstService)
							if len(ClosedPortsReceived[dIP]) >= min_closed_ports_for_scanner:
								ReportId("IP", dIP, "IP", "suspicious", 'Scanned closed ports.', (['scan']))
				elif (Code == 4) and (p[IPerror6].nh == 6) and isinstance(p[TCPerror], TCPerror):				#Port unreachable and embedded protocol = 6, TCP, which it shouldn't.
					OrigDPort = str(p[TCPerror].dport)
					Service = meta['OrigdIP'] + ",TCP_" + OrigDPort
					if Service in SynSentToTCPService and ((Service not in LiveTCPService) or LiveTCPService[Service]):
						LiveTCPService[Service] = False
						ReportId("TS", str(p[IPerror6].dst), "TCP_" + str(p[TCPerror].dport), "closed", '', ([]))

					if Service in SynSentToTCPService:
						#Prober is dIP.  Probed port is meta['OrigdIP'] + ",TCP_" + OrigDPort
						if dIP not in ClosedPortsReceived:
							ClosedPortsReceived[dIP] = set()
						ClosedPortsReceived[dIP].add(Service)
						if len(ClosedPortsReceived[dIP]) >= min_closed_ports_for_scanner:
							ReportId("IP", dIP, "IP", "suspicious", 'Scanned closed ports.', (['scan']))
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
					ShowPacket(p, "IPV6/ICMPv6/Dest Unreach=1/Unknown code", HonorQuit)
### IPv6/ICMPv6=58/PacktTooBig=2
			elif p.getlayer(ICMPv6PacketTooBig):
				ReportId("RO", sIP, "TooBig", "router", "client_ip=" + dIP, ([]))
### IPv6/ICMPv6=58/TimeExceeded=3
			elif p.getlayer(ICMPv6TimeExceeded):
				Code = p[ICMPv6TimeExceeded].code
				if Code == 0:				#hop limit exceeded in transit
					ReportId("RO", sIP, "TTLEx", "router", "client_ip=" + dIP, ([]))
				else:
					ShowPacket(p, "IPv6/ICMPv6/ICMPv6TimeExceeded = type 3/Code = " + str(Code), HonorQuit)
### IPv6/ICMPv6=58/EchoRequest=128
			elif p.getlayer(ICMPv6EchoRequest):
				pass
### IPv6/ICMPv6=58/EchoReply=129
			elif p.getlayer(ICMPv6EchoReply):
				ReportId("IP", sIP, "IP", "live", 'icmp echo reply', ([]))
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
				ReportId("RO", sIP, "RouterAdv", "router", AdditionalInfo, ([]))

				if p.getlayer(ICMPv6NDOptSrcLLAddr):
					router_mac_addr = str(p[ICMPv6NDOptSrcLLAddr].lladdr)
					ReportId("MA", sIP, 'Ethernet', router_mac_addr, '', ([]))
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
					ReportId("MA", sIP, 'Ethernet', host_mac_addr, '', ([]))
### IPv6/ICMPv6=58/ND_NeighborAdvertisement=136												https://tools.ietf.org/html/rfc4861
			elif p.getlayer(ICMPv6ND_NA) and p.getlayer(Ether) and meta['ttl'] == 255 and p[ICMPv6ND_NA].code == 0:
				if p[ICMPv6ND_NA].R == 1:
					ReportId("RO", sIP, "NeighborAdvRouterFlag", "router", '', ([]))
				host_mac_addr = meta['sMAC']
				ReportId("MA", sIP, 'Ethernet', host_mac_addr, '', ([]))
### IPv6/ICMPv6=58/ND_Redirect=137													http://www.tcpipguide.com/free/t_ICMPv6RedirectMessages-2.htm
			elif p.getlayer(ICMPv6ND_Redirect) and p.getlayer(Ether) and meta['ttl'] == 255 and p[ICMPv6ND_Redirect].code == 0:
				ReportId("RO", sIP, "ND_Redirect_source", "router", "client_ip=" + dIP, ([]))				#the original complaining router
				ReportId("RO", p[ICMPv6ND_Redirect].tgt, "ND_Redirect_target", "router", "client_ip=" + dIP, ([]))	#the better router to use
				if p.getlayer(ICMPv6NDOptDstLLAddr):
					ReportId("MA", p[ICMPv6ND_Redirect].tgt, 'Ethernet', p[ICMPv6NDOptDstLLAddr].lladdr, '', ([]))	#packet probably includes the mac address of the better router too.
			else:
				ShowPacket(p, "IPv6/ICMPv6/unhandled type", HonorQuit)
### IPv6/SATNET-EXPAK=64
		elif p[IPv6].nh == 64:
			UnhandledPacket(p)
### IPv6/EIGRPv4	EIGRP = Enhanced Interior Gateway Routing Protocol
		elif (p[IPv6].nh == 88) and dIP in ("224.0.0.10", "FF02:0:0:0:0:0:0:A"):
			#224.0.0.10 for IPv4 EIGRP Routers, FF02:0:0:0:0:0:0:A for IPv6 EIGRP Routers
			ReportId("RO", sIP, "EIGRP", "router", "", ([]))
		elif p[IPv6].nh == 88:						#Different target address format, perhaps?
			ShowPacket(p, "IPv6/EIGRP unknown target IP", HonorQuit)
### IPv6/OSPF=89
		elif (p[IPv6].nh == 89) and (dIP == "ff02:0000:0000:0000:0000:0000:0000:0005"): 		#OSPF
			#https://tools.ietf.org/html/rfc5340
			UnhandledPacket(p)
### IPv6/VRRP=112
		elif (p[IPv6].nh == 112) and (dIP == "ff02:0000:0000:0000:0000:0000:0000:0012"): 		#VRRPv6	VRRP = virtual router redundancy protocol
			#https://tools.ietf.org/html/rfc5798
			UnhandledPacket(p)
### IPv6/other
		else:
			ShowPacket(p, "IPV6 unknown protocol; Next header:" + str(p[IPv6].nh), HonorQuit)

		if SuspiciousIPs:
			if sIP in SuspiciousIPs or dIP in SuspiciousIPs:
				SuspiciousPacket(p)
### No ethernet layer
	elif not p.haslayer(Ether):
### 802.11 wireless
		if p.haslayer(RadioTap):
			if p.haslayer(Dot11) and p.haslayer(Dot11Deauth) and p[Dot11Deauth].reason == 7:	#"class3-from-nonass"
				if p[Dot11].addr1 == p[Dot11].addr3:		#These should be the AP mac address
					ReportId("WI", "0.0.0.0", "802.11_Deauth", "Deauthentication: client=" + p[Dot11].addr2 + " AP=" + p[Dot11].addr1, "", ([]))
				elif p[Dot11].addr2 == p[Dot11].addr3:		#These should be the AP mac address
					ReportId("WI", "0.0.0.0", "802.11_Deauth", "Deauthentication: client=" + p[Dot11].addr1 + " AP=" + p[Dot11].addr2, "", ([]))
				else:
					ShowPacket(p, "802.11 Deauth", HonorQuit)
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
						ReportId("WI", "0.0.0.0", "802.11_Auth", "success", "", ([]))
				else:
					ShowPacket(p, "802.11 Elt with unknown intermediate header", HonorQuit)
				if current_element:
					while isinstance(current_element, Dot11Elt):		#Somewhat equivalent:	while not isinstance(current_element, NoPayload):
						if current_element.ID == 0 and current_element.info.strip():	#ESSID
							ReportId("WI", "0.0.0.0", "802.11 ESSID", current_element.info.strip().replace('\n', '').replace('\r', '').replace(',', ' '), "", ([]))
						current_element = current_element.payload
			elif p.haslayer(Dot11) and p[Dot11].type == 0:					#0 == Management
				UnhandledPacket(p)
			elif p.haslayer(Dot11) and p[Dot11].type == 1:					#1 == Control
				UnhandledPacket(p)
			elif p.haslayer(Dot11) and p[Dot11].type == 2 and p.haslayer(LLC):		#2 == Data
				UnhandledPacket(p)
			elif p.haslayer(Dot11) and p[Dot11].type == 2 and p.haslayer(Dot11WEP):		#2 == Data
				ReportId("WI", "0.0.0.0", "802.11 WEP", "", "", ([]))
			elif p.haslayer(Dot11):
				ShowPacket(p, "802.11", HonorQuit)
				UnhandledPacket(p)
			else:
				UnhandledPacket(p)
		elif p.haslayer(Raw):
			#Sample payload from Mac lo0 packet:   \x02\x00\x00\x00E\x00\x00   Hack; strip off first 4 bytes and interpret the rest as IP.
			encap_packet_raw = None
			if p[Raw].load[0:6] in two_prelude_ip_start:
				encap_packet_raw = p[Raw].load[4:]
			if encap_packet_raw:
				encap_packet = IP(encap_packet_raw)
				processpacket(encap_packet)
			else:
				ShowPacket(p, "Non-ethernet raw does not appear to have E\x00\x00", HonorQuit)
		else:
			UnhandledPacket(p)
		#ShowPacket(p, "packet has no ethernet layer", HonorQuit)
	elif p[Ether].type == 0x4860:		#18528: ?
		UnhandledPacket(p)
	elif p[Ether].type == 0x6002:		#24578: MOP Remote Console
		UnhandledPacket(p)
	elif p[Ether].type == 0x8001:		#32769: ?
		UnhandledPacket(p)
	elif p[Ether].type == 0x8035:		#32821: Reverse ARP https://en.wikipedia.org/wiki/Reverse_Address_Resolution_Protocol
		UnhandledPacket(p)
	elif p[Ether].type == 0x8100:		#33024 = IEEE 802.1Q VLAN-tagged frames (initially Wellfleet)
		UnhandledPacket(p)
	elif p[Ether].type == 0x872D:		#34605 ?
		UnhandledPacket(p)
	elif p[Ether].type == 0x8809:		#34825 LACP (builds multiple links into a trunk)
		UnhandledPacket(p)
	elif p[Ether].type == 0x888E:		#34958 EAPOL, EAP over LAN (IEEE 802.1X)
		UnhandledPacket(p)
	elif p[Ether].type == 0x8899:		#34969 Unknown
		UnhandledPacket(p)
	elif p[Ether].type == 0x88A2:		#34978 ATA over ethernet
		UnhandledPacket(p)
	elif p[Ether].type == 0x88A7:		#34983 Unknown
		UnhandledPacket(p)
	elif p[Ether].type == 0x88CC:		#35020 LLDP Link Layer Discovery Protocol
		UnhandledPacket(p)
	elif p[Ether].type == 0x88E1:		#35041 HomePlug AV MME
		UnhandledPacket(p)
	elif p[Ether].type == 0x8912:		#35090 unknown
		UnhandledPacket(p)
	elif p[Ether].type == 0x9000:		#36864 = Ethernet loopback protocol.  http://wiki.wireshark.org/Loop
		UnhandledPacket(p)
	else:
		ShowPacket(p, "Unregistered ethernet type:" + str(p[Ether].type), HonorQuit)
		#For a good reference on new ethernet types, see:
		#http://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
		#http://www.iana.org/assignments/ethernet-numbers
		#http://en.wikipedia.org/wiki/EtherType


#======== Start of main code. ========
if __name__ == "__main__":
	import argparse

	signal.signal(signal.SIGINT, signal_handler)

	parser = argparse.ArgumentParser(description='Passer version ' + str(passerVersion))
	input_options = parser.add_mutually_exclusive_group()
	input_options.add_argument('-i', '--interface', help='Interface from which to read packets (default is all interfaces)', required=False, default=None)
	#input_options.add_argument('-r', '--read', help='Pcap file(s) from which to read packets (use   -   for stdin)', required=False, default=[], nargs='*')	#Not supporting stdin at the moment
	input_options.add_argument('-r', '--read', help='Pcap file(s) from which to read packets', required=False, default=[], nargs='*')
	#input_options.add_argument('-r', '--read', help='Pcap file from which to read packets', required=False, default=None)						#Old input form that only supported a single input file
	parser.add_argument('-l', '--log', help='File to which to write output csv lines', required=False, default=None)
	parser.add_argument('-s', '--suspicious', help='File to which to write packets to/from suspicious IPs', required=False, default=None)
	parser.add_argument('-u', '--unhandled', help='File to which to write unhandled packets', required=False, default=None)
	parser.add_argument('--acks', help='Save unhandled ack packets as well', required=False, default=False, action='store_true')
	parser.add_argument('-d', '--devel', help='Enable development/debug statements', required=False, default=False, action='store_true')
	parser.add_argument('-q', '--quit', help='With -d, force passer to quit when debug packets are shown', required=False, default=False, action='store_true')
	parser.add_argument('--nxdomain', help='Show NXDomain DNS answers', required=False, default=False, action='store_true')
	parser.add_argument('--creds', help='Show credentials as well', required=False, default=False, action='store_true')
	parser.add_argument('-b', '--bpf', help='BPF to restrict which packets are processed', required=False, default='')
	parser.add_argument('--debuglayers', required=False, default=False, action='store_true', help=argparse.SUPPRESS)						#Debug scapy layers, hidden option
	(parsed, unparsed) = parser.parse_known_args()
	args = vars(parsed)


	debug_known_layer_lists = args['debuglayers']

	if args['bpf']:
		bpfilter = args['bpf']
		if len(unparsed) > 0:
			sys.stderr.write('Too many arguments that do not match a parameter, exiting.\n')
			quit()
	else:
		if len(unparsed) == 0:
			bpfilter = ''
		elif len(unparsed) == 1:
			bpfilter = str(unparsed[0])
		else:
			sys.stderr.write('Too many arguments that do not match a parameter.  Any change you did not put the bpf expression in quotes?  Exiting.\n')
			quit()

	InterfaceName = args['interface']
	LogFilename = args['log']
	UnhandledFilename = args['unhandled']
	SuspiciousFilename = args['suspicious']
	Devel = args['devel']
	QuitOnShow = args['quit']
	ReportNXDomain = args['nxdomain']								#If True , we'll output a line for items that come back with NXDOMAIN dns answers too.
	SaveUnhandledAcks = args['acks']
	ShowCredentials = args['creds']									#If True , we'll include passwords in the output lines.  At the time of this writing, only the snmp community string is logged when True



	Debug("Passer version " + str(passerVersion))

	if not os.path.exists(config_dir):
		os.makedirs(config_dir)


	if os.path.exists(suspicious_ips_file):
		with open(suspicious_ips_file) as suspicious_h:
			SuspiciousIPs = json.loads(suspicious_h.read())

	if os.path.exists(trusted_ips_file):
		with open(trusted_ips_file) as trusted_h:
			TrustedIPs = json.loads(trusted_h.read())
	else:
		#Use root nameserver ips as initial set.
		TrustedIPs = ['192.5.5.241', '192.33.4.12', '192.36.148.17', '192.58.128.30', '192.112.36.4', '192.203.230.10', '193.0.14.129', '198.41.0.4', '198.97.190.53', '199.7.83.42', '199.7.91.13', '199.9.14.201', '202.12.27.33', '2001:0dc3:0000:0000:0000:0000:0000:0035', '2001:07fd:0000:0000:0000:0000:0000:0001', '2001:07fe:0000:0000:0000:0000:0000:0053', '2001:0500:00a8:0000:0000:0000:0000:000e', '2001:0500:0001:0000:0000:0000:0000:0053', '2001:0500:002d:0000:0000:0000:0000:000d', '2001:0500:002f:0000:0000:0000:0000:000f', '2001:0500:0002:0000:0000:0000:0000:000c', '2001:0500:009f:0000:0000:0000:0000:0042', '2001:0500:0012:0000:0000:0000:0000:0d0d', '2001:0500:0200:0000:0000:0000:0000:000b', '2001:0503:0c27:0000:0000:0000:0002:0030', '2001:0503:ba3e:0000:0000:0000:0002:0030']
		write_object(trusted_ips_file, json.dumps(TrustedIPs))

	for one_trusted in TrustedIPs:
		if one_trusted in SuspiciousIPs:
			del SuspiciousIPs[one_trusted]


	if not has_advanced_ntp_headers:
		Debug('The version of scapy on your system does not appear to be new enough to include advanced NTP processing.  If possible, please upgrade scapy.')

	if LogFilename:
		try:
			LogFile = open(LogFilename, 'a')
		except:
			Debug("Unable to append to " + LogFilename + ", no logging will be done.")
			LogFile = None
	else:
		LogFile = None

	if UnhandledFilename:
		try:
			UnhandledFile = PcapWriter(filename=UnhandledFilename, append=True)
		except:
			Debug("Unable to open " + UnhandledFilename + ", no unhandled packets will be saved.")
			UnhandledFile = None
	else:
		UnhandledFile = None

	if SuspiciousFilename:
		try:
			SuspiciousFile = PcapWriter(filename=SuspiciousFilename, append=True)
		except:
			Debug("Unable to open " + SuspiciousFilename + ", no suspicious packets will be saved.")
			SuspiciousFile = None
	else:
		SuspiciousFile = None


	Debug("BPFilter is " + bpfilter)
	#Hmmm, bpfilter appears not to work.  It loads correctly into the variable, but the sniff command appears to ignore it.


	#Temporarily disabled p0f
	#if not os.path.isfile("/etc/p0f/p0f.fp"):
	#	Debug("/etc/p0f/p0f.fp not found; please install p0f version 2 to enable OS fingerprinting.")

	for oneMacFile in ('/usr/share/ettercap/etter.finger.mac', '/opt/local/share/ettercap/etter.finger.mac', '/usr/share/nmap/nmap-mac-prefixes', '/opt/local/share/nmap/nmap-mac-prefixes', '/usr/share/wireshark/manuf', '/opt/local/share/wireshark/manuf', '/usr/share/ethereal/manuf', '/usr/share/arp-scan/ieee-oui.txt', '/opt/local/share/arp-scan/ieee-oui.txt'):
		if os.path.isfile(oneMacFile):
			LoadMacData(oneMacFile)
	if len(EtherManuf) == 0:
		Debug("None of the default mac address listings found.  Please install ettercap, nmap, wireshark, and/or arp-scan.")
	else:
		Debug(str(len(EtherManuf)) + " mac prefixes loaded.")

	for oneFPFile in ('/usr/local/share/nmap/nmap-service-probes', '/usr/share/nmap/nmap-service-probes', '/opt/local/share/nmap/nmap-service-probes'):
		if os.path.isfile(oneFPFile):
			LoadNmapServiceFP(oneFPFile)
	if len(ServiceFPs) == 0:
		Debug("Can't locate /{usr,opt}/{local/,}share/nmap/nmap-service-probes.  Please install nmap to support more server descriptions.")
	else:
		Debug("Fingerprints for " + str(len(ServiceFPs)) + " ports loaded.")


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

	#Neither this nor adding "filter=bpfilter" to each sniff line seems to actually apply the bpf.  Hmmm.
	try:
		conf.filter = bpfilter
	except:
		config.filter = bpfilter

	#if exit_now:
	#	quit(1)


	#read_from_stdin = False		#If stdin requested, it needs to be processed last, so we remember it here.  We also handle the case where the user enters '-' more than once by simply remembering it.

	#if args['interface'] is None and args['read'] == []:
		#Debug("No source specified with -i or -r, exiting.")
		#quit(1)
		#Debug('No source specified, reading from stdin.')
		#read_from_stdin = True


	#Process normal files first
	for PcapFilename in args['read']:
		work_filename = None
		delete_temp = False

		if not PcapFilename:
			Debug("Skipping empty filename.")
		elif PcapFilename == '-':
			#read_from_stdin = True
			Debug("Unable to read from stdin, exiting.")
			quit(1)
		elif not os.path.exists(PcapFilename):
			Debug("No file named " + str(PcapFilename) + ", skipping.")
		#By this point we have an existing, non-empty, non-stdin file.  Now check to see if we need to decompress it, and finally process the pcap file.
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
				sniff(store=0, offline=work_filename, filter=bpfilter, stopperTimeout=5, stopper=exit_now, prn=lambda x: processpacket(x))
			elif False:					#Old scapy "stop_filter" feature to exit if needed; doesn't work yet, disabled.
				sniff(store=0, offline=work_filename, filter=bpfilter, stop_filter=exit_now_packet_param, prn=lambda x: processpacket(x))
			else:						#No attempt to exit sniff loop for the moment.
				sniff(store=0, offline=work_filename, filter=bpfilter, prn=lambda x: processpacket(x))

		if delete_temp and work_filename != PcapFilename and os.path.exists(work_filename):
			os.remove(work_filename)


	#Now that we've done all files, sniff from a specific interface.
	if InterfaceName:
		if False:						#New scapy "stopper" feature to exit if needed; doesn't work yet, disabled.
			#https://github.com/secdev/scapy/wiki/Contrib:-Code:-PatchSelectStopperTimeout
			sniff(store=0, iface=InterfaceName, filter=bpfilter, stopperTimeout=5, stopper=exit_now, prn=lambda x: processpacket(x))
		elif False:						#Old scapy "stop_filter" feature to exit if needed; doesn't work yet, disabled.
			sniff(store=0, iface=InterfaceName, filter=bpfilter, stop_filter=exit_now_packet_param, prn=lambda x: processpacket(x))
		else:							#No attempt to exit sniff loop for the moment.
			sniff(store=0, iface=InterfaceName, filter=bpfilter, prn=lambda x: processpacket(x))


	#If the user didn't specify any files or interfaces to read from, read from all interfaces.
	if not InterfaceName and args['read'] == []:
		if False:						#New scapy "stopper" feature to exit if needed; doesn't work yet, disabled.
			#https://github.com/secdev/scapy/wiki/Contrib:-Code:-PatchSelectStopperTimeout
			sniff(store=0, filter=bpfilter, stopperTimeout=5, stopper=exit_now, prn=lambda x: processpacket(x))
		elif False:						#Old scapy "stop_filter" feature to exit if needed; doesn't work yet, disabled.
			sniff(store=0, filter=bpfilter, stop_filter=exit_now_packet_param, prn=lambda x: processpacket(x))
		else:							#No attempt to exit sniff loop for the moment.
			sniff(store=0, filter=bpfilter, prn=lambda x: processpacket(x))

	#To limit to the first 500 packets, add ", count=500" at the end of the "sniff" command inside the last paren


	generate_summary_lines()

	#Only write out if changes have been made (if no changes have been made, no point in writing the dictionary out).  To test this, see if there are any entries in NewSuspiciousIPs.
	if NewSuspiciousIPs:
		#We may be in a situation where two copies of this program running at the same time may both have changes to write.  Just before writing this out, we re-read the on-disk version to pull in any changes made by other copies that finished before us.
		if os.path.exists(suspicious_ips_file):
			with open(suspicious_ips_file) as suspicious_h:
				SuspiciousIPs_at_end = json.loads(suspicious_h.read())

		for one_trusted in TrustedIPs:
			if one_trusted in SuspiciousIPs_at_end:
				del SuspiciousIPs_at_end[one_trusted]

		#Now we copy all entries from the on-disk version (which may contain more than we originally read) into SuspiciousIPs just before writing it back out.
		for one_ip in SuspiciousIPs_at_end:
			if one_ip not in SuspiciousIPs:
				SuspiciousIPs[one_ip] = []
			for one_warning in SuspiciousIPs_at_end[one_ip]:
				if one_warning not in SuspiciousIPs[one_ip]:
					SuspiciousIPs[one_ip].append(one_warning)
		#Yes, this is shaky and still has race conditions.  It's worse than using a database, and better than doing nothing at all.  Worst case we lose some entries from one of the copies.

		write_object(suspicious_ips_file, json.dumps(SuspiciousIPs))

	#FIXME - move to just after sniffing done for a given source and add up the deltas into a cumulative time for all captures.
	if start_stamp and end_stamp:
		pcap_delta = end_stamp - start_stamp
		Debug("The packets processed ran from " + start_string + " to " + end_string + " for " + str(pcap_delta) + " seconds.")
	else:
		Debug("It does not appear the start and end stamps were set - were any packets processed?")
