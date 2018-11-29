#!/usr/bin/python
"""Library of routines used by passer."""
#Copyright 2018, William Stearns <william.l.stearns@gmail.com>

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
from __future__ import print_function

import ipaddress
from scapy.all import *			#Required for Scapy 2.0 and above
use_scapy_all = True


#======== Constants ========

#==== Ports ====
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


#======== Regexes ========
SIPFromMatch = re.compile('From:[^<]*<sip:([a-zA-Z0-9_\.-]+)@([a-zA-Z0-9:_\.-]+)[;>]')		#https://en.wikipedia.org/wiki/SIP_URI_scheme
SIPToMatch = re.compile('To:[^<]*<sip:([a-zA-Z0-9_\.-]+)@([a-zA-Z0-9:_\.-]+)[;>]')



#======== Variables ========
passer_lib_version = '0.4'
Type = 0				#Indexes into the tuple used in passing data to the output handler
IPAddr = 1
Proto = 2
State = 3
Description = 4
Warnings = 5


#======== Support functions ========

def ReturnLayers(rl_p):
	"""Return the layers in this packet from outer to inner.  Sample use: list(ReturnLayers(p))"""
	#try:
	yield rl_p.name
	#except AttributeError:
	#	print('>>' + str(rl_p))
	while rl_p.payload:
		rl_p = rl_p.payload
		yield rl_p.name


def explode_ip(raw_addr):
	"""Converts the input IP address string into its exploded form (type "unicode" in python2) ready for printing.  The raw_addr string should already have leading and trailing whitespace removed before being handed to this function.  If it's not a valid IP address, returns an empty string."""

	try:
		if sys.version_info > (3, 0):
			raw_addr_string = str(raw_addr)
		else:
			raw_addr_string = unicode(raw_addr)
	except UnicodeDecodeError:
		raw_addr_string = ''

		#if Devel:
		#	Debug('Cannot convert:'
		#	Debug(raw_addr)
		#	raise
		#else:
		#	pass

	full_ip_string = ''
	ip_obj = None

	if raw_addr_string != '' and not raw_addr_string.endswith(('.256', '.257', '.258', '.259', '.260')):		#raw_addr_string.find('.256') == -1
		try:
			ip_obj = ipaddress.ip_address(raw_addr_string)
		except ValueError:
			#See if it's in 2.6.0.0.9.0.0.0.5.3.0.1.B.7.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 or 260090005301B7000000000000000001 format
			hex_string = raw_addr_string.replace('.', '')
			colon_hex_string = hex_string[0:4] + ':' + hex_string[4:8] + ':' + hex_string[8:12] + ':' + hex_string[12:16] + ':' + hex_string[16:20] + ':' + hex_string[20:24] + ':' + hex_string[24:28] + ':' + hex_string[28:32]
			try:
				ip_obj = ipaddress.ip_address(colon_hex_string)
			except ValueError:
				if Devel:
					Debug('IP Conversion problem with:')
					Debug(raw_addr_string)
					raise
				else:
					pass

	if ip_obj is not None:
		full_ip_string = ip_obj.exploded

	return full_ip_string


def generate_meta_from_packet(gmfp_pkt):
	"""Creates a dictionary of packet fields that may be needed by other layers."""

	#Default values.  Prefer '' to None so these can be used without having to use str() on everything.
	meta_dict = {'sMAC': '', 'dMAC': '', 'cast_type': '', 'ip_class': '', 'ttl': '', 'sIP': '', 'dIP': '', 'sport': '', 'dport': '', 'pkt_layers': []}

	meta_dict['pkt_layers'] = list(ReturnLayers(gmfp_pkt))

	if gmfp_pkt.haslayer(Ether) and isinstance(gmfp_pkt[Ether], Ether):
		meta_dict['sMAC'] = gmfp_pkt[Ether].src
		meta_dict['dMAC'] = gmfp_pkt[Ether].dst

		if meta_dict['dMAC'] == 'ff:ff:ff:ff:ff:ff':
			meta_dict['cast_type'] = 'broadcast'
		elif meta_dict['dMAC'].startswith(('01:00:5e:', '33:33:')) or meta_dict['dMAC'][1] in ('1', '3', '5', '7', '9', 'b', 'd', 'f'):	#https://tools.ietf.org/html/rfc7042 .  List of "odd" numbered nibbles are where the low order bit of byte 1 is set to 1.
			meta_dict['cast_type'] = 'multicast'
		#For non-broadcast/multicast, we don't put in the string 'unicast' as that's the default.  It also allows us to test
		#if meta_dict['cast_type']:  as a quick test for broadcast or multicast

	if gmfp_pkt.haslayer('TCP'):
		meta_dict['sport'] = str(gmfp_pkt['TCP'].sport)
		meta_dict['dport'] = str(gmfp_pkt['TCP'].dport)
	elif gmfp_pkt.haslayer('UDP'):
		meta_dict['sport'] = str(gmfp_pkt['UDP'].sport)
		meta_dict['dport'] = str(gmfp_pkt['UDP'].dport)

	if gmfp_pkt.haslayer('ARP'):
		meta_dict['sIP'] = gmfp_pkt['ARP'].psrc
		meta_dict['dIP'] = gmfp_pkt['ARP'].pdst
	elif gmfp_pkt.haslayer('IP'):
		meta_dict['ip_class'] = '4'
		meta_dict['ttl'] = gmfp_pkt['IP'].ttl
		meta_dict['sIP'] = gmfp_pkt['IP'].src
		meta_dict['dIP'] = gmfp_pkt['IP'].dst
	elif gmfp_pkt.haslayer('IPv6'):
		#FIXME - need to explode ips
		meta_dict['ip_class'] = '6'
		meta_dict['ttl'] = gmfp_pkt['IPv6'].hlim
		meta_dict['sIP'] = explode_ip(gmfp_pkt['IPv6'].src)
		meta_dict['dIP'] = explode_ip(gmfp_pkt['IPv6'].dst)
	#else:
	#	gmfp_pkt.show()
	#	quit()

	if gmfp_pkt.haslayer('IPerror'):
		meta_dict['OrigsIP'] = gmfp_pkt['IPerror'].src
		meta_dict['OrigdIP'] = gmfp_pkt['IPerror'].dst
	elif gmfp_pkt.haslayer('IPerror6'):
		meta_dict['OrigsIP'] = explode_ip(gmfp_pkt['IPerror6'].src)
		meta_dict['OrigdIP'] = explode_ip(gmfp_pkt['IPerror6'].dst)




	if meta_dict['dIP'] == '255.255.255.255':
		meta_dict['cast_type'] = 'broadcast'
	elif meta_dict['dIP'].startswith(('224.', '225.', '226.', '227.', '228.', '229.', '230.', '231.', '232.', '233.', '234.', '235.', '236.', '237.', '238.', '239.', 'ff')):
		meta_dict['cast_type'] = 'multicast'

	return meta_dict




#======== Extraction functions ========
#In the original (single process) passer script, these are called as:
#	ReportAll(ARP_extract(p, meta))
#In the new mutiprocess passer script, these are called by the handler script for that layer, such as:
#def ARP_handler(task_q, output_q):
#...
#	for statement in ARP_extract(p, meta):
#		output_q.put(statement)


def template_extract(p, meta):
	"""Pull all statements from the template layer and return as a set of tuples."""

	state_set = set([])

	#if p[template].op == 2:
	#	state_set.add(("MA", meta['sIP'], "Ethernet", p[template].hwsrc.upper(), "", ()))

	return state_set


def ARP_extract(p, meta):
	"""Pull all statements from the ARP layer and return as a set of tuples."""

	state_set = set([])

	if p[ARP].op == 2:		#"is-at"
		state_set.add(("MA", meta['sIP'], "Ethernet", p[ARP].hwsrc.upper(), "", ()))

	return state_set


def IP_extract(p, meta):
	"""Pull all statements from the IP layer and return as a set of tuples."""

	state_set = set([])

	#if p[IP].op == 2:
	#	state_set.add(("MA", meta['sIP'], "Ethernet", p[IP].hwsrc.upper(), "", ()))

	return state_set


def TCP_extract(p, meta):
	"""Pull all statements from the TCP layer and return as a set of tuples."""

	state_set = set([])

	if (p[TCP].flags & 0x17) == 0x12:	#SYN/ACK
		state_set.add(("TS", meta['sIP'], "TCP_" + meta['sport'], "listening", "", ()))

	return state_set


def UDP_extract(p, meta):
	"""Pull all statements from the UDP layer and return as a set of tuples."""

	sIP = meta['sIP']
	dport = meta['dport']

	if p.getlayer(Raw):
		Payload = p.getlayer(Raw).load
	else:
		Payload = ""


	state_set = set([])


### IP/UDP/SIP sipvicious scanner and other SIP clients.  https://www.nurango.ca/blog/sipvicious-the-not-so-friendly-scanner , http://www.hackingvoip.com/presentations/sample_chapter3_hacking_voip.pdf p54
#We used to look for 'User-Agent: friendly-scanner', but this is for sipvicious only.  'Via: SIP/2.0/UDP ' is more general.
# https://github.com/EnableSecurity/sipvicious
	if (dport in sip_altport) and Payload and Payload.startswith(('100@', '19179001661@', 'CANCEL sip:', 'INVITE sip:', 'OPTIONS sip:', 'REGISTER sip:')) and (Payload.find(': SIP/2.0/UDP ') > -1):		#Looking for 'Via: SIP/2.0/UDP ' or 'v: SIP/2.0/UDP'
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
			state_set.add(("UC", sIP, "UDP_" + dport, "open", base_description + additional_info, ('scan')))
		else:
			state_set.add(("UC", sIP, "UDP_" + dport, "open", base_description + additional_info, ('nonstandardport', 'scan')))
	#else:
	#	p.show()
	#	quit()

	#if p[UDP].op == 2:
	#	state_set.add(("MA", meta['sIP'], "Ethernet", p[UDP].hwsrc.upper(), "", ()))

	return state_set


