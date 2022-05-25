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
import string
import json
import tempfile		#Used in processing compressed files
import gzip		#Lets us read gzip compressed files
import bz2		#Lets us read bzip2 compressed files
import errno
from scapy.all import *			#Required for Scapy 2.0 and above
use_scapy_all = True

from db_lib import buffer_merges
from normalize_ip import ip_addr_obj


#======== Constants ========
KeepGoing = False		#Dont change this - it's an internal value to make the code more readable.  Change third param of ReportId instead.
HonorQuit = True		#Dont change this - it's an internal value to make the code more readable.  Change third param of ReportId instead.

#==== Ports ====

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
### IPv4/UDPv4/3283  net-assistant	https://en.wikipedia.org/wiki/Apple_Remote_Desktop and https://support.apple.com/en-us/HT202944
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
SecUDPPortNames = {"7": "echo", "13": "daytime", "17": "qotd", "19": "chargen", "179": "bgp", "192": "osu-nms", "445": "microsoft-ds", "465": "igmpv3lite", "513": "who", "623": "asf-rmcp_or_ipmi", "808": "omirr", "1080": "udpsocks", "1099": "rmiregistry", "1500": "udp1500", "1604": "darkcomet_rat_winframe_icabrowser", "3128": "udpsquid", "3283": "arms", "3386": "udp3386", "4738": "udp4738", "4800": "udp4800", "5006": "udp5006", "5008": "udp5008", "5093": "sentienl-lm", "5094": "hart-ip", "5354": "mdnsresponder", "5632": "pcanywherestat", "6000": "udp6000", "6969": "acmsoda", "6970": "rtsp", "8000": "udp8000", "8123": "udp8123", "8301": "udp8301", "8302": "udp8302", "9050": "udp9050", "9600": "udp9600", "9987": "teamspeak3-voice", "16464": "udp16464", "17185": "vxworks-debug", "20000": "udp20000", "24223": "udp24223", "27960": "udp27960", "30718": "lantronix", "32015": "udp32015", "32764": "udp32764", "32770": "udp32770", "34436": "udp34436", "35950": "udp35950", "44818": "rockwell-encap", "46414": "udp46414", "47808": "bacnet", "50023": "udp50023", "51413": "transmission", "53007": "udp53007", "55020": "udp55020", "63520": "udp63520", "64211": "udp64211"}

					#Some ports in PriUDPPortNames and SecUDPPortNames need warnings attached to them - list them and their warning here.
udp_port_warnings = {'13': 'small', '17': 'small', '1194': 'tunnel', '1701': 'tunnel', '1723': 'tunnel', '4500': 'tunnel', '8080': 'tunnel'}

udp_port_names = {"53": "dns", "5353": "mdns"}		#Always access this as     udp_port_names.get(port_number_string, "unknown_port_name")

				#UDP ports banned by policy.  May wish to do the entire range from 0 to 21 inclusive.
				#Perhaps add 161: snmp and solaris in.routed 520.
PolicyViolationUDPPorts = {'7': 'echo', '9': 'discard', '11': "sysstat", '13': 'daytime', '17': "qotd", '19': 'chargen', '69': 'tftp'}
				#TCP ports banned by policy.  May wish to do the entire range from 0 to 19 inclusive.
PolicyViolationTCPPorts = {'7': 'echo', '9': 'discard', '11': "sysstat", '13': 'daytime', '17': "qotd", '19': 'chargen', '23': 'telnet', '79': 'finger', "512": "rexec", "513": "rlogin", "514": "rsh_rcp", "623": "bmc"}

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


#======== Misc ========

config_dir = os.path.expanduser('~/.passer/')
cache_dir = os.path.expanduser('~/.cache/')

suspicious_ips_file = config_dir + '/suspicious_ips.json'
trusted_ips_file = config_dir + '/trusted_ips.json'

#Following are the root nameservers
default_trusted_ips = ['192.5.5.241', '192.33.4.12', '192.36.148.17', '192.58.128.30', '192.112.36.4', '192.203.230.10', '193.0.14.129', '198.41.0.4', '198.97.190.53', '199.7.83.42', '199.7.91.13', '199.9.14.201', '202.12.27.33', '2001:0dc3:0000:0000:0000:0000:0000:0035', '2001:07fd:0000:0000:0000:0000:0000:0001', '2001:07fe:0000:0000:0000:0000:0000:0053', '2001:0500:00a8:0000:0000:0000:0000:000e', '2001:0500:0001:0000:0000:0000:0000:0053', '2001:0500:002d:0000:0000:0000:0000:000d', '2001:0500:002f:0000:0000:0000:0000:000f', '2001:0500:0002:0000:0000:0000:0000:000c', '2001:0500:009f:0000:0000:0000:0000:0042', '2001:0500:0012:0000:0000:0000:0000:0d0d', '2001:0500:0200:0000:0000:0000:0000:000b', '2001:0503:0c27:0000:0000:0000:0002:0030', '2001:0503:ba3e:0000:0000:0000:0002:0030']

no_warn_name_tails = ('64-ptr.not.set.', '.adsl.', 'ptr-not-configured.cloudatcost.', '-bj-cnc.', '.ha.cnc.', 'domain.not.configured.', '.cto-go-a1k-01.', '.cust.', '.dedicated.', '.dhcp.', '.dsl.', '.fixed.', '.gnace701.', '.gnace702.', '.gnace703.', '.gnace704.', '.adsl-surfen.hetnet.', '.home.', '.hosted.', '.iplocal.', 'ipv6.', '.kdca.', '.lan.', 'localdomain.', 'localhost.', '.muc.', '.naspers.', '.nvi.', '.payu.', 'hosted.by.pcextreme.', '.cust.dsl.teletu.', '.cust.vodafonedsl.')

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
unamplified_any_domains = ('in-addr.arpa.', 'health.missouri.edu.', 'incidents.org.', 'ip6.arpa.', 'local.', 'm-net.arbornet.org.', 'm247.ro.', 'qrsparadigm.com.', 'rob.stearns.org.', 'sans.org.', 'stearns.org.', 'tourdesigns.com.', 'tourdesignsinc.com.')
unsure_any_domains = ('com.', 'domain.doesnt.exist.anywhereZZZZ')

min_closed_ports_for_scanner = 15	#If an IP gets RSTs or unreachables to at least this many unique IP/transport/port combinations, call it a scanner.
include_udp_errors_in_closed_ports = False	#If True, we look at unreachables and other ICMP errors for UDP ports in the "closed_ports" array; if False, we don't (and only count TCP RST's)



#======== Variables ========
passer_lib_version = '0.27'

#Indexes into the tuple used in passing data to the output handler.  _e is for "enumerated"
Type_e = 0
IPAddr_e = 1
Proto_e = 2
State_e = 3
Description_e = 4
Warnings_e = 5


#======== Support functions ========
def debug_out(debug_string, prefs, dests):
	"""Send debug into to stderr."""

	if prefs['devel']:
		if "warnings_sent" not in debug_out.__dict__:
			debug_out.warnings_sent = []

		if debug_string not in debug_out.warnings_sent:
			debug_out.warnings_sent.append(debug_string)
			sys.stderr.write(debug_string + '\n')


def force_string(raw_string):
	"""Make sure the returned object is a string."""

	retval = raw_string

	if sys.version_info > (3, 0):		#Python 3
		if isinstance(raw_string, bytes):
			retval = raw_string.decode("utf-8", 'replace')
		elif isinstance(raw_string, str):
			pass
		elif isinstance(raw_string, list):
			retval = ' '.join([force_string(listitem) for listitem in raw_string])
			#print(str(type(raw_string)))
			#print("huh:" + str(raw_string))
			#sys.exit()
		else:
			print(str(type(raw_string)))
			print("huh:" + str(raw_string))
			sys.exit()
			retval = str(raw_string)
	else:
		retval = str(raw_string)

	return retval

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


def mkdir_p(path):
	"""Create an entire directory branch.  Will not complain if the directory already exists."""

	if not os.path.isdir(path):
		try:
			os.makedirs(path)
		except OSError as exc:
			if exc.errno == errno.EEXIST and os.path.isdir(path):
				pass
			else:
				raise


def write_object(filename, generic_object):
	"""Write out an object to a file."""

	try:
		with open(filename, "wb") as write_h:
			write_h.write(generic_object.encode('utf-8'))
	except:
		sys.stderr.write("Problem writing " + filename + ", skipping.")
		raise

	return


def ReturnLayers(rl_p):
	"""Return the layers in this packet from outer to inner.  Sample use: list(ReturnLayers(p))"""
	#try:
	yield rl_p.name
	#except AttributeError:
	#	print('>>' + str(rl_p))
	while rl_p.payload:
		rl_p = rl_p.payload
		yield rl_p.name


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


def load_json_from_file(json_filename):
	"""Bring in json content from a file and return it as a python data structure (or None if not successful for any reason)."""

	ljff_return = None

	if os.path.exists(json_filename) and os.access(json_filename, os.R_OK):
		try:
			with open(json_filename) as json_h:
				ljff_return = json.loads(json_h.read())
		except:
			pass

	return ljff_return


def ShowPacket(orig_packet, meta_dict, banner_string, quit_override_preference, prefs, dests):
	"""In development mode, displays details about an unknown packet, and exits if quit_override_preference is True."""
	UnhandledPacket(orig_packet, prefs, dests)

	if prefs['devel'] is not False:
		if meta_dict:
			debug_out(str(meta_dict), prefs, dests)
		debug_out("======== " + str(banner_string), prefs, dests)
		try:
			debug_out(str(orig_packet.show(dump=True)), prefs, dests)
		except TypeError:					#On older versions of scapy (<= 2.2.0) TypeError: show() got an unexpected keyword argument 'dump'
			debug_out(str(orig_packet.show()), prefs, dests)
		ls(orig_packet)						#This one's still spitting to stdout, not sure how to redirect to stderr
		debug_out(str(orig_packet.answers), prefs, dests)
		debug_out("Packet type: " + str(type(orig_packet)), prefs, dests)
		if quit_override_preference and prefs['quit']:		#quit_override_preference is either KeepGoing == false or HonorQuit == True
			sys.exit()


def explode_ip(raw_addr, prefs, dests):
	"""Converts the input IP address string into its exploded form (type "unicode" in python2) ready for printing.  The raw_addr string should already have leading and trailing whitespace removed before being handed to this function.  If it's not a valid IP address, returns an empty string."""

	try:
		if sys.version_info > (3, 0):
			raw_addr_string = str(raw_addr)
		else:
			raw_addr_string = unicode(raw_addr)
	except UnicodeDecodeError:
		raw_addr_string = ''

		#if Devel:
		#	debug_out('Cannot convert:', prefs, dests)
		#	debug_out(raw_addr, prefs, dests)
		#	raise
		#else:
		#	pass

	full_ip_string = ''
	ip_obj = None

	if raw_addr_string and raw_addr_string.find('%') > -1:
		raw_addr_string = raw_addr_string.split('%')[0]			#Discard any "%en0...." after the IP address

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
				#debug_out('IP Conversion problem with:', prefs, dests)
				#debug_out(raw_addr_string, prefs, dests)
				pass

	if ip_obj is not None:
		full_ip_string = ip_obj.exploded

	return full_ip_string


def isFQDN(Hostname, prefs, dests):
	"""Boolean function: Checks to se if a hostname ends in a TLD.  Not a strict check, just some quick checks."""
	#https://en.wikipedia.org/wiki/List_of_Internet_top-level_domains
	#'..',
	if len(Hostname) < 5:		#Shortest I can think of is "h.uk.", technically a domain, but still a dns object
		#debug_out("Hostname " + Hostname + " too short, ignoring.", prefs, dests)
		return False
	elif not Hostname.endswith('.'):
		debug_out("Hostname " + Hostname + "doesn't end in '.', ignoring.", prefs, dests)
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
		#if not Hostname.endswith(no_warn_name_tails):
		#	debug_out("Hostname " + Hostname + " has invalid TLD, ignoring.", prefs, dests)
		return False


def generate_meta_from_packet(gmfp_pkt, prefs, dests):
	"""Creates a dictionary of packet fields that may be needed by other layers."""

	#Default values.  Prefer '' to None so these can be used without having to use str() on everything.
	meta_dict = {'sMAC': '', 'dMAC': '', 'cast_type': '', 'ip_class': '', 'ttl': '', 'sIP': '', 'dIP': '', 'sport': '', 'dport': '', 'SrcService': '', 'DstService': '', 'SrcClient': '', 'pkt_layers': [], 'flags': 0x0}

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
		meta_dict['sIP'] = explode_ip(gmfp_pkt['IPv6'].src, prefs, dests)
		meta_dict['dIP'] = explode_ip(gmfp_pkt['IPv6'].dst, prefs, dests)
	#else:
	#	gmfp_pkt.show()
	#	sys.exit()

	if gmfp_pkt.haslayer('TCP'):
		meta_dict['sport'] = str(gmfp_pkt['TCP'].sport)
		meta_dict['dport'] = str(gmfp_pkt['TCP'].dport)
		meta_dict['SrcService'] = meta_dict['sIP'] + ",TCP_" + meta_dict['sport']
		meta_dict['DstService'] = meta_dict['dIP'] + ",TCP_" + meta_dict['dport']
		meta_dict['SrcClient'] = meta_dict['sIP'] + ",TCP_" + meta_dict['dport']
		meta_dict['flags'] = gmfp_pkt['TCP'].flags
	elif gmfp_pkt.haslayer('UDP'):
		meta_dict['sport'] = str(gmfp_pkt['UDP'].sport)
		meta_dict['dport'] = str(gmfp_pkt['UDP'].dport)
		meta_dict['SrcService'] = meta_dict['sIP'] + ",UDP_" + meta_dict['sport']
		meta_dict['DstService'] = meta_dict['dIP'] + ",UDP_" + meta_dict['dport']
		meta_dict['SrcClient'] = meta_dict['sIP'] + ",UDP_" + meta_dict['dport']
		#udp_layer = gmfp_pkt.getlayer(UDP)
	elif gmfp_pkt.haslayer('TCPerror'):
		meta_dict['sport'] = str(gmfp_pkt['TCPerror'].sport)
		meta_dict['dport'] = str(gmfp_pkt['TCPerror'].dport)
		meta_dict['SrcService'] = meta_dict['sIP'] + ",TCP_" + meta_dict['sport']
		meta_dict['DstService'] = meta_dict['dIP'] + ",TCP_" + meta_dict['dport']
		meta_dict['SrcClient'] = meta_dict['sIP'] + ",TCP_" + meta_dict['dport']
		meta_dict['flags'] = gmfp_pkt['TCPerror'].flags
	elif gmfp_pkt.haslayer('UDPerror'):
		meta_dict['sport'] = str(gmfp_pkt['UDPerror'].sport)
		meta_dict['dport'] = str(gmfp_pkt['UDPerror'].dport)
		meta_dict['SrcService'] = meta_dict['sIP'] + ",UDP_" + meta_dict['sport']
		meta_dict['DstService'] = meta_dict['dIP'] + ",UDP_" + meta_dict['dport']
		meta_dict['SrcClient'] = meta_dict['sIP'] + ",UDP_" + meta_dict['dport']

	if gmfp_pkt.haslayer('IPerror'):
		meta_dict['OrigsIP'] = gmfp_pkt['IPerror'].src
		meta_dict['OrigdIP'] = gmfp_pkt['IPerror'].dst
	elif gmfp_pkt.haslayer('IPerror6'):
		meta_dict['OrigsIP'] = explode_ip(gmfp_pkt['IPerror6'].src, prefs, dests)
		meta_dict['OrigdIP'] = explode_ip(gmfp_pkt['IPerror6'].dst, prefs, dests)




	if meta_dict['dIP'] == '255.255.255.255':
		meta_dict['cast_type'] = 'broadcast'
	elif meta_dict['dIP'].startswith(('224.', '225.', '226.', '227.', '228.', '229.', '230.', '231.', '232.', '233.', '234.', '235.', '236.', '237.', '238.', '239.', 'ff')):
		meta_dict['cast_type'] = 'multicast'

	return meta_dict


def MacDataDict(MacFiles, prefs, dests):
	"""Load Ethernet Mac address prefixes from standard locations (from ettercap, nmap, wireshark, and/or arp-scan)."""

	tmp_manuf_dict = {}

	LoadCount = 0

	for MacFile in MacFiles:
		if os.path.isfile(MacFile):
			try:
				MacHandle = open(MacFile, 'r', errors='ignore')

				for line in MacHandle:
					if (len(line) >= 8) and (line[2] == ':') and (line[5] == ':'):
						#uppercase incoming strings just in case one of the files uses lowercase
						MacHeader = line[:8].upper()
						Manuf = line[8:].strip()
						if MacHeader not in tmp_manuf_dict:
							tmp_manuf_dict[MacHeader] = Manuf
							LoadCount += 1
					elif (len(line) >= 7) and (re.search('^[0-9A-F]{6}[ \t]', line) is not None):
						MacHeader = str.upper(line[0:2] + ':' + line[2:4] + ':' + line[4:6])
						Manuf = line[7:].strip()
						if MacHeader not in tmp_manuf_dict:
							tmp_manuf_dict[MacHeader] = Manuf
							LoadCount += 1

				MacHandle.close()
				if '00:00:00' in tmp_manuf_dict:
					del tmp_manuf_dict['00:00:00']		#Not really Xerox
					LoadCount -= 1
			except:
				debug_out("Unable to load " + str(MacFile), prefs, dests)
		#Silently ignore if it isn't there
		#else:
		#	debug_out("Unable to load " + str(MacFile), prefs, dests)

	debug_out(str(LoadCount) + " mac prefixes loaded.", prefs, dests)

	return tmp_manuf_dict


def NmapServiceFPDict(ServiceFileNames, prefs, dests):
	"""Load nmap fingerprints from nmap-service-probes, usually in /usr/share/nmap."""

	#File format details at http://nmap.org/vscan/vscan-fileformat.html

	tmp_fp_dict = {}

	LoadCount = 0
	CompileSuccess = 0
	CompileFail = 0
	PortArray = []

	for ServiceFileName in ServiceFileNames:
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
						#debug_out("==== " + Remainder[MatchEnd+1:MatchEnd+4], prefs, dests)
						if MatchEnd + 1 == len(Remainder):
							InformationPresent = False
							#debug_out("No information data for " + MatchString, prefs, dests)
						elif Remainder[MatchEnd+1:MatchEnd+2] == " ":
							PPointer = MatchEnd + 2
							MatchFlags = re.M
							#debug_out(Remainder + ", no flags", prefs, dests)
						elif Remainder[MatchEnd+1:MatchEnd+3] == "i ":
							PPointer = MatchEnd + 3
							MatchFlags = re.M | re.I
							#debug_out(Remainder + ", i flag", prefs, dests)
						elif Remainder[MatchEnd+1:MatchEnd+3] == "s ":
							PPointer = MatchEnd + 3
							MatchFlags = re.M | re.S
							#debug_out(Remainder + ", s flag", prefs, dests)
						elif (Remainder[MatchEnd+1:MatchEnd+4] == "is ") or (Remainder[MatchEnd+1:MatchEnd+4] == "si "):
							PPointer = MatchEnd + 4
							MatchFlags = re.M | re.I | re.S
							#debug_out(Remainder + ", i and s flag", prefs, dests)
						#Following lines commented out as they're only needed for development
						#else:
						#	debug_out("Unrecognized nmap-service-probes flag combination", prefs, dests)
						#	debug_out(str(MatchEnd + 1) + " " + str(len(Remainder)), prefs, dests)
						#	debug_out(Remainder + ", unknown flags", prefs, dests)
						#	#sys.exit()

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
								#We try to compile the MatchString now before inserting into tmp_fp_dict so the work only needs to be
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
									if 'all' not in tmp_fp_dict:
										tmp_fp_dict['all'] = []
									tmp_fp_dict['all'].append(SearchTuple)
									LoadCount += 1
								else:
									#Register this search pair for every port requested
									for OnePort in PortArray:
										if int(OnePort) not in tmp_fp_dict:
											tmp_fp_dict[int(OnePort)] = []
										tmp_fp_dict[int(OnePort)].append(SearchTuple)
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
					debug_out(str(CompileSuccess) + " nmap service signatures successfully loaded.", prefs, dests)
				else:
					debug_out(str(CompileSuccess) + " nmap service signatures successfully loaded, unable to parse " + str(CompileFail) + " others.", prefs, dests)
			except:
				debug_out("Failed to load " + ServiceFileName, prefs, dests)
		#No "else:" here as we don't warn on a specific missing source file.  Calling routine complains if none could be loaded.

	return tmp_fp_dict


#======== IO functions ========


def SuspiciousPacket(sp_packet, prefs, dests):
	"""Save packets that have not been (completely) processed out to a pcap file for later analysis."""
	#Note we have to handle where dests['suspicious'] will be:
	#- None, do nothing
	#- a string (orig passer filename), so use existing persistent handle or create a new persistent handle and write to it.
	#- a queue (passer_ng queue), so write to that queue and let the suspicious_handler take care of it.

	if dests['suspicious'] is None:
		pass
	elif type(dests['suspicious']) is str:
		if "suspicious_h" not in SuspiciousPacket.__dict__:
			SuspiciousPacket.suspicious_h = None
			if dests['suspicious']:
				try:
					SuspiciousPacket.suspicious_h = PcapWriter(filename=dests['suspicious'], append=True)
				except:
					debug_out("Unable to open " + dests['suspicious'] + ", no suspicious packets will be saved.", prefs, dests)

		if SuspiciousPacket.suspicious_h is not None:
			SuspiciousPacket.suspicious_h.write(sp_packet)
	else:								#More strictly, elif type(dests['suspicious']) is multiprocessing.queues.Queue:   , but we're not sure if that module has been imported.
		dests['suspicious'].put(sp_packet)


def UnhandledPacket(up_packet, prefs, dests):
	"""Save packets that have not been (completely) processed out to a pcap file for later analysis."""
	#Note we have to handle where dests['unhandled'] will be:
	#- None, do nothing
	#- a string (orig passer filename), so use existing persistent handle or create a new persistent handle and write to it.
	#- a queue (passer_ng queue), so write to that queue and let the unhandled_handler take care of it.

	if dests['unhandled'] is None:
		pass
	elif type(dests['unhandled']) is str:
		if "unhandled_h" not in UnhandledPacket.__dict__:
			UnhandledPacket.unhandled_h = None
			if dests['unhandled']:
				try:
					UnhandledPacket.unhandled_h = PcapWriter(filename=dests['unhandled'], append=True)
				except:
					debug_out("Unable to open " + dests['unhandled'] + ", no unhandled packets will be saved.", prefs, dests)

		if UnhandledPacket.unhandled_h is not None:
			UnhandledPacket.unhandled_h.write(up_packet)
	else:								#More strictly, elif type(dests['unhandled']) is multiprocessing.queues.Queue:   , but we're not sure if that module has been imported.
		dests['unhandled'].put(up_packet)


def save_to_db(out_rec, prefs, dests):
	"""Take the fields in an output record tuple/list into the appropriate sqlite database."""

	max_adds = 50

	hostname_ips = prefs['db_dir'] + 'hostname_ips.sqlite3'		#Note; the databases are created automatically
	ip_asns = prefs['db_dir'] + 'ip_asns.sqlite3'
	ip_client_ports = prefs['db_dir'] + 'ip_client_ports.sqlite3'
	ip_client_protocols = prefs['db_dir'] + 'ip_client_protocols.sqlite3'
	ip_closed_servers = prefs['db_dir'] + 'ip_closed_servers.sqlite3'
	ip_flags = prefs['db_dir'] + 'ip_flags.sqlite3'
	ip_hostnames = prefs['db_dir'] + 'ip_hostnames.sqlite3'
	ip_locations = prefs['db_dir'] + 'ip_locations.sqlite3'
	ip_macaddrs = prefs['db_dir'] + 'ip_macaddrs.sqlite3'
	ip_mx_for = prefs['db_dir'] + 'ip_mx_for.sqlite3'
	ip_names = prefs['db_dir'] + 'ip_names.sqlite3'
	ip_ns_for = prefs['db_dir'] + 'ip_ns_for.sqlite3'
	ip_open_servers = prefs['db_dir'] + 'ip_open_servers.sqlite3'
	ip_peers = prefs['db_dir'] + 'ip_peers.sqlite3'
	ip_rhostnames = prefs['db_dir'] + 'ip_rhostnames.sqlite3'

	report_closed_server_ports = True

	clean_ip_obj = ip_addr_obj(out_rec[IPAddr_e])
	if clean_ip_obj is None:
		return
	clean_ip = explode_ip(clean_ip_obj, prefs, dests)


	if prefs['db_dir']:
		if out_rec[Type_e] == "DN":
			if out_rec[Proto_e] in ('A', 'AAAA', 'CNAME', 'SRV'):
				if clean_ip != '0.0.0.0':
					if out_rec[Description_e]:
						service_string = out_rec[State_e].rstrip('.') + ';' + out_rec[Description_e]
					else:
						service_string = out_rec[State_e].rstrip('.')
					buffer_merges(ip_hostnames, clean_ip, [service_string,], max_adds)
					buffer_merges(hostname_ips, out_rec[State_e].rstrip('.'), [clean_ip,], max_adds)
			elif out_rec[Proto_e] in ('PTR'):
				if clean_ip != '0.0.0.0':
					if out_rec[Description_e]:
						service_string = out_rec[State_e].rstrip('.') + ';' + out_rec[Description_e]
					else:
						service_string = out_rec[State_e].rstrip('.')
					buffer_merges(ip_rhostnames, clean_ip, [service_string,], max_adds)
					buffer_merges(hostname_ips, out_rec[State_e].rstrip('.'), [clean_ip,], max_adds)
			elif out_rec[Proto_e] == 'NS':
				domain = out_rec[State_e].rstrip('.')
				#nameserver = out_rec[Description_e].rstrip('.')
				buffer_merges(ip_ns_for, clean_ip, [domain,], max_adds)
			elif out_rec[Proto_e] == 'MX':
				domain = out_rec[State_e].rstrip('.')
				#mailserver = out_rec[Description_e].rstrip('.')
				buffer_merges(ip_mx_for, clean_ip, [domain,], max_adds)
			elif out_rec[IPAddr_e] == '0.0.0.0' and out_rec[Proto_e] == 'SOA':
				domain = out_rec[State_e].rstrip('.')
				soa_fields = out_rec[Description_e].split(' ')
				#one_dns = soa_fields[0]	#This is a nameserver _hostname_; would need manual conversion to an IP to store in ns_for.
				#email_addr = soa_fields[1].replace('.', '@', 1)
			elif out_rec[IPAddr_e] == '0.0.0.0' and out_rec[Proto_e] == 'TXT':
				pass
		#elif out_rec[Type_e] == "DO":
		#	if out_rec[IPAddr_e] == '0.0.0.0' and out_rec[Proto_e] == 'reputation':
		#		domain = out_rec[State_e].rstrip('.')
		#		rep_string = out_rec[Description_e]
		#		if rep_string:
		elif out_rec[Type_e] == "NA":
			if out_rec[Proto_e] in ('PTR', 'DHCP'):
				if out_rec[Description_e]:
					service_string = out_rec[State_e] + ';' + out_rec[Description_e]
				else:
					service_string = out_rec[State_e]
				buffer_merges(ip_names, clean_ip, [service_string,], max_adds)		#Only forward at the moment
			elif out_rec[Proto_e] in ('RP'):
				#NA,0.0.0.0,RP,www.ktvc8.com.,dnsproxy.oray.com.
				pass
		#elif out_rec[Type_e] == "IP" and out_rec[Proto_e] in ("IP", "service_banner"):
		#	if out_rec[Description_e] and out_rec[Description_e] != 'p0f failure':
		#		service_string = out_rec[State_e] + ';' + out_rec[Description_e]
		#	else:
		#		service_string = out_rec[State_e]
		elif out_rec[Type_e] == "PE" and out_rec[Proto_e] == "traceroute" and out_rec[State_e] in ('is_beyond', 'precedes'):
			peer_ip_obj = ip_addr_obj(out_rec[Description_e])
			if peer_ip_obj is None:
				return
			peer_ip = explode_ip(peer_ip_obj, prefs, dests)

			buffer_merges(ip_peers, clean_ip, [peer_ip,], max_adds)
			buffer_merges(ip_peers, peer_ip, [clean_ip,], max_adds)
		elif out_rec[Type_e] in ("US", "UD"):
			if out_rec[State_e] in ('open', 'listening'):
				if out_rec[Description_e]:
					service_string = out_rec[Proto_e] + ';' + out_rec[Description_e]
				else:
					service_string = out_rec[Proto_e]
				buffer_merges(ip_open_servers, clean_ip, [service_string,], max_adds)
			elif out_rec[State_e] == 'closed':
				if report_closed_server_ports:
					buffer_merges(ip_closed_servers, clean_ip, [out_rec[Proto_e],], max_adds)
		elif out_rec[Type_e] == "UC":
			if out_rec[State_e] == 'open':
				if out_rec[Description_e]:
					service_string = out_rec[Proto_e] + ';' + out_rec[Description_e]
				else:
					service_string = out_rec[Proto_e]
				buffer_merges(ip_client_ports, clean_ip, [service_string,], max_adds)
		elif out_rec[Type_e] == "TS":
			if out_rec[State_e] == 'listening':
				if out_rec[Description_e]:
					service_string = out_rec[Proto_e] + ';' + out_rec[Description_e]
				else:
					service_string = out_rec[Proto_e]
				buffer_merges(ip_open_servers, clean_ip, [service_string,], max_adds)
			elif out_rec[State_e] == 'closed':
				if report_closed_server_ports:
					buffer_merges(ip_closed_servers, clean_ip, [out_rec[Proto_e],], max_adds)
			#elif out_rec[State_e] == 'unknown':
			#	if out_rec[Description_e]:
			#		service_string = out_rec[Description_e]
		elif out_rec[Type_e] == "TC":
			if out_rec[State_e] == 'open':
				if out_rec[Description_e]:
					service_string = out_rec[Proto_e] + ';' + out_rec[Description_e]
				else:
					service_string = out_rec[Proto_e]
				buffer_merges(ip_client_ports, clean_ip, [service_string,], max_adds)
		elif out_rec[Type_e] == "RO":
			if out_rec[State_e] == 'router':
				buffer_merges(ip_flags, clean_ip, ['router',], max_adds)
		elif out_rec[Type_e] == "MA":
			if out_rec[Proto_e] == 'Ethernet':
				if out_rec[Description_e]:
					service_string = out_rec[State_e] + ';' + out_rec[Description_e]
				else:
					service_string = out_rec[State_e]
				buffer_merges(ip_macaddrs, clean_ip, [service_string,], max_adds)
		elif out_rec[Type_e] == "GE":
			if out_rec[Proto_e] in ("CC", "COUNTRY", "CSC"):
				#GE,10.0.0.0,CC,NU,
				if out_rec[Description_e]:
					service_string = out_rec[State_e] + ';' + out_rec[Description_e]
				else:
					service_string = out_rec[State_e]
				buffer_merges(ip_locations, clean_ip, [service_string,], max_adds)
		elif out_rec[Type_e] == "AS":
			if out_rec[Proto_e] in ("AS"):
				#AS,128.223.60.22,AS,3582,UONET - University of Oregon
				if out_rec[Description_e]:
					service_string = out_rec[State_e] + ';' + out_rec[Description_e]
				else:
					service_string = out_rec[State_e]
				buffer_merges(ip_asns, clean_ip, [service_string,], max_adds)
		elif out_rec[Type_e] == "PC":
			if out_rec[State_e] == 'open':
				if out_rec[Description_e]:
					service_string = out_rec[Proto_e] + ';' + out_rec[Description_e]
				else:
					service_string = out_rec[Proto_e]
				buffer_merges(ip_client_protocols, clean_ip, [service_string,], max_adds)
		elif out_rec[Type_e] in ("NB", "NE"):
			pass





#======== Extraction functions ========
#In the original (single process) passer script, these are called as:
#	ReportAll(ARP_extract(p, meta, prefs, dests))
#In the new mutiprocess passer script, these are called by the handler script for that layer, such as:
#def ARP_handler(task_q, output_q):
#...
#	for statement in ARP_extract(p, meta, prefs, dests):
#		output_q.put(statement)


def template_extract(p, meta, prefs, dests):
	"""Pull all statements from the template layer and return as a set of tuples."""

	state_set = set([])

	#if p[template].op == 2:
	#	state_set.add(("MA", meta['sIP'], "Ethernet", p[template].hwsrc.upper(), "", ()))

	return state_set


def ARP_extract(p, meta, prefs, dests):
	"""Pull all statements from the ARP layer and return as a set of tuples."""

	state_set = set([])

	if p[ARP].op == 2:		#"is-at"
		state_set.add(("MA", meta['sIP'], "Ethernet", p[ARP].hwsrc.upper(), "", ()))

	return state_set


def ICMP_extract(p, meta, prefs, dests):
	"""Pull all statements from the ICMP layer and return as a set of tuples."""

	state_set = set([])

	I_Type = p[ICMP].type
	I_Code = p[ICMP].code

	if I_Type in (3, 11, ):		#3=Unreachable, 11=Time exceeded.  All have embedded packets that may need attention
		pass
	#elif I_Type in ():
	#else:
	#	p.show()
	#	sys.exit(86)

	#if p[template].op == 2:
	#	state_set.add(("MA", meta['sIP'], "Ethernet", p[template].hwsrc.upper(), "", ()))

	return state_set


def IP_extract(p, meta, prefs, dests):
	"""Pull all statements from the IP layer and return as a set of tuples."""

	sIP = meta['sIP']

	if "OSDescription" not in IP_extract.__dict__:
		IP_extract.OSDescription = {}		#Dictionary of strings.  Key is the expanded IP address, value is the OS of this system.

	state_set = set([])

	#if p[IP].op == 2:
	#	state_set.add(("MA", meta['sIP'], "Ethernet", p[IP].hwsrc.upper(), "", ()))

	##We have to handle passive OS fingerprinting here because the p0f module needs a complete IP packet, not just the TCP layer.
	#if 'TCP' in meta['pkt_layers'] and (meta['flags'] & 0x17) == 0x02:
	#	#debug_out("trying to fingerprint " + sIP + "/" + str(type(p)), prefs, dests)

	#	if sIP not in IP_extract.OSDescription:
	#		try:
	#			p0fdata = p0f(p)
	#			#FIXME - reasonably common occurence, don't whine, just fix it.
	#			#if (len(p0fdata) >1):
	#			#	debug_out("More than one OS fingerprint for " + sIP + ", using the first.", prefs, dests)
	#			if (len(p0fdata) >=1):
	#				PDescription = p0fdata[0][0] + " " + p0fdata[0][1] + " (" + str(int(p0fdata[0][2]) + 1)	#FIXME - Grabbing just the first candidate, may need to compare correlation values; provided?
	#				if (p0fdata[0][2] == 0):
	#					PDescription = PDescription + " hop away)"
	#				else:
	#					PDescription = PDescription + " hops away)"
	#											#[N][2] param appears to be distance away in hops (but add 1 to this to get real hop count?)
	#				PDescription = PDescription.replace(',', ';')		#Commas are delimiters in output
	#				state_set.add(("IP", sIP, "IP", "live", PDescription, ()))
	#				IP_extract.OSDescription[sIP] = PDescription
	#		except KeyError:
	#			pass
	#		#except:
	#		#	PDescription = 'p0f failure'
	#		#	debug_out("P0f failure in " + sIP + ":" + sport + " -> " + dIP + ":" + dport, prefs, dests)
	#		#	state_set.add(("IP", sIP, "IP", "live", PDescription, ()))


	return state_set


def TCP_extract(p, meta, prefs, dests):
	"""Pull all statements from the TCP layer and return as a set of tuples."""

	#Persistent variables
	if "ServiceFPs" not in TCP_extract.__dict__:
		TCP_extract.ServiceFPs = {}
				#Dictionary of service fingerprints.  Keys are straight int port numbers (no TCP or UDP), or 'all' for strings that need
				#to be matched against all ports.  These are loaded from nmap's "nmap-service-probes", ignoring the probes since we're passive.
				#Values are lists of tuples, ala: [("Apache *server ready.", "Apache web"), ("VSFTPD FTP at your service", "vsftpd ftp")]
				#Note that the first object in a tuple is a _compiled regex_ rather than the printable strings I've used above.
				#A sample (non-compiled) version looks like:  {80: [('^Server: Apache/', 'http/apachewebserver')]}

		TCP_extract.ServiceFPs = NmapServiceFPDict(['/usr/local/share/nmap/nmap-service-probes', '/usr/share/nmap/nmap-service-probes', '/opt/local/share/nmap/nmap-service-probes'], prefs, dests)
		if len(TCP_extract.ServiceFPs) == 0:
			debug_out("Can't locate /{usr,opt}/{local/,}share/nmap/nmap-service-probes.  Please install nmap to support more server descriptions.", prefs, dests)
		else:
			debug_out("Fingerprints for " + str(len(TCP_extract.ServiceFPs)) + " ports loaded.", prefs, dests)

	#Next two are used to discover clients.  If we've seen a SYN/ACK going to what appears to be a client port, and it
	#later responds with a FIN, we'll call that a live TCP client.
	if "SynSentToTCPService" not in TCP_extract.__dict__:
		TCP_extract.SynSentToTCPService = {}	#Boolean dictionary: Have we seen a syn sent to this "IP,Proto_Port" pair yet?

	if "SynAckSentToTCPClient" not in TCP_extract.__dict__:
		TCP_extract.SynAckSentToTCPClient = {}	#Boolean dictionary: Have we seen a SYN/ACK sent to this "IP,Proto_Port" pair yet?

	if "LiveTCPClient" not in TCP_extract.__dict__:
		TCP_extract.LiveTCPClient = {}		#Boolean dictionary: Have we seen a FIN from this client, indicating a 3 way handshake and successful conversation?

	if "LiveTCPService" not in TCP_extract.__dict__:
		TCP_extract.LiveTCPService = {}		#Boolean dictionary: Have we seen a SYN/ACK come back (true) or a RST (False) from this "IP,Proto_Port" pair?

	if "NmapServerDescription" not in TCP_extract.__dict__:
		TCP_extract.NmapServerDescription = {}	#String dictionary: What server is this "IP,Proto_Port" pair?  These descriptions come from nmap-service-probes.

	#String dictionary: What server is on this "IP,Proto_Port"?  Locally found strings.
	if "TCPManualServerDescription" not in TCP_extract.__dict__:
		TCP_extract.TCPManualServerDescription = {}

	#String dictionary: What client is on this "IP,Proto_Port"?  NOTE: the port here is the _server_ port at the other end.  So if
	#Firefox on 1.2.3.4 is making outbound connections to port 80 on remote servers, TCP_extract.ClientDescription['1.2.3.4,TCP_80'] = "http/firefox"
	if "ClientDescription" not in TCP_extract.__dict__:
		TCP_extract.ClientDescription = {}

	if "ClosedTCPPortsReceived" not in TCP_extract.__dict__:
		TCP_extract.ClosedTCPPortsReceived = {}	#Dictionary of sets.  Key is expanded IP address, value is a set of "IP,Proto_Port" strings that sent back "closed".  High counts of these are systems that are scanning for ports.

	#Transitional variables
	sIP = meta['sIP']
	dIP = meta['dIP']
	dport = meta['dport']
	sport = meta['sport']

	if p.getlayer(Raw):
		Payload = force_string(p.getlayer(Raw).load)
	else:
		Payload = ""


	state_set = set([])

	if (sIP == dIP) and (sport == dport) and sIP not in ("127.0.0.1", "::1", "0000:0000:0000:0000:0000:0000:0000:0001"):
		state_set.add(("TS", sIP, "TCP_" + sport, "attack", 'land attack IP address spoofed', ('malicious', 'spoofed')))

	#print meta['sIP'] + ":" + meta['sport'] + " -> ", meta['dIP'] + ":" + meta['dport'],
	if (meta['flags'] & 0x17) == 0x12:	#SYN/ACK (RST and FIN off)
		CliService = dIP + ",TCP_" + sport
		if CliService not in TCP_extract.SynAckSentToTCPClient:
			TCP_extract.SynAckSentToTCPClient[CliService] = True

		#If we've seen a syn sent to this port and have either not seen any SA/R, or we've seen a R in the past:
		#The last test is for a service that was previously closed and is now open; report each transition once.
		Service = sIP + ",TCP_" + sport
		if Service in TCP_extract.SynSentToTCPService and ((Service not in TCP_extract.LiveTCPService) or (not TCP_extract.LiveTCPService[Service])):
			TCP_extract.LiveTCPService[Service] = True
			if sport in PolicyViolationTCPPorts:
				state_set.add(("TS", sIP, "TCP_" + sport, "listening", '', ('portpolicyviolation',)))
			else:
				state_set.add(("TS", sIP, "TCP_" + sport, "listening", '', ()))
	elif (meta['flags'] & 0x17) == 0x02:	#SYN (ACK, RST, and FIN off)
		Service = dIP + ",TCP_" + dport
		if Service not in TCP_extract.SynSentToTCPService:
			TCP_extract.SynSentToTCPService[Service] = True

		if dport in PolicyViolationTCPPorts:
			state_set.add(("TC", sIP, "TCP_" + dport, "open", '', ('portpolicyviolation',)))
		else:
			state_set.add(("TC", sIP, "TCP_" + dport, "open", '', ()))

	elif (meta['flags'] & 0x07) == 0x01:	#FIN (SYN/RST off)
		#FIXME - check this logic.  Also, should we handle fin in both directions with two if blocks?
		CliService = sIP + ",TCP_" + dport
		if CliService in TCP_extract.SynAckSentToTCPClient and ((CliService not in TCP_extract.LiveTCPClient) or (not TCP_extract.LiveTCPClient[CliService])):
			TCP_extract.LiveTCPClient[CliService] = True
			state_set.add(("TC", sIP, "TCP_" + dport, "open", '', ()))
	elif (meta['flags'] & 0x07) == 0x04:	#RST (SYN and FIN off, ignore ACK)
		#FIXME - handle rst going in the other direction?
		Service = sIP + ",TCP_" + sport
		if Service in TCP_extract.SynSentToTCPService and ((Service not in TCP_extract.LiveTCPService) or TCP_extract.LiveTCPService[Service]):
			TCP_extract.LiveTCPService[Service] = False
			state_set.add(("TS", sIP, "TCP_" + sport, "closed", '', ()))

		if Service in TCP_extract.SynSentToTCPService:
			#Prober is dIP.  Probed port is Service (= sIP + ",TCP_" + sport)
			if dIP not in TCP_extract.ClosedTCPPortsReceived:
				TCP_extract.ClosedTCPPortsReceived[dIP] = set()
			TCP_extract.ClosedTCPPortsReceived[dIP].add(Service)
			if len(TCP_extract.ClosedTCPPortsReceived[dIP]) >= min_closed_ports_for_scanner:
				state_set.add(("IP", dIP, "IP", "suspicious", 'Scanned TCP closed ports.', ('scan', )))
	elif ((meta['flags'] & 0x3F) == 0x15) and (sport == "113"):	#FIN, RST, ACK (SYN, PSH, URG off)
		#This may be a firewall or some other device stepping in for 113 with a FIN/RST.
		pass
	elif (meta['flags'] & 0x17) == 0x10:	#ACK (RST, SYN, and FIN off)
		#FIXME - check for UnhandledPacket placement in ACK
		FromPort = sIP + ",TCP_" + sport
		ToPort = dIP + ",TCP_" + dport

		if FromPort in TCP_extract.LiveTCPService and TCP_extract.LiveTCPService[FromPort] and (ToPort in TCP_extract.LiveTCPService) and TCP_extract.LiveTCPService[ToPort]:
			ShowPacket(p, meta, "IPv4/TCPv4/ACK (RST, SYN, FIN off) Logic failure: both " + FromPort + " and " + ToPort + " are listed as live services.", HonorQuit, prefs, dests)
		elif FromPort in TCP_extract.LiveTCPService and TCP_extract.LiveTCPService[FromPort]:			#If the "From" side is a known TCP server:
			if FromPort not in TCP_extract.NmapServerDescription:				#Check nmap fingerprint strings for this server port
				if int(sport) in TCP_extract.ServiceFPs:
					for OneTuple in TCP_extract.ServiceFPs[int(sport)]:
						MatchObj = OneTuple[0].search(Payload)
						if MatchObj is not None:
							#Debugging:
							#FIXME - removeme once understood:
							#File "/home/wstearns/med/programming/python/passer/passer.py", line 504, in processpacket
							#OutputDescription = OutputDescription.replace('$' + str(Index), MatchObj.group(Index))
							#TypeError: expected a character buffer object
							if OneTuple[1] is None:
								debug_out("Null description for " + OneTuple[0], prefs, dests)
								#sys.exit()
							OutputDescription = OneTuple[1]
							if len(MatchObj.groups()) >= 1:
								#We have subexpressions matched, these need to be inserted into the description string
								for Index in range(1, len(MatchObj.groups())+1):
									#Example: Replace "$1" with MatchObj.group(1)
									OutputDescription = OutputDescription.replace('$' + str(Index), str(MatchObj.group(Index)))
							state_set.add(("TS", sIP, "TCP_" + sport, "listening", OutputDescription, ()))
							TCP_extract.NmapServerDescription[FromPort] = OutputDescription
							break					#Exit for loop, no need to check any more fingerprints now that we've found a match

			if FromPort not in TCP_extract.NmapServerDescription:			#If the above loop didn't find a server description
				if 'all' in TCP_extract.ServiceFPs:					#Now recheck against regexes not associated with a specific port (port 'all').
					for OneTuple in TCP_extract.ServiceFPs['all']:
						MatchObj = OneTuple[0].search(Payload)
						if MatchObj is not None:
							OutputDescription = OneTuple[1]
							if len(MatchObj.groups()) >= 1:
								#We have subexpressions matched, these need to be inserted into the description string
								for Index in range(1, len(MatchObj.groups())+1):
									OutputDescription = OutputDescription.replace('$' + str(Index), MatchObj.group(Index))
							state_set.add(("TS", sIP, "TCP_" + sport, "listening", OutputDescription, ()))
							TCP_extract.NmapServerDescription[FromPort] = OutputDescription
							break

			#FIXME - should add:
			#if FromPort not in TCP_extract.NmapServerDescription:			#If neither of the above loops found a server description
			if sport in ("22", "25", "80", "110", "143", "783", "3128") and FromPort not in TCP_extract.TCPManualServerDescription and Payload:
				#WARNING: update port list above if any new ports are added.
				if (sport == "22") and Payload.startswith('SSH-'):
					if Payload.startswith('SSH-1.99-OpenSSH_') or Payload.startswith('SSH-2.0-OpenSSH_'):
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "ssh/openssh", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "ssh/openssh"
					#elif Payload.startswith('SSH-1.5-'):
					else:
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "ssh/generic", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "ssh/generic"
						#LogNewPayload(ServerPayloadDir, FromPort, Payload)
					#Note: with the port restriction above, this block will never execute.  Remove port restriction if you want to use this.
					#else:
					#	if SaveUnhandledAcks:
					#		UnhandledPacket(p, prefs, dests)
					#		#LogNewPayload(ServerPayloadDir, FromPort, Payload)
				elif (sport == "25") and (Payload.find(' ESMTP Sendmail ') > -1):
					state_set.add(("TS", sIP, "TCP_" + sport, "listening", "smtp/sendmail", ()))
					TCP_extract.TCPManualServerDescription[FromPort] = "smtp/sendmail"
				elif (sport == "25") and (Payload.find(' - Welcome to our SMTP server ESMTP') > -1):
					state_set.add(("TS", sIP, "TCP_" + sport, "listening", "smtp/generic", ()))
					TCP_extract.TCPManualServerDescription[FromPort] = "smtp/generic"
					#Note: with the port restriction above, this block will never execute.  Remove port restriction if you want to use this.
					#if SaveUnhandledAcks:
					#	UnhandledPacket(p, prefs, dests)
					#	#LogNewPayload(ServerPayloadDir, FromPort, Payload)
				#Check for port 80 and search for "Server: " once
				elif (sport == "80") and (Payload.find('Server: ') > -1):
					if Payload.find('Server: Apache') > -1:
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "http/apache", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "http/apache"
					elif Payload.find('Server: Embedded HTTP Server') > -1:
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "http/embedded", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "http/embedded"
					elif Payload.find('Server: gws') > -1:
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "http/gws", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "http/gws"
					elif Payload.find('Server: KFWebServer') > -1:
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "http/kfwebserver", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "http/kfwebserver"
					elif Payload.find('Server: micro_httpd') > -1:
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "http/micro-httpd", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "http/micro-httpd"
					elif Payload.find('Server: Microsoft-IIS') > -1:
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "http/iis", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "http/iis"
					elif Payload.find('Server: lighttpd') > -1:
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "http/lighttpd", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "http/lighttpd"
					elif Payload.find('Server: MIIxpc') > -1:
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "http/mirrorimage", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "http/mirrorimage"
					elif Payload.find('Server: mini_httpd') > -1:
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "http/mini-httpd", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "http/mini-httpd"
					elif Payload.find('Server: nc -l -p 80') > -1:
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "http/nc", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "http/nc"
					elif Payload.find('Server: nginx/') > -1:
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "http/nginx", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "http/nginx"
					elif Payload.find('Server: Nucleus') > -1:
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "http/nucleus", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "http/nucleus"
					elif Payload.find('Server: RomPager') > -1:
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "http/rompager", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "http/rompager"
					elif Payload.find('Server: Server') > -1:
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "http/server", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "http/server"
					elif Payload.find('Server: Sun-ONE-Web-Server/') > -1:
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "http/sun-one", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "http/sun-one"
					elif Payload.find('Server: TrustRank Frontend') > -1:
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "http/trustrank", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "http/trustrank"
					elif Payload.find('Server: YTS/') > -1:
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "http/yahoo", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "http/yahoo"
					elif (Payload.find('HTTP/1.0 404 Not Found') > -1) or (Payload.find('HTTP/1.1 200 OK') > -1):
						state_set.add(("TS", sIP, "TCP_" + sport, "listening", "http/generic", ()))
						TCP_extract.TCPManualServerDescription[FromPort] = "http/generic"
						#Note: with the port restriction above, this block will never execute.  Remove port restriction if you want to use this.
						#if SaveUnhandledAcks:
						#	UnhandledPacket(p, prefs, dests)
						#	#LogNewPayload(ServerPayloadDir, FromPort, Payload)
					#Note: with the port restriction above, this block will never execute.  Remove port restriction if you want to use this.
					#else:
					#	if SaveUnhandledAcks:
					#		UnhandledPacket(p, prefs, dests)
					#		#LogNewPayload(ServerPayloadDir, FromPort, Payload)
				elif (sport == "110") and (Payload.find('POP3 Server Ready') > -1):
					state_set.add(("TS", sIP, "TCP_" + sport, "listening", "pop3/generic", ()))
					TCP_extract.TCPManualServerDescription[FromPort] = "pop3/generic"
				elif (sport == "143") and (Payload.find('* OK dovecot ready') > -1):
					state_set.add(("TS", sIP, "TCP_" + sport, "listening", "imap/dovecot", ()))
					TCP_extract.TCPManualServerDescription[FromPort] = "imap/dovecot"
				elif (sport == "143") and (Payload.find(' IMAP4rev1 ') > -1):
					state_set.add(("TS", sIP, "TCP_" + sport, "listening", "imap/generic", ()))
					TCP_extract.TCPManualServerDescription[FromPort] = "imap/generic"
					#Note: with the port restriction above, this block will never execute.  Remove port restriction if you want to use this.
					#if SaveUnhandledAcks:
					#	UnhandledPacket(p, prefs, dests)
					#	#LogNewPayload(ServerPayloadDir, FromPort, Payload)
				elif (sport == "783") and (Payload.find('SPAMD/1.1 ') > -1):
					state_set.add(("TS", sIP, "TCP_" + sport, "listening", "spamd/spamd", ()))
					TCP_extract.TCPManualServerDescription[FromPort] = "spamd/spamd"
				elif (sport in ("80", "3128")) and (Payload.find('Via: ') > -1) and (Payload.find(' (squid/') > -1):
					state_set.add(("TS", sIP, "TCP_" + sport, "listening", "proxy/squid", ()))
					TCP_extract.TCPManualServerDescription[FromPort] = "proxy/squid"
				#Note: with the port restriction above, this block will never execute.  Remove port restriction if you want to use this.
				#else:
				#	if SaveUnhandledAcks:
				#		UnhandledPacket(p, prefs, dests)
				#		#LogNewPayload(ServerPayloadDir, FromPort, Payload)
		elif dport in ("22", "80", "143", "783", "3128") and ToPort in TCP_extract.LiveTCPService and TCP_extract.LiveTCPService[ToPort]:	#If the "To" side is a known TCP server:
			ClientKey = sIP + ",TCP_" + dport	#Note: CLIENT ip and SERVER port
			if (ClientKey not in TCP_extract.ClientDescription) and Payload:
				#WARNING: update port list above if any new ports are added or 25 is reinstated.
				if (dport == "22") and (Payload.find('SSH-Latency-Measurement') > -1):
					state_set.add(("TC", sIP, "TCP_" + dport, "open", "ssh/smokeping-latency-scanner", ('scan', )))
					TCP_extract.ClientDescription[ClientKey] = "ssh/smokeping-latency-scanner"
				elif (dport == "22") and (Payload.find('SSH-2.-check_ssh_1.5') > -1):
					state_set.add(("TC", sIP, "TCP_" + dport, "open", "ssh/nagios-check_ssh", ('scan', )))
					TCP_extract.ClientDescription[ClientKey] = "ssh/nagios-check_ssh"
				elif (dport == "22") and (Payload.startswith('SSH-2.0-OpenSSH_') or Payload.startswith('SSH-1.5-OpenSSH_')):
					state_set.add(("TC", sIP, "TCP_" + dport, "open", "ssh/openssh", ()))
					TCP_extract.ClientDescription[ClientKey] = "ssh/openssh"
				#As cute as it is to catch this, it miscatches any relay that's carrying a pine-generated mail.
				#elif (dport == "25") and (Payload.find('Message-ID: <Pine.') > -1):
				#	state_set.add(("TC", sIP, "TCP_" + dport, "open", "smtp/pine", ()))
				#	TCP_extract.ClientDescription[ClientKey] = "smtp/pine"
				elif (dport in ("80", "3128")) and (Payload.find('User-Agent: libwww-perl/') > -1):
					state_set.add(("TC", sIP, "TCP_" + dport, "open", "http/libwww-perl", ()))
					TCP_extract.ClientDescription[ClientKey] = "http/libwww-perl"
				elif (dport in ("80", "3128")) and (Payload.find('User-Agent: Lynx') > -1):
					state_set.add(("TC", sIP, "TCP_" + dport, "open", "http/lynx", ()))
					TCP_extract.ClientDescription[ClientKey] = "http/lynx"
				elif (dport in ("80", "3128")) and (Payload.find('User-Agent: Mozilla') > -1)  and (Payload.find(' Firefox/') > -1):
					state_set.add(("TC", sIP, "TCP_" + dport, "open", "http/firefox", ()))
					TCP_extract.ClientDescription[ClientKey] = "http/firefox"
				elif (dport in ("80", "3128")) and (Payload.find('User-Agent: Wget/') > -1):
					state_set.add(("TC", sIP, "TCP_" + dport, "open", "http/wget", ()))
					TCP_extract.ClientDescription[ClientKey] = "http/wget"
				elif (dport == "143") and (Payload.find('A0001 CAPABILITY') > -1):
					state_set.add(("TC", sIP, "TCP_" + dport, "open", "imap/generic", ()))
					TCP_extract.ClientDescription[ClientKey] = "imap/generic"
					#LogNewPayload(ClientPayloadDir, ClientKey, Payload)
				elif (dport == "783") and (Payload.find('PROCESS SPAMC') > -1):
					state_set.add(("TC", sIP, "TCP_" + dport, "open", "spamd/spamc", ()))
					TCP_extract.ClientDescription[ClientKey] = "spamd/spamc"
				#Note: with the port restriction above, this block will never execute.  Remove port restriction if you want to use this.
				#else:
				#	if SaveUnhandledAcks:
				#		UnhandledPacket(p, prefs, dests)
				#		#LogNewPayload(ClientPayloadDir, ClientKey, Payload)
		#else:	#Neither port pair is known as a server
		#	ShowPacket(p, meta, "IPv4/TCPv4/ACK (RST, SYN, FIN off)/Neither port pair is known as a server", HonorQuit, prefs, dests)
		#	#Following is debugging at best; it should only show up early on as the sniffer listens to conversations for which it didn't hear the SYN/ACK
		#	#print "note: neither " + FromPort + " nor " + ToPort + " is listed as a live service."
	elif (meta['flags'] & 0x17) == 0x00:	#(ACK, RST, SYN, and FIN off)
		#FIXME - change these over to SuspiciousPacket
		UnhandledPacket(p, prefs, dests)
		state_set.add(("TC", sIP, "TCP_" + dport, "open", "TCP Null flag scanner", ('noncompliant', 'scan', )))
	elif (meta['flags'] & 0x17) == 0x03:	#SYN/FIN (ACK and RST off)
		UnhandledPacket(p, prefs, dests)
		state_set.add(("TC", sIP, "TCP_" + dport, "open", "TCP SYN/FIN flag scanner", ('noncompliant', 'scan', )))
	elif (meta['flags'] & 0x17) == 0x05:	#RST/FIN (ACK and SYN off)
		UnhandledPacket(p, prefs, dests)
		state_set.add(("TC", sIP, "TCP_" + dport, "open", "TCP RST/FIN flag scanner", ('noncompliant', 'scan', )))
	elif (meta['flags'] & 0x17) == 0x06:	#SYN/RST (ACK and FIN off)
		UnhandledPacket(p, prefs, dests)
		state_set.add(("TC", sIP, "TCP_" + dport, "open", "TCP SYN/RST flag scanner", ('noncompliant', 'scan', )))
	elif (meta['flags'] & 0x17) == 0x07:	#SYN/RST/FIN (ACK off)
		UnhandledPacket(p, prefs, dests)
		state_set.add(("TC", sIP, "TCP_" + dport, "open", "TCP SYN/RST/FIN flag scanner", ('noncompliant', 'scan', )))
	elif (meta['flags'] & 0x17) == 0x13:	#ACK/SYN/FIN (RST off)
		UnhandledPacket(p, prefs, dests)
		state_set.add(("TC", sIP, "TCP_" + dport, "open", "TCP ACK/SYN/FIN flag scanner", ('noncompliant', 'scan', )))
	elif (meta['flags'] & 0x17) == 0x15:	#ACK/RST/FIN (SYN off)
		UnhandledPacket(p, prefs, dests)
		state_set.add(("TC", sIP, "TCP_" + dport, "open", "TCP ACK/RST/FIN flag scanner", ('noncompliant', 'scan', )))
	elif (meta['flags'] & 0x17) == 0x16:	#ACK/RST/SYN (FIN off)
		UnhandledPacket(p, prefs, dests)
		state_set.add(("TC", sIP, "TCP_" + dport, "open", "TCP ACK/RST/SYN flag scanner", ('noncompliant', 'scan', )))
	elif (meta['flags'] & 0x17) == 0x17:	#SYN/FIN/ACK/RST
		UnhandledPacket(p, prefs, dests)
		state_set.add(("TC", sIP, "TCP_" + dport, "open", "TCP SYN/FIN/ACK/RST flag scanner", ('noncompliant', 'scan', )))
	else:	#Other TCP flag combinations here
		ShowPacket(p, meta, "IP/TCP/Unhandled TCP flag combination" + str(meta['flags']), HonorQuit, prefs, dests)

	return state_set


def UDP_extract(p, meta, prefs, dests):
	"""Pull all statements from the UDP layer and return as a set of tuples."""

	sIP = meta['sIP']
	dIP = meta['dIP']
	dport = meta['dport']
	sport = meta['sport']

	if p.getlayer(Raw):
		Payload = force_string(p.getlayer(Raw).load)
	else:
		Payload = ""


	state_set = set([])

	if (sIP == dIP) and (sport == dport) and sIP not in ("127.0.0.1", "::1", "0000:0000:0000:0000:0000:0000:0000:0001"):
		state_set.add(("US", sIP, "UDP_" + sport, "attack", 'land attack IP address spoofed', ('malicious', 'spoofed')))


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
			state_set.add(("UC", sIP, "UDP_" + dport, "open", base_description + additional_info, ('scan', )))
		else:
			state_set.add(("UC", sIP, "UDP_" + dport, "open", base_description + additional_info, ('nonstandardport', 'scan')))
	#else:
	#	p.show()
	#	sys.exit()

#Handle easily categorized services early
	elif dport in PriUDPPortNames:								#Client talking to server
		warning_list = ()
		if dport in udp_port_warnings:			#FIXME - move this outside of UDP main if block, and other udp_port_warning lines too?
			warning_list = (udp_port_warnings[dport],)
		state_set.add(("UC", sIP, "UDP_" + dport, "open", str(PriUDPPortNames[dport]) + "/client", warning_list))	#'portonlysignature'
	elif sport in PriUDPPortNames:								#server talking to client
		warning_list = ()
		if sport in udp_port_warnings:
			warning_list = (udp_port_warnings[sport],)
		state_set.add(("US", sIP, "UDP_" + sport, "open", str(PriUDPPortNames[sport]) + "/server", warning_list))	#'portonlysignature'


	return state_set


def DNS_extract(p, meta, prefs, dests):
	"""Pull all statements from the DNS layer and return as a set of tuples."""

	if "HostIPs" not in DNS_extract.__dict__:
		DNS_extract.HostIPs = {}			#Dictionary of arrays: For a given fully qualified hostname, what IPs (array) are associated?

	state_set = set([])

	if (meta['sport'] != "5353") and (meta['dport'] == "5353") and (p[DNS].qr == 0) and meta['ttl'] != 255:	#query from outside local lan; see https://tools.ietf.org/html/rfc6762 section 5.5
		base_warnings = ('external',)
	else:
		base_warnings = ()

	#see https://tools.ietf.org/html/rfc6762 section 5.5 for notes on external queries
	#qr == 1 is a response
	if 'TCP' in meta['pkt_layers'] or 'TCPerror' in meta['pkt_layers']:
		pass						#We're not handling TCP DNS at the moment
	elif meta['sport'] in ("53", "5353") and p[DNS].qr == 1:
		state_set.add(("US", meta['sIP'], "UDP_" + meta['sport'], "open", udp_port_names.get(meta['sport'], "dns") + "/server", ()))



		#FIXME - Also report the TLD from one of the query answers to show what it's willing to answer for?

		#Not sure if we need this:
		#mdns_service_scan = False

		#Now we extract dns answers.  First, check that there's no dns error:
### rcode=0 No Error
		if p[DNS].rcode == 0:
			#Not sure if we need this:
			#DNSQueryBlocks = []
			DNSBlocks = []
			CNAMERecs = []				#We hold onto all cnames until we've processed all PTR's and A's here
			if p[DNS].ancount > 0:		#If we have at least one answer from the answer block, process it
				DNSBlocks.append(p[DNS].an)
			if p[DNS].arcount > 0:		#Likewise for the "additional" block
				DNSBlocks.append(p[DNS].ar)

			#Not sure if we need this:
			#if p[DNS].qdcount > 0:		#If we have at least one answer from the question block, save it
			#	DNSQueryBlocks.append(p[DNS].qd)
			#	for one_query in DNSQueryBlocks:
			#		while isinstance(one_query, DNSQR):
			#			if one_query.qname == '_services._dns-sd._udp.local.':
			#				mdns_service_scan = True
			#			elif one_query.qname.endswith('.local.'):
			#				ShowPacket(p, meta, ".local. DNS response to NOT _services._dns-sd._udp.local", HonorQuit, prefs, dests)

			#			#Move to the next DNS object in the "qd" block (there should only be one, but try anyways)
			#			one_query = one_query.payload

			for OneAn in DNSBlocks:
				#Thanks to Philippe Biondi for showing me how to extract additional records.
				#debug_out("Start dns extract" + str(p[DNS].ancount), prefs, dests)
				#OneAn = p[DNS].an
				#while OneAn is not NoPayload:		#This doesn't seem to stop at the end of the list; incorrect syntax.
				while isinstance(OneAn, DNSRR):		#Somewhat equivalent:	while not isinstance(an, NoPayload):
					#FIXME - removeme
					#if isinstance(OneAn.rdata, list) and len(OneAn.rdata) == 1:
					#	rdata_string = force_string(OneAn.rdata[0])				#[b'ntp minpoll 9 maxpoll 12 iburst']
					#elif isinstance(OneAn.rdata, list):
					#	ShowPacket(p, meta, "List in dns record: rdata:" + str(OneAn.rdata), HonorQuit, prefs, dests)
					#else:
					rdata_string = force_string(OneAn.rdata)

					#if isinstance(OneAn.rrname, list):
					#	ShowPacket(p, meta, "List in dns record: rrname:" + str(OneAn.rrname), HonorQuit, prefs, dests)
					#else:
					rrname_string = force_string(OneAn.rrname)

					#Type codes can be found in http://www.rfc-editor.org/rfc/rfc1035.txt
					#print "Type: " + str(type(OneAn))		#All of type scapy.DNSRR
					#Note: rclass 32769 appears to show up in mdns records from apple
					if OneAn.rclass in (1, 32769):
						if OneAn.type == 1:		#"IN" class and "A" type answer	#https://en.wikipedia.org/wiki/List_of_DNS_record_types
							DNSIPAddr = rdata_string
							DNSHostname = rrname_string.lower()

							if isFQDN(DNSHostname, prefs, dests):  #We don't want to remember ips for names like "www", "ns1.mydom", "localhost", etc.
								if DNSHostname not in DNS_extract.HostIPs:
									DNS_extract.HostIPs[DNSHostname] = []
								if not DNSIPAddr in DNS_extract.HostIPs[DNSHostname]:             #If we haven't seen this IP address for this hostname,
									DNS_extract.HostIPs[DNSHostname].append(DNSIPAddr)        #Remember this new IP address for this hostname.

							state_set.add(("DN", DNSIPAddr, "A", DNSHostname, "", ()))
						elif OneAn.type == 2:			#"IN" class and "NS" answer
							pass							#Perhaps later
							#Like cnames, this is object -> nameserver hostname, so these would need to be queued like cnames until we're done with A's and PTR's.
						elif OneAn.type == 5:			#"IN" class and "CNAME" answer
							CNAMERecs.append(OneAn)					#Remember the record; we'll process these after the PTR's and A's
						elif OneAn.type == 6:			#"IN" class and "SOA" answer
							pass							#Not immediately useful, perhaps later
						elif OneAn.type == 12:		#"IN" class and "PTR" type answer
							DNSHostname = rdata_string.lower()
															#For input of '182.111.59.66.in-addr.arpa.'  :
							DNSIPAddr = rrname_string.upper()				# '182.111.59.66.IN-ADDR.ARPA.'
							DNSIPAddr = DNSIPAddr.replace(".IN-ADDR.ARPA.", "")		# '182.111.59.66'
							DNSIPAddr = DNSIPAddr.replace(".IP6.ARPA.", "")			# (Strip off the suffix used for ipv6)
							DNSIPAddr = DNSIPAddr.split('.')				# ['182', '111', '59', '66']
							DNSIPAddr.reverse()						# ['66', '59', '111', '182']
							DNSIPAddr = '.'.join(DNSIPAddr)					# '66.59.111.182'
							#Check that we end up with a legal IP address before continuing; we're getting garbage.

							rrname_lower = rrname_string.lower()

							if isFQDN(DNSHostname, prefs, dests):  #We don't want to remember ips for names like "www", "ns1.mydom", "localhost", etc.
								if DNSHostname not in DNS_extract.HostIPs:
									DNS_extract.HostIPs[DNSHostname] = []
								if not DNSIPAddr in DNS_extract.HostIPs[DNSHostname]:             #If we haven't seen this IP address for this hostname,
									DNS_extract.HostIPs[DNSHostname].append(DNSIPAddr)        #Remember this new IP address for this hostname.

							if re.search('^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*$', DNSIPAddr) is not None:
								#Legal IPv4 address
								state_set.add(("DN", DNSIPAddr, "PTR", DNSHostname, "", ()))
							elif re.search('^[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]\.[0-9A-F]$', DNSIPAddr) is not None:
								#Legal IPv6 address such as 0.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.9.2.4.E.1.4.0.0.2.2.F.7.0.6.2.ip6.arpa.
								state_set.add(("DN", explode_ip(DNSIPAddr, prefs, dests), "PTR", DNSHostname, "", ()))
							elif rrname_lower.endswith('.local.'):
								state_set.add(("DN", meta['sIP'], "PTR", rrname_lower, DNSHostname, ()))
								if rrname_string == '_services._dns-sd._udp.local.':	#https://www.akamai.com/us/en/about/our-thinking/threat-advisories/akamai-mdns-reflection-ddos-threat-advisory.jsp
									#FIXME Check if ttl not 0,1,255 and report as external in warnings, otherwise no warning.
									#http://www.dns-sd.org/ServiceTypes.html
									if rdata_string in ('_adisk.', '_adisk._tcp.', '_adisk._tcp.local.'):				#https://jonathanmumm.com/tech-it/mdns-bonjour-bible-common-service-strings-for-various-vendors/
										state_set.add(("IP", meta['sIP'], "IP", "Time Capsule Backups (likely Mac OS)", '', ()))
									elif rdata_string in ('_afpovertcp.', '_afpovertcp._tcp.', '_afpovertcp._tcp.local.'):
										state_set.add(("TS", meta['sIP'], "TCP_427", "listening", 'svrloc/server not confirmed', ()))
										state_set.add(("US", meta['sIP'], "UDP_427", "listening", 'svrloc/server not confirmed', ()))
										state_set.add(("TS", meta['sIP'], "TCP_548", "listening", 'afpovertcp/server not confirmed', ()))
									elif rdata_string in ('_airdrop.', '_airdrop._tcp.', '_airdrop._tcp.local.'):			#https://stackoverflow.com/questions/10693411/implementing-the-airdrop-protocol
										state_set.add(("IP", meta['sIP'], "IP", "Airdrop server (likely Mac OS)", '', ()))
									elif rdata_string in ('_airplay.', '_airplay._tcp.', '_airplay._tcp.local.'):			#https://www.cisco.com/c/en/us/td/docs/solutions/Enterprise/Borderless_Networks/Unified_Access/BYOD_Bonjour_EntMob.html
										state_set.add(("IP", meta['sIP'], "IP", "Apple TV or Apple Airport Express", rdata_string, ()))
									elif rdata_string in ('_amzn-wplay.', '_amzn-wplay._tcp.', '_amzn-wplay._tcp.local.'):
										state_set.add(("IP", meta['sIP'], "IP", "Amazon Fire TV not confirmed", '', ()))			#https://github.com/soef/mdns-discovery
									elif rdata_string in ('_apple-mobdev2.', '_apple-mobdev2._tcp.', '_apple-mobdev2._tcp.local.'):
										state_set.add(("IP", meta['sIP'], "IP", "Apple mobile device possible iphone with wifi sync", '', ()))
									elif rdata_string in ('_appletv-v2.', '_appletv-v2._tcp.', '_appletv-v2._tcp.local.'):
										state_set.add(("IP", meta['sIP'], "IP", "Apple TV V2", rdata_string, ()))
									elif rdata_string in ('_atc.', '_atc._tcp.', '_atc._tcp.local.'):
										state_set.add(("IP", meta['sIP'], "IP", "Shared iTunes Library service", '', ()))
									elif rdata_string in ('_bowtie.', '_bowtie._tcp.', '_bowtie._tcp.local.', '_bttouch.', '_bttouch._tcp.', '_bttouch._tcp.local.', '_bttremote.', '_bttremote._tcp.', '_bttremote._tcp.local.'):	#https://github.com/sgentle/MPDTie/blob/master/rbowtie.rb
										state_set.add(("IP", meta['sIP'], "IP", "Bowtie Remote", '', ()))					#http://bowtieapp.com/
									elif rdata_string in ('_coremediamgr.', '_coremediamgr._tcp.', '_coremediamgr._tcp.local.'):	#http://www.inmethod.com/airvideohd/index.html
										state_set.add(("IP", meta['sIP'], "IP", "Air Video HD", '', ()))
										state_set.add(("TS", meta['sIP'], "TCP_45633", "listening", 'airvideohd/server not confirmed', ()))
									elif rdata_string in ('_cros_p2p.', '_cros_p2p._tcp.', '_cros_p2p._tcp.local.'):			#https://chromium.googlesource.com/chromiumos/platform/p2p/+/master/README
										state_set.add(("TS", meta['sIP'], "TCP_16725", "listening", 'cros_p2p/server not confirmed', ()))
									elif rdata_string in ('_daap.', '_daap._tcp.', '_daap._tcp.local.', '_dacp.', '_dacp._tcp.', '_dacp._tcp.local.'):	#https://nto.github.io/AirPlay.html
										state_set.add(("TS", meta['sIP'], "TCP_3689", "listening", 'daap_dacp/server not confirmed', ()))
									elif rdata_string in ('_dlaccess.', '_dlaccess._tcp.', '_dlaccess._tcp.local.', '_dlattachmentd.', '_dlattachmentd._tcp.', '_dlattachmentd._tcp.local.', '_dltouch.', '_dltouch._tcp.', '_dltouch._tcp.local.'):	#Dylite CRM https://www.marketcircle.com/help/article/what-processes-in-the-os-x-firewall-must-be-allowed-to-use-daylite/
										state_set.add(("TS", meta['sIP'], "TCP_2021", "listening", 'daylite/server not confirmed', ()))
										state_set.add(("TS", meta['sIP'], "TCP_4243", "listening", 'daylite/server not confirmed', ()))
										state_set.add(("TS", meta['sIP'], "TCP_11000", "listening", 'daylite/server not confirmed', ()))
										state_set.add(("TS", meta['sIP'], "TCP_443", "listening", 'daylite/server not confirmed', ()))
									elif rdata_string in ('_eppc.', '_eppc._tcp.', '_eppc._tcp.local.'):				#https://developer.apple.com/library/archive/qa/qa1312/_index.html
										state_set.add(("IP", meta['sIP'], "IP", "Remote AppleEvents", rdata_string, ()))
									elif rdata_string in ('_ftp.', '_ftp._tcp.', '_ftp._tcp.local.'):
										state_set.add(("TS", meta['sIP'], "TCP_21", "listening", 'ftp/server not confirmed', ()))
									elif rdata_string in ('_gntp.', '_gntp._tcp.', '_gntp._tcp.local.'):				#http://www.growlforwindows.com/gfw/help/gntp.aspx
										state_set.add(("TS", meta['sIP'], "TCP_23053", "listening", 'growl/server not confirmed', ()))
									elif rdata_string in ('_home-sharing.', '_home-sharing._tcp.', '_home-sharing._tcp.local.'):
										state_set.add(("IP", meta['sIP'], "IP", "iTunes Home Sharing", rdata_string, ()))
									elif rdata_string in ('_homekit.', '_homekit._tcp.', '_homekit._tcp.local.', '_hap.', '_hap._tcp.', '_hap._tcp.local.'):	#http://dev.iachieved.it/iachievedit/an-in-depth-look-at-apples-homekit/
										state_set.add(("IP", meta['sIP'], "IP", "Apple Homekit server", '', ()))
									elif rdata_string in ('_http.', '_http._tcp.', '_http._tcp.local.'):
										state_set.add(("TS", meta['sIP'], "TCP_80", "listening", 'http/server not confirmed', ()))
									elif rdata_string in ('_http-alt.', '_http-alt._tcp.', '_http-alt._tcp.local.'):
										state_set.add(("IP", meta['sIP'], "IP", 'http/server on alternate port not confirmed', '', ()))
									elif rdata_string in ('_fax-ipp.', '_fax-ipp._tcp.', '_fax-ipp._tcp.local.', '_ipp.', '_ipp._tcp.', '_ipp._tcp.local.', '_sub._ipp._tcp.local.', '_print._sub._ipp._tcp.local.', '_cups._sub._ipp._tcp.local.', '_ipps.', '_ipps._tcp.', '_ipps._tcp.local.', '_sub._ipps._tcp.local.', '_print._sub._ipps._tcp.local.', '_cups._sub._ipps._tcp.local.', '_printer.', '_printer._tcp.', '_printer._tcp.local.'):
										state_set.add(("TS", meta['sIP'], "TCP_515", "listening", 'printer/server not confirmed', ()))
										state_set.add(("US", meta['sIP'], "UDP_515", "listening", 'printer/server not confirmed', ()))
										state_set.add(("TS", meta['sIP'], "TCP_631", "listening", 'ipp/server not confirmed', ()))
										state_set.add(("US", meta['sIP'], "UDP_631", "listening", 'ipp/server not confirmed', ()))
										state_set.add(("TS", meta['sIP'], "TCP_9100", "listening", 'hp-pdl-datastr/server not confirmed', ()))
										state_set.add(("US", meta['sIP'], "UDP_9100", "listening", 'hp-pdl-datastr/server not confirmed', ()))
									elif rdata_string in ('_mediaremotetv.', '_mediaremotetv._tcp.', '_mediaremotetv._tcp.local.'):	#https://github.com/jeanregisser/mediaremotetv-protocol
										state_set.add(("IP", meta['sIP'], "IP", "Apple TV Remote client or server", '', ()))
										state_set.add(("TS", meta['sIP'], "TCP_49152", "listening", 'mediaremotetv/server not confirmed', ()))	#May not be on this port
									elif rdata_string in ('_mpd.', '_mpd._tcp.', '_mpd._tcp.local.'):				#https://www.musicpd.org/doc/html/user.html#chapter-3-configuration
										state_set.add(("TS", meta['sIP'], "TCP_6600", "listening", 'musicplayerdaemon/server not confirmed', ()))
									elif rdata_string in ('_nfs.', '_nfs._tcp.', '_nfs._tcp.local.'):
										state_set.add(("TS", meta['sIP'], "TCP_111", "listening", 'sunrpc/server not confirmed', ()))
										state_set.add(("US", meta['sIP'], "UDP_111", "listening", 'sunrpc/server not confirmed', ()))
										state_set.add(("TS", meta['sIP'], "TCP_1110", "listening", 'nfsd-status/server not confirmed', ()))
										state_set.add(("US", meta['sIP'], "UDP_1110", "listening", 'nfsd-keepalive/server not confirmed', ()))
										state_set.add(("TS", meta['sIP'], "TCP_2049", "listening", 'nfsd/server not confirmed', ()))
										state_set.add(("US", meta['sIP'], "UDP_2049", "listening", 'nfsd/server not confirmed', ()))
										state_set.add(("TS", meta['sIP'], "TCP_4045", "listening", 'nfslock/server not confirmed', ()))
										state_set.add(("US", meta['sIP'], "UDP_4045", "listening", 'nfslock/server not confirmed', ()))
									elif rdata_string in ('_nvstream_dbd.', '_nvstream_dbd._tcp.', '_nvstream_dbd._tcp.local.'):	#https://www.nvidia.com/en-us/shield/games/gamestream/
										state_set.add(("IP", meta['sIP'], "IP", "NVidia Gamestream server", '', ()))
									elif rdata_string in ('_odisk.', '_odisk._tcp.', '_odisk._tcp.local.'):
										state_set.add(("IP", meta['sIP'], "IP", "Mac OS sharing optical disk not confirmed", '', ()))
									elif rdata_string in ('_odproxy.', '_odproxy._tcp.', '_odproxy._tcp.local.'):			#https://support.apple.com/en-us/HT202944
										state_set.add(("TS", meta['sIP'], "TCP_625", "listening", 'odproxy/server not confirmed', ()))
									elif rdata_string in ('_pdl-datastream.', '_pdl-datastream._tcp.', '_pdl-datastream._tcp.local.'):
										state_set.add(("TS", meta['sIP'], "TCP_9100", "listening", 'pdl-datastream/server not confirmed', ()))
									elif rdata_string in ('_presence.', '_presence._tcp.', '_presence._tcp.local.'):
										state_set.add(("IP", meta['sIP'], "IP", 'xmpp_jabber/server not confirmed', '', ()))
									elif rdata_string in ('_printer._sub._privet._tcp.local.', '_sub._privet._tcp.local.', '_privet._tcp.local.', '_privet._tcp.', '_privet.'):	#https://developers.google.com/cloud-print/docs/privet
										state_set.add(("IP", meta['sIP'], "IP", "Google Cloud Print server", '', ()))
									elif rdata_string in ('_raop.', '_raop._tcp.', '_raop._tcp.local.'):				#https://blog.hyperiongray.com/multicast-dns-service-discovery/
										state_set.add(("IP", meta['sIP'], "IP", 'AirTunes not confirmed', '', ()))
									elif rdata_string in ('_remotemouse.', '_remotemouse._tcp.', '_remotemouse._tcp.local.'):	#https://www.informatics.indiana.edu/xw7/papers/bai2016staying.pdf  https://itunes.apple.com/us/app/remote-mouse/id403195710?mt=12  http://www.remotemouse.net/
										state_set.add(("TS", meta['sIP'], "TCP_1978", "listening", 'remotemouse/server not confirmed', ()))
										state_set.add(("US", meta['sIP'], "UDP_1978", "listening", 'remotemouse/server not confirmed', ()))
										state_set.add(("TS", meta['sIP'], "TCP_2007", "listening", 'remotemouse/server not confirmed', ()))
										state_set.add(("TS", meta['sIP'], "TCP_2008", "listening", 'remotemouse/server not confirmed', ()))
									elif rdata_string in ('_rfb.', '_rfb._tcp.', '_rfb._tcp.local.'):
										state_set.add(("TS", meta['sIP'], "TCP_5900", "listening", 'vnc/server not confirmed', ()))
									elif rdata_string in ('_scanner.', '_scanner._tcp.', '_scanner._tcp.local.'):
										state_set.add(("IP", meta['sIP'], "IP", 'Scanner not confirmed', '', ()))
									elif rdata_string in ('_sftp-ssh.', '_sftp-ssh._tcp.', '_sftp-ssh._tcp.local.', '_ssh.', '_ssh._tcp.', '_ssh._tcp.local.', '_udisks-ssh.', '_udisks-ssh._tcp.', '_udisks-ssh._tcp.local.'):
										state_set.add(("TS", meta['sIP'], "TCP_22", "listening", 'ssh/server not confirmed', ()))
									elif rdata_string in ('_sleep-proxy.', '_sleep-proxy._udp.', '_sleep-proxy._udp.local.'):	#http://stuartcheshire.org/sleepproxy/
										state_set.add(("IP", meta['sIP'], "IP", 'Sleep proxy - wake on demand - not confirmed', '', ()))
									elif rdata_string in ('_smb.', '_smb._tcp.', '_smb._tcp.local.'):
										state_set.add(("TS", meta['sIP'], "TCP_137", "listening", 'smb/server not confirmed', ()))
										state_set.add(("TS", meta['sIP'], "TCP_139", "listening", 'smb/server not confirmed', ()))
										state_set.add(("TS", meta['sIP'], "TCP_445", "listening", 'smb/server not confirmed', ()))
										state_set.add(("US", meta['sIP'], "UDP_137", "listening", 'smb/server not confirmed', ()))
										state_set.add(("US", meta['sIP'], "UDP_138", "listening", 'smb/server not confirmed', ()))
									elif rdata_string in ('_teamviewer.', '_teamviewer._tcp.', '_teamviewer._tcp.local.'):		#https://superuser.com/questions/387821/how-do-i-tell-if-employees-are-using-teamviewer-at-work/1049611
										state_set.add(("TS", meta['sIP'], "TCP_5938", "listening", 'teamviewer/server not confirmed', ()))
										#<DNSRR  rrname='_teamviewer._tcp.local.' type=PTR rclass=IN ttl=4500 rdata='....'		#rdata is digits followed by a periond
									elif rdata_string in ('_touch-able.', '_touch-able._tcp.', '_touch-able._tcp.local.'):
										state_set.add(("IP", meta['sIP'], "IP", "Apple TV Remote App", rdata_string, ()))
									elif rdata_string in ('_tunnel.', '_tunnel._tcp.', '_tunnel._tcp.local.'):			#https://tools.ietf.org/html/rfc3620  One system that advertised _tunnel also advertised _bp2p - any relationship?
										state_set.add(("TS", meta['sIP'], "TCP_604", "listening", 'tunnel/server not confirmed', ('tunnel',)))
									elif rdata_string in ('_xcs2p.', '_xcs2p._tcp.', '_xcs2p._tcp.local.'):				#https://github.com/buildasaurs/Buildasaur/issues/166
										state_set.add(("IP", meta['sIP'], "IP", "XCode Server (likely Mac OS)", rdata_string, ()))
										state_set.add(("TS", meta['sIP'], "TCP_22", "listening", 'ssh/server not confirmed', ()))		#https://support.apple.com/en-us/HT202944
										state_set.add(("TS", meta['sIP'], "TCP_80", "listening", 'http/server not confirmed', ()))
										state_set.add(("TS", meta['sIP'], "TCP_443", "listening", 'https/server not confirmed', ()))
										state_set.add(("TS", meta['sIP'], "TCP_3690", "listening", 'svn/server not confirmed', ()))
										state_set.add(("US", meta['sIP'], "UDP_3690", "listening", 'svn/server not confirmed', ()))
										state_set.add(("TS", meta['sIP'], "TCP_9418", "listening", 'git/server not confirmed', ()))
										state_set.add(("US", meta['sIP'], "UDP_9418", "listening", 'git/server not confirmed', ()))
									elif rdata_string in ('', '_bp2p.', '_bp2p._tcp.', '_bp2p._tcp.local.', '_chat-files.', '_chat-files._tcp.', '_chat-files._tcp.local.', '_companion-link.', '_companion-link._tcp.', '_companion-link._tcp.local.', '_coupon_printer.', '_coupon_printer._tcp.', '_coupon_printer._tcp.local', '_device-info.', '_device-info._tcp.', '_device-info._tcp.local.', '_dltouch.', '_dltouch._tcp.', '_dltouch._tcp.local.', '_hearing.', '_hearing._tcp.', '_hearing._tcp.local.', '_mamp.', '_mamp._tcp.', '_mamp._tcp.local.', '_nasd.', '_nasd._tcp.', '_nasd._tcp.local.', '_net-assistant.', '_octoprint.', '_octoprint._tcp.', '_octoprint._tcp.local.', '_parentcontrol.', '_parentcontrol._tcp.', '_parentcontrol._tcp.local.', '_ptService.', '_ptService._tcp.', '_qmobile.', '_qdiscover.', '_rfb.', '_rfb._tcp.', '_rfb._tcp.local', '_tw-multipeer.', '_tw-multipeer._tcp.', '_tw-multipeer._tcp.local.', '_uscan.', '_uscan._tcp.', '_uscan._tcp.local.', '_uscans.', '_uscans._tcp.', '_uscans._tcp.local.', '_workstation.', '_workstation._tcp.', '_workstation._tcp.local.'):
										pass
									else:
										debug_out("service scan reply:" + rdata_string, prefs, dests)
										ShowPacket(p, meta, "service scan reply", HonorQuit, prefs, dests)
										#sys.exit()

								#<DNSRR  rrname='_kerberos.{machine_name}.local.' type=TXT rclass=IN ttl=4500 rdata='LKDC:SHA1.......' (hash removed)
								elif rrname_string.startswith('_kerberos.') and rrname_string.endswith('.local.') and rdata_string.startswith('LKDC:'):
									#FIXME - extract hostname from the center
									state_set.add(("DN", meta['sIP'], "PTR", rrname_string, 'Kerberos', ()))
								#<DNSRR  rrname='{machine_name}._device-info._tcp.local.' type=TXT rclass=IN ttl=4500 rdata='model=MacBookPro11,4osxvers=16'
								elif rrname_string.endswith('._device-info._tcp.local.'):
									device_name = rrname_string.replace('._device-info._tcp.local.', '')
									state_set.add(("IP", meta['sIP'], "IP", device_name, rdata_string, ()))
								elif rrname_string in ('_presence.', '_presence._tcp.', '_presence._tcp.local.'):			#Book: XMPP: The Definitive Guide: Building Real-Time Applications with Jabber
									#debug_out("_presence reply:" + rdata_string, prefs, dests)
									#ShowPacket(p, meta, "_presence reply", HonorQuit, prefs, dests)
									#Appears to be used by jabber with _presence._tcp.local. PTR username@machine._presence._tcp.local.
									#Requesting a SRV record for username@machine._presence._tcp.local. returns a port and machine to use
									state_set.add(("IP", meta['sIP'], "IP", "XMPP/Jabber/_presence Owner ID", rdata_string, ()))
								else:
									UnhandledPacket(p, prefs, dests)
							#else:
							#	debug_out("Odd PTR rrname: " + rrname_string, prefs, dests)
						elif OneAn.type == 13:		#"IN" class and "HINFO" answer	https://tools.ietf.org/html/rfc1035
							if rrname_string.endswith('.local.'):
								cpu_name, remainder = extract_len_string(rdata_string)
								os_name, remainder = extract_len_string(remainder)
								state_set.add(("DN", meta['sIP'], "HINFO", rrname_string, "cpu=" + cpu_name + " os=" + os_name, ()))
							else:
								UnhandledPacket(p, prefs, dests)				#Possibly later, save as raw text
						elif OneAn.type == 15:		#"IN" class and "MX" answer
							pass							#Possibly later
						elif OneAn.type == 16:		#"IN" class and "TXT" answer
							if rrname_string.endswith('.local.'):
								#Note, this is technically a TXT record, but it's converting an IP address into a hostname (possibly with other stuff), so I'm calling it a PTR
								state_set.add(("DN", meta['sIP'], "PTR", rrname_string, rdata_string, ()))
							else:
								UnhandledPacket(p, prefs, dests)				#Possibly later, save as raw text
						elif OneAn.type == 17:		#"IN" class and "RP" answer.
							dns_object = rrname_string
							resp_person = rdata_string

							readable_person = ''
							first_word, remainder = extract_len_string(resp_person)
							while first_word:
								readable_person += first_word + '.'
								first_word, remainder = extract_len_string(remainder)

							state_set.add(("NA", '0.0.0.0', "RP", dns_object, readable_person, ()))
						elif OneAn.type == 24:		#"IN" class and "SIG" answer					https://tools.ietf.org/html/rfc4034
							pass
						elif OneAn.type == 28:		#"IN" class and "AAAA" answer
							DNSIPAddr = rdata_string.upper()
							DNSHostname = rrname_string.lower()

							if isFQDN(DNSHostname, prefs, dests):  #We don't want to remember ips for names like "www", "ns1.mydom", "localhost", etc.
								if DNSHostname not in DNS_extract.HostIPs:
									DNS_extract.HostIPs[DNSHostname] = []
								if not DNSIPAddr in DNS_extract.HostIPs[DNSHostname]:             #If we haven't seen this IP address for this hostname,
									DNS_extract.HostIPs[DNSHostname].append(DNSIPAddr)        #Remember this new IP address for this hostname.

							state_set.add(("DN", explode_ip(DNSIPAddr, prefs, dests), "AAAA", DNSHostname, "", ()))
						elif OneAn.type == 33:		#"IN" class and "SRV" answer
							if rrname_string.endswith('_presence._tcp.local.'):
								state_set.add(("DN", meta['sIP'], "SRV", rrname_string, rdata_string.strip(' \t\r\n\0'), ()))
							elif rrname_string.endswith('.local.'):
								state_set.add(("DN", meta['sIP'], "SRV", rrname_string, '', ()))			#Too much garbage in OneAn.rdata to include it as additional info: str(OneAn.rdata).strip(' \t\r\n\0')
							else:
								UnhandledPacket(p, prefs, dests)							#Possibly later, save as raw text
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
						elif OneAn.type == 65:		#"IN" class and "HTTPS" answer					https://en.wikipedia.org/wiki/List_of_DNS_record_types
							pass
						elif OneAn.type == 99:		#"IN" class and "SPF" answer					https://tools.ietf.org/html/rfc7208
							pass
						else:
							debug_out("PUDR: IN, but unhandled type: " + str(OneAn.type), prefs, dests)
							ShowPacket(p, meta, "IN, but unhandled type", HonorQuit, prefs, dests)
					elif (OneAn.rclass == 0) and (OneAn.type == 255):					#"Reserved" class and "ANY" answer.  WTF?
						UnhandledPacket(p, prefs, dests)
					elif OneAn.rclass == 0:									#"Reserved" class
						UnhandledPacket(p, prefs, dests)
					elif (OneAn.rclass == 3) and (OneAn.type == 16):					#Chaos/CH domain and type TXT
						if rrname_string.upper() in ('VERSION.BIND.', 'HOSTNAME.BIND.'):
							state_set.add(("DN", meta['sIP'], "TXT", rdata_string, 'Chaos/' + rrname_string, ()))
							state_set.add(("UC", meta['dIP'], "TXT", 'open', 'dns/client Chaos/' + rrname_string, ('scan',)))
						else:
							ShowPacket(p, meta, "DNS Chaos/OTHER answer", HonorQuit, prefs, dests)
					elif (OneAn.rclass == 3) and (OneAn.type == 2) and rrname_string.upper() == 'VERSION.BIND.':	#Chaos/CH domain and type NS
						pass
					elif (OneAn.rclass == 254) and (OneAn.type == 5):					#254 => QCLASS NONE and type=CNAME
						UnhandledPacket(p, prefs, dests)
					elif (OneAn.rclass == 255) and (OneAn.type == 250):					#"ANY" class and "TSIG" answer.
						UnhandledPacket(p, prefs, dests)
					elif (OneAn.rclass == 256) and (OneAn.type == 256):					#WTF?
						UnhandledPacket(p, prefs, dests)
					elif (OneAn.type == 41) and rrname_string in ('.', ''):	#OPT AR record for EDNS0; see https://tools.ietf.org/html/rfc6891 . Class holds the UDP payload size
						pass
					else:
						debug_out("PUDR: unhandled rclass: " + str(OneAn.type), prefs, dests)
						ShowPacket(p, meta, "unhandled rclass", HonorQuit, prefs, dests)

					#Move to the next DNS object in the "an" block
					OneAn = OneAn.payload
			for OneCNAME in CNAMERecs:		#Now that we have all A/PTR's, go back and turn cname records into pseudo-A's
				if isinstance(OneCNAME, DNSRR):
					Alias = force_string(OneCNAME.rrname).lower()
					Existing = force_string(OneCNAME.rdata).lower()
					if isFQDN(Alias, prefs, dests) and isFQDN(Existing, prefs, dests):
						if Existing in DNS_extract.HostIPs:
							for OneIP in DNS_extract.HostIPs[Existing]:				#Loop through each of the IPs for the canonical name, and
								state_set.add(("DN", explode_ip(OneIP, prefs, dests), "CNAME", Alias, "", ()))	#report them as kind-of A records for the Alias.		#FIXME - change last field to Existing?
						#If we don't have a A/PTR record for "Existing", just ignore it.  Hopefully we'll get the Existing A/PTR in the next few answers, and will re-ask for the CNAME later, at which point we'll get a full cname record.
						#else:
						#	debug_out("CNAME " + Alias + " -> " + Existing + " requested, but no IP's for the latter, skipping.", prefs, dests)
					#else:
					#	debug_out("One of " + Alias + " and " + Existing + " isn't an FQDN, skipping cname processing.", prefs, dests)
### rcode=1 FormErr: server responding to an improperly formatted request
		elif p[DNS].rcode == 1:
			pass
### rcode=2 ServFail: domain exists, root nameservers list authoritative name servers, but authNS's won't answer queries
		elif p[DNS].rcode == 2:
			pass
### rcode=3 NXDOMAIN: root nameservers don't have any listing (domain doesn't exist or is on hold)
		elif p[DNS].rcode == 3:
			if prefs['nxdomain']:
				DNSBlocks = []
				if p[DNS].qdcount == 1:		#If we have one question from the question record, process it
					DNSBlocks.append(p[DNS].qd)
				else:
					ShowPacket(p, meta, "DNS Answer with NXDOMAIN, qdcount not equal to 1", KeepGoing, prefs, dests)
				for OneAn in DNSBlocks:
					if isinstance(OneAn, DNSQR):
						if OneAn.qclass in (1, 32769):
							#FIXME - add more DNS record types
							if OneAn.qtype == 1:		#"IN" class and "A" type answer
								DNSQuery = OneAn.qname.lower()
								state_set.add(("DN", "0.0.0.0", "A", DNSQuery, "NXDOMAIN", ()))
							elif OneAn.qtype == 2:		#"IN" class and "NS" type answer
								DNSQuery = OneAn.qname.lower()
								state_set.add(("DN", "0.0.0.0", "NS", DNSQuery, "NXDOMAIN", ()))
							elif OneAn.qtype == 12:		#"IN" class and "PTR" type answer
								DNSQuery = OneAn.qname.lower()
								state_set.add(("DN", "0.0.0.0", "PTR", DNSQuery, "NXDOMAIN", ()))
							elif OneAn.qtype == 15:		#"IN" class and "MX" type answer
								DNSQuery = OneAn.qname.lower()
								state_set.add(("DN", "0.0.0.0", "MX", DNSQuery, "NXDOMAIN", ()))
							elif OneAn.qtype == 28:		#"IN" class and "AAAA" type answer
								DNSQuery = OneAn.qname.lower()
								state_set.add(("DN", "0000:0000:0000:0000:0000:0000:0000:0000", "AAAA", DNSQuery, "NXDOMAIN", ()))
							else:
#FIXME - pass down prefs dict with unhandled_h
								ShowPacket(p, meta, "DNS Answer with NXDOMAIN", KeepGoing, prefs, dests)
						else:
#FIXME - pass down prefs dict with unhandled_h
							UnhandledPacket(p, prefs, dests)
### rcode=4 Not implemented
		elif p[DNS].rcode == 4:
			UnhandledPacket(p, prefs, dests)
### rcode=5 Query refused
### rcode=7 YXRRSET - RRset exists when it should not.
### rcode=8 NXRRSet - RRset that should exist does not.
### rcode=9 Not authoritative https://tools.ietf.org/html/rfc2136 (note, also used as Not Authorized in TSIG update response https://tools.ietf.org/html/rfc2845 )
		elif p[DNS].rcode in (5, 7, 8, 9):
			pass
		else:	#rcode indicates an error
			UnhandledPacket(p, prefs, dests)
			#ShowPacket(p, meta, "process_udp_dns_response/unhandled rcode", HonorQuit, prefs, dests)


	#qr == 0 is a request
	elif meta['dport'] in ("53", "5353") and p[DNS].qr == 0:
		state_set.add(("UC", meta['sIP'], "UDP_" + meta['dport'], "open", udp_port_names.get(meta['dport'], "dns") + "/client", base_warnings))

		#Note DNS queries that use type ANY.
		amplified_query = False
		DNSBlocks = []
		ANY_domains = ([])
		if p[DNS].qdcount > 0:
			DNSBlocks.append(p[DNS].qd)
		for OneQr in DNSBlocks:
			while isinstance(OneQr, DNSQR):
				if OneQr.qclass == 1:			#Class IN
					dns_object = force_string(OneQr.qname).lower()
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
						ShowPacket(p, meta, "ANY domain requested", HonorQuit, prefs, dests)

					if OneQr.qtype == 255 and not dns_object in ANY_domains:
						ANY_domains.append(dns_object)

				OneQr = OneQr.payload

		if amplified_query:
			state_set.add(("UC", meta['sIP'], "UDP_" + meta['dport'], "open", udp_port_names.get(meta['dport'], "dns") + "/client ANY domains requested:" + ' '.join(ANY_domains), ('amplification', 'spoofed')))
			#ShowPacket(p, meta, "malicious dns query", HonorQuit, prefs, dests)
		else:
			state_set.add(("UC", meta['sIP'], "UDP_" + meta['dport'], "open", udp_port_names.get(meta['dport'], "dns") + "/client", ()))

	elif (meta['sport'] != "53") and (meta['dport'] == "53") and (p[DNS].qr == 1):			#dns response coming in from what looks like a DNS client.
		UnhandledPacket(p, prefs, dests)
	elif (meta['sport'] == "53") and (p[DNS].rcode in (2, 9, 13)):					#source port 53, but the server is sending back server-failure/unassigned.
		UnhandledPacket(p, prefs, dests)
	else:
		ShowPacket(p, meta, "IP/UDP/unhandled packet with DNS layer", HonorQuit, prefs, dests)

	return state_set
