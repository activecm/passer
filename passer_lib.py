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
from scapy.all import * #Required for Scapy 2.0 and above
use_scapy_all = True


#======== Variables ========
passer_lib_version = '0.2'



#======== Support functions ========

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
	meta_dict = {'sMAC': '', 'dMAC': '', 'cast_type': '', 'ip_class': '', 'ttl': '', 'sIP': '', 'dIP': '', 'sport': '', 'dport': ''}

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
