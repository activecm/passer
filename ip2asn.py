#!/usr/bin/env python3
"""Takes ip addresses provided on stdin (one per line) and outputs info about the ASNs that contain them."""
#Appears to work just fine under both python2 and python3.

#Download https://iptoasn.com/data/ip2asn-combined.tsv.gz to current directory, gunzip it.

import os
import sys
import csv
import fileinput
from ipaddress import summarize_address_range, IPv4Address, IPv6Address		#Not needed: ip_address, AddressValueError


#Note: netaddr removed as standard python library does not include it, but appears to include ipaddress.  See v0.1 for comparison between the two - both provide equal results for all ip ranges.
ip2asn_version = '0.6.1'


def load_asn_table(source_file):
	"""Loads the subnets from ip2asn-combined.tsv."""
	#real	0m46.232s to load

	Paranoid = False			#Setting this to True enables additional checks on the ip2asn-combined raw data (that descriptions and countries stay consistent)

	as_info_struct = {}		#Dictionary of Lists of dictionaries.
					#Top level dictionary has keys = 4_firstoctet for ipv4, 6_firsthexbyte for ipv6.  Values are the lists on the next line
					#next level lists have keys 0-128; their values are dictionaries.  For most specific subnet, search from 128 back to 1 (32 back to 1 for ipv4)
					#second level dictionaries;  key = IP object, value is as_num
					#Adding the first_octet level makes a significant and visual performance increase in lookup time.

	asn_country = {}		#Key= as_num, value=2 letter country code
	asn_description = {}		#Key= as_num, value=asn description


	if os.path.exists(source_file):
		with open(source_file, 'r') as aih:
			reader = csv.reader(aih, delimiter='\t')
			#Format: range_start range_end AS_number country_code AS_description
			for first_ip, last_ip, as_num, country, as_description in reader:
				if sys.version_info < (3, 0):
					first_ip = unicode(first_ip)
					last_ip = unicode(last_ip)
					country = unicode(country)
					try:
						as_description = as_description.decode('utf-8')
					except UnicodeDecodeError:
						sys.stderr.write("Unable to convert: " + as_description + "\n")

				#Load country and description values into dictionaries for later use.
				if as_num in asn_country:
					if Paranoid and asn_country[as_num] != country:
						sys.stderr.write("country mismatch: for asnum: " + str(as_num) + ", " + asn_country[as_num] + " != " + country + "\n")
				else:
					asn_country[as_num] = country

				if as_num in asn_description:
					if Paranoid and asn_description[as_num] != as_description:
						sys.stderr.write("description mismatch: for asnum: " + str(as_num) + ", " + asn_description[as_num] + " != " + as_description + "\n")
				else:
					asn_description[as_num] = as_description

				#print(first_ip + ',' + last_ip + ',' + as_num + ',' + country + ',' + as_description)
				if as_num == '0' and as_description == 'Not routed':
					pass
				#elif as_num == '0' and as_description != 'Not routed':
				#	sys.stderr.write('as == 0, desc != not routed\n')
				#elif as_num != '0' and as_description == 'Not routed':
				#	sys.stderr.write('as != 0, desc == not routed\n')
				else:
					if first_ip.find(':') > -1:
						first_addr = IPv6Address(first_ip)
						last_addr = IPv6Address(last_ip)
					else:
						first_addr = IPv4Address(first_ip)
						last_addr = IPv4Address(last_ip)
					#except:				# (AddressValueError, ipaddress.AddressValueError):

					sar_cidrs = list(summarize_address_range(first_addr, last_addr))
					for one_cidr in sar_cidrs:
						if one_cidr.version == 4:
							first_octet = '4_' + one_cidr.exploded.split('.')[0]
						elif one_cidr.version == 6:
							first_octet = '6_' + one_cidr.exploded[0:2]

						if first_octet not in as_info_struct:
							as_info_struct[first_octet] = []
							for cidr_len in range(0, 129):		#Numbers 0 to 128
								as_info_struct[first_octet].append({})

						one_netmask = one_cidr.prefixlen
						#print("Prefixlen: " + str(one_netmask))
						if one_cidr in as_info_struct[first_octet][one_netmask]:
							if Paranoid and as_info_struct[one_netmask][one_cidr] != as_num:
								sys.stderr.write("For subnet " + str(one_cidr) + ", " + as_info_struct[one_netmask][one_cidr] + " != " + str(as_num) + "\n")
						else:
							as_info_struct[first_octet][one_netmask][one_cidr] = as_num
	else:
		sys.stderr.write("ASN Source file " + source_file + " does not exist, unable to lookup ASNs.\n")

	return as_info_struct, asn_country, asn_description



def ip_asn_lookup(ip_string, as_num_d):
	"""Find the ASN for the given IP address or None if no match found.  This returns the most specific subnet in case there are multiple matching cidr blocks."""
	#Approx 0.7 secs/lookup

	if sys.version_info < (3, 0):
		ip_string = unicode(ip_string)

	if ip_string.find(':') > -1:
		try:
			lookup_obj = IPv6Address(ip_string)
			first_octet = '6_' + lookup_obj.exploded[0:2]
		except:
			return None
		max_index = 128
	else:
		try:
			lookup_obj = IPv4Address(ip_string)
			first_octet = '4_' + lookup_obj.exploded.split('.')[0]
		except:
			return None
		max_index = 32


	if first_octet in as_num_d:
		for search_netmask in range(max_index, -1, -1):
			for one_net in as_num_d[first_octet][search_netmask]:
				if lookup_obj in one_net:
					return as_num_d[first_octet][search_netmask][one_net]
	#else:
	#	return None

	return None



def formatted_asn_output(orig_ip_string, out_format, as_num_d, as_country_d, as_descriptions_d):
	"""Take supplied ip string, look up its ASN, and return a formatted output string."""

	formatted_output = []		#List of output strings/dictionaries

	clean_ip_string = orig_ip_string.rstrip()
	found_as_num = ip_asn_lookup(clean_ip_string, as_num_d)
	if out_format == 'passer':
		if found_as_num:
			formatted_output.append('AS,' + clean_ip_string + ',AS,' + str(found_as_num) + ',' + as_descriptions_d[found_as_num].replace(',', ' '))
			if as_country_d[found_as_num] not in ('', 'Unknown'):
				formatted_output.append('GE,' + clean_ip_string + ',CC,' + as_country_d[found_as_num] + ',')
	elif out_format == 'json':
		if found_as_num:
			formatted_output.append({'Type': 'AS', 'IPAddr': clean_ip_string, 'Proto': 'AS', 'State': str(found_as_num), 'Description': as_descriptions_d[found_as_num].replace(',', ' ')})
			if as_country_d[found_as_num] not in ('', 'Unknown'):
				formatted_output.append({'Type': 'GE', 'IPAddr': clean_ip_string, 'Proto': 'CC',  'State': as_country_d[found_as_num], 'Description': ''})
	else:
		if found_as_num:
			formatted_output.append('IP: ' + clean_ip_string + ' ASN: ' + str(found_as_num) + ' Country: ' + as_country_d[found_as_num] + ' Description: ' + as_descriptions_d[found_as_num])
		else:
			formatted_output.append('IP: ' + clean_ip_string + ' is not in any asn')

	return formatted_output


if __name__ == "__main__":
	asn_info_file = './ip2asn-combined.tsv'
	requested_format = 'passer'

	as_nums, asn_countries, asn_descriptions = load_asn_table(asn_info_file)

	for line in fileinput.input():
		for one_out in formatted_asn_output(line, requested_format, as_nums, asn_countries, asn_descriptions):
			print(one_out)
