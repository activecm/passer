#!/usr/bin/env python
"""Multiprocessing version of passer."""
#Copyright 2018 William Stearns <william.l.stearns@gmail.com>
#Released under GPL v3

#FIXME - on KeyboardInterrupt exception, drain input queue.

from __future__ import print_function
from ipaddress import summarize_address_range, IPv4Address, IPv6Address
from multiprocessing import Process, current_process, Manager
import multiprocessing
import os
import sys
import csv
import fileinput
import time
import json
import socket				#For dns lookups
import codecs				#For python2 utf-8 writing
#from scapy.all import sniff, Scapy_Exception, PcapWriter
from scapy.all import *			#Please make sure you have an up-to-date version of scapy, at least 2.4.0
# Imports for passive_fingerprinting feature.
from smudge.passive_data import passive_data
from smudge.passive_data import pull_data
from smudge.passive_data import tcp_sig


sys.path.insert(0, '.')			#Allows us to load from the current directory (There was one claim that we need to create an empty file __init__.py , but this does not appear to be required.)

ip2asn_loaded = False
try:
	from ip2asn import load_asn_table, ip_asn_lookup, formatted_asn_output
except ImportError:
	sys.stderr.write('Unable to load ip2asn , skipping ASN lookups of IP addresses.\n')
else:
	ip2asn_loaded = True

scapy_traceroute_loaded = False
try:
	from scapy_traceroute import traceroute_hop_list
except ImportError:
	sys.stderr.write('Unable to load scapy_traceroute , skipping traceroute path lookups.\n')
else:
	scapy_traceroute_loaded = True

try:
	from passer_lib import *		#Support functions for this script
except ImportError:
	sys.stderr.write('Unable to load passer_lib , exiting.\n')
	quit()

if sys.version_info > (3, 0):           #Python 3
	from queue import Empty, Full
else:					#Python 2
	from Queue import Empty, Full

try:
	if not passer_lib_version:
		sys.stderr.write('Unable to load passer_lib , exiting.\n')
		quit()
except NameError:
	sys.stderr.write('Unable to load passer_lib , exiting.\n')
	quit()

#Note; this particular module hasn't been updated in a while and doesn't support python3.
##sudo port install GeoLiteCity py27-geoip py34-geoip py35-geoip py36-geoip
##sudo yum install geolite2-city   #NOT python-pygeoip
##sudo pip install python-geoip python-geoip-geolite2

#Instead, use this:
#sudo pip3 install maxminddb-geolite2
geolite_loaded = False
try:
	from geolite2 import geolite2
except ImportError:
	sys.stderr.write('Unable to load geolite2 , skipping geolocation lookups.\n')
else:
	geolite_loaded = True

if os.path.exists("/etc/p0f/p0f.fp") or os.path.exists("/opt/local/share/p0f/p0f.fp") or os.path.exists("/usr/share/p0f/p0f.fp"):
	load_module("p0f")
else:
	sys.stderr.write("/etc/p0f/p0f.fp not found; please install p0f version 2 to enable OS fingerprinting.\n")
	#FIXME - remember whether it's loaded or not and test this before trying to use p0f

p_test_version = '0.39'

Verbose = False
ShowProgress = False			#In most handlers, spit out a letter when each handler finishes processing a packet
out_format = 'csv'			#Either 'json' or 'csv'

max_processed_acks = 5			#For TCP packets, we only want to look at the early ACK packets.  After we've looked at this many in a given direction we stop handing the rest to TCP_extract

#On mac OS/X with python 2.7 at least, queue sizes are limited to 32767
max_handler_qsz = 16384
highpri_packet_qsz = 32767
lowpri_packet_qsz = 4096
output_qsz = 32767
unhandled_qsz = 32767
ip_lookup_qsz = 32767
host_lookup_qsz = 4096
nice_raise = 2				#Medium/lower priority processes raise their nice level by this amount/this amount+2.  This is in addition to any adjustments by running the entire program under the "nice" executable.


#======== Support functions ========
def whatami(base_name):
	"""Returns debug string with information about the current process."""

	ret_whatami = base_name

	ret_whatami += '/self_name=' + str(current_process().name)

	if hasattr(os, 'getppid'):
		ret_whatami += '/ppid=' + str(os.getppid())
	ret_whatami += '/pid=' + str(os.getpid())

	return ret_whatami


def Progress(progress_string):
	"""If ShowProgress is True, put a progress indicator to stderr."""

	if ShowProgress:
		sys.stderr.write(str(progress_string))
		sys.stderr.flush()



#======== Specific layer handlers ========
def output_handler(sh_da, prefs, dests):
	"""Process all CSV output supplied by the other processes."""

	if "need_to_exit" not in output_handler.__dict__:
		output_handler.need_to_exit = False

	if 'tr_already_submitted' not in output_handler.__dict__:
		output_handler.tr_already_submitted = set([])

	os.nice(nice_raise)							#Lower priority to give higher priority to critical tasks
	debug_out(whatami('output'), prefs, dests)

	if "lines_sent" not in output_handler.__dict__:
		output_handler.lines_sent = []

	if "log_h" not in output_handler.__dict__:
		output_handler.log_h = None

		if prefs['log']:
			try:
				if sys.version_info > (3, 0):           #Python 3
					output_handler.log_h = open(prefs['log'], 'a', errors='backslashreplace')
				else:					#Python 2
					output_handler.log_h = codecs.open(prefs['log'], 'a', errors='ignore')
			except:
				debug_out("Unable to append to " + prefs['log'] + ", no logging will be done.", prefs, dests)

	while True:
		try:
			out_rec = dests['output'].get(block=True, timeout=None)
		except KeyboardInterrupt:
			output_handler.need_to_exit = True
			break
		else:
			if out_rec is None:
				output_handler.need_to_exit = True
				break
			if out_rec not in output_handler.lines_sent:
				output_handler.lines_sent.append(out_rec)
				if len(out_rec) != 6:
					debug_out('outrecord length != 6', prefs, dests)
				elif out_format == 'json':
					out_string = '{"Type": "' + str(out_rec[Type_e]) + '", "IPAddr": "' + str(out_rec[IPAddr_e]) + '", "Proto": "' + str(out_rec[Proto_e]) + '", "State": "' + str(out_rec[State_e]) + '", "Description": "' + str(out_rec[Description_e]) + '", "Warnings": ' + str(list(out_rec[Warnings_e])) + '}'
					try:
						print(out_string)			#.decode('utf-8')
					except UnicodeDecodeError:
						pass
					except:
						raise
					if output_handler.log_h is not None:
						try:
							if sys.version_info > (3, 0):           #Python 3
								output_handler.log_h.write(out_string + '\n')
							else:					#Python 2
								output_handler.log_h.write(out_string.encode('utf-8') + '\n')
							output_handler.log_h.flush()
						except UnicodeDecodeError:
							pass
						except:
							raise

				elif out_format == 'csv':
					out_csv = ','.join((out_rec[Type_e], out_rec[IPAddr_e], out_rec[Proto_e], out_rec[State_e], out_rec[Description_e] + ' ' + str(list(out_rec[Warnings_e])).replace(',', ' ').replace("'", '').strip('[]')))
					try:
						print(out_csv)				#.decode('utf-8')
					except UnicodeDecodeError:
						pass
					except:
						raise

					if output_handler.log_h is not None:
						try:
							if sys.version_info > (3, 0):           #Python 3
								output_handler.log_h.write(out_csv + '\n')	#.encode('utf-8') , believed to be wrong
							else:					#Python 2
								output_handler.log_h.write(out_csv.encode('utf-8') + '\n')
							output_handler.log_h.flush()
						except UnicodeDecodeError:
							pass
						except:
							raise

				if prefs['active'] and not output_handler.need_to_exit:
					if out_rec[IPAddr_e] not in ('', '0.0.0.0', '::', '0000:0000:0000:0000:0000:0000:0000:0000'):
						try:
							dests['ip_lookup_asn'].put(out_rec[IPAddr_e], block=False)
						except Full:
							pass

						try:
							dests['ip_lookup_geoip'].put(out_rec[IPAddr_e], block=False)
						except Full:
							pass

						try:
							dests['ip_lookup_hostname'].put(out_rec[IPAddr_e], block=False)
						except Full:
							pass

						if out_rec[IPAddr_e] not in output_handler.tr_already_submitted:
							output_handler.tr_already_submitted.add(out_rec[IPAddr_e])
							try:
								dests['ip_lookup_traceroute'].put(out_rec[IPAddr_e], block=False)
							except Full:
								pass
					if out_rec[Type_e] == "DN" and out_rec[Proto_e] in ('A', 'AAAA', 'PTR', 'CNAME'):
						try:
							dests['host_lookup'].put(out_rec[State_e], block=False)
						except Full:
							pass
	debug_out('Exiting output', prefs, dests)



def unhandled_handler(sh_da, prefs, dests):
	"""Save all unhandled packets supplied by the other processes."""

	os.nice(nice_raise)							#Lower priority to give higher priority to critical tasks
	debug_out(whatami('unhandled'), prefs, dests)

	if "packets_saved" not in unhandled_handler.__dict__:
		unhandled_handler.packets_saved = []

	if "unhandled_h" not in unhandled_handler.__dict__:
		unhandled_handler.unhandled_h = None
		if prefs['unhandled']:
			try:
				unhandled_handler.unhandled_h = PcapWriter(filename=prefs['unhandled'], append=True)
			except:
				debug_out("Unable to open " + prefs['unhandled'] + ", no unhandled packets will be saved.", prefs, dests)

	if unhandled_handler.unhandled_h is not None:
		while True:
			try:
				out_rec = dests['unhandled'].get(block=True, timeout=None)
			except KeyboardInterrupt:
				break
			else:
				if out_rec is None:
					break
				if out_rec not in unhandled_handler.packets_saved:
					unhandled_handler.packets_saved.append(out_rec)
					unhandled_handler.unhandled_h.write(out_rec)

	debug_out('Exiting unhandled', prefs, dests)



def suspicious_handler(sh_da, prefs, dests):
	"""Save all suspicious packets supplied by the other processes."""

	os.nice(nice_raise)							#Lower priority to give higher priority to critical tasks
	debug_out(whatami('suspicious'), prefs, dests)

	if "packets_saved" not in suspicious_handler.__dict__:
		suspicious_handler.packets_saved = []

	if "suspicious_h" not in suspicious_handler.__dict__:
		suspicious_handler.suspicious_h = None
		if prefs['suspicious']:
			try:
				suspicious_handler.suspicious_h = PcapWriter(filename=prefs['suspicious'], append=True)
			except:
				debug_out("Unable to open " + prefs['suspicious'] + ", no suspicious packets will be saved.", prefs, dests)

	if suspicious_handler.suspicious_h is not None:
		while True:
			try:
				out_rec = dests['suspicious'].get(block=True, timeout=None)
			except KeyboardInterrupt:
				break
			else:
				if out_rec is None:
					break
				if out_rec not in suspicious_handler.packets_saved:
					suspicious_handler.packets_saved.append(out_rec)
					suspicious_handler.suspicious_h.write(out_rec)

	debug_out('Exiting suspicious', prefs, dests)



def ip_lookup_geoip_extract(ip_addr, prefs, dests):
	"""Lookup Geoip information about an IP address and return as a set of tuples."""

	state_set = set([])

	if "geo_reader" not in ip_lookup_geoip_extract.__dict__:
		ip_lookup_geoip_extract.geo_reader = geolite2.reader()

	if not ip_addr.startswith(('10.', '169.254.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.', '127.', 'fe80:')):
		geo_match = ip_lookup_geoip_extract.geo_reader.get(ip_addr)
		if geo_match:
			rec_type = "CC"

			Country = ""
			city_state = ""
			if "country" in geo_match and "names" in geo_match["country"] and "en" in geo_match["country"]["names"]:
				Country = geo_match["country"]["names"]["en"]

			if "subdivisions" in geo_match:			#This is a list.
				city_state = "/"
				for one_subdiv in geo_match['subdivisions']:
					if "names" in one_subdiv and "en" in one_subdiv["names"]:
						city_state = "/" + one_subdiv["names"]["en"]
						rec_type = "CSC"
						break				#Stop looking through the geo_match['subdivisions'] list once we've found one.

			if "city" in geo_match and "names" in geo_match["city"] and "en" in geo_match["city"]["names"]:
				city_state = city_state + "/" + geo_match["city"]["names"]["en"]
				rec_type = "CSC"
			else:
				city_state = city_state + "/"

			if "country" in geo_match and "iso_code" in geo_match["country"]:
				if rec_type == 'CC':
					state_set.add(("GE", ip_addr, rec_type, geo_match["country"]["iso_code"], Country, ()))
				else:
					state_set.add(("GE", ip_addr, rec_type, geo_match["country"]["iso_code"], Country + city_state, ()))

	return state_set



def ip_lookup_geoip_handler(ip_lookup_geoip_q, sh_da, prefs, dests):
	"""Lookup Geoip information about IP addresses."""

	if prefs['active'] and prefs['geolite_loaded']:
		os.nice(nice_raise+2)							#Lower priority to give higher priority to critical tasks
		debug_out(whatami('ip_lookup_geoip'), prefs, dests)

		if "ips_researched" not in ip_lookup_geoip_handler.__dict__:
			ip_lookup_geoip_handler.ips_researched = ['', '0.0.0.0', '::', '0000:0000:0000:0000:0000:0000:0000:0000']	#No point in looking these up

		while True:
			try:
				out_rec = ip_lookup_geoip_q.get(block=True, timeout=None)
			except KeyboardInterrupt:
				break
			else:
				if out_rec is None:
					break
				out_rec = explode_ip(out_rec, prefs, dests)

				if out_rec not in ip_lookup_geoip_handler.ips_researched:
					ip_lookup_geoip_handler.ips_researched.append(out_rec)

					for statement in ip_lookup_geoip_extract(out_rec, prefs, dests):
						dests['output'].put(statement)

					Progress('g')

		debug_out('Exiting ip_lookup_geoip', prefs, dests)
	elif prefs['active'] and not prefs['geolite_loaded']:
		debug_out('Unable to load geolite2 module, exiting ip_lookup_geoip', prefs, dests)



def ip_lookup_asn_extract(ip_addr, prefs, dests):
	"""Lookup ASN information about an IP address and return as a set of tuples."""

	state_set = set([])

	if "as_nums" not in ip_lookup_asn_extract.__dict__:
		ip_lookup_asn_extract.as_nums = {}

	if "asn_countries" not in ip_lookup_asn_extract.__dict__:
		ip_lookup_asn_extract.asn_countries = {}

	if "asn_descriptions" not in ip_lookup_asn_extract.__dict__:
		ip_lookup_asn_extract.asn_descriptions = {}
		#script_dir = os.path.dirname(os.path.abspath(__file__))
		if os.path.exists(config_dir + '/ip2asn-combined.tsv') and os.access(config_dir + '/ip2asn-combined.tsv', os.R_OK):
			ip_lookup_asn_extract.as_nums, ip_lookup_asn_extract.asn_countries, ip_lookup_asn_extract.asn_descriptions = load_asn_table(config_dir + '/ip2asn-combined.tsv')
		else:
			debug_out(config_dir + '/ip2asn-combined.tsv either does not exist or is not readable, please download from https://iptoasn.com/data/ip2asn-combined.tsv.gz and decompress with gunzip.', prefs, dests)
		#elif os.path.exists(script_dir + '/ip2asn-combined.tsv'):
		#	ip_lookup_asn_extract.as_nums, ip_lookup_asn_extract.asn_countries, ip_lookup_asn_extract.asn_descriptions = load_asn_table(script_dir + '/ip2asn-combined.tsv')
		#elif os.path.exists('./ip2asn-combined.tsv'):
		#	ip_lookup_asn_extract.as_nums, ip_lookup_asn_extract.asn_countries, ip_lookup_asn_extract.asn_descriptions = load_asn_table('./ip2asn-combined.tsv')

	if not ip_addr.startswith(('10.', '169.254.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.', '127.', 'fe80:')):
		for one_d in formatted_asn_output(ip_addr, 'json', ip_lookup_asn_extract.as_nums, ip_lookup_asn_extract.asn_countries, ip_lookup_asn_extract.asn_descriptions):
			state_set.add((one_d['Type'], one_d['IPAddr'], one_d['Proto'], one_d['State'], one_d['Description'], ()))

	return state_set



def ip_lookup_asn_handler(ip_lookup_asn_q, sh_da, prefs, dests):
	"""Lookup ASN information about IP addresses."""

	if prefs['active'] and prefs['ip2asn_loaded']:
		os.nice(nice_raise+2)							#Lower priority to give higher priority to critical tasks
		debug_out(whatami('ip_lookup_asn'), prefs, dests)

		if "ips_researched" not in ip_lookup_asn_handler.__dict__:
			ip_lookup_asn_handler.ips_researched = ['', '0.0.0.0', '::', '0000:0000:0000:0000:0000:0000:0000:0000']	#No point in looking these up

		while True:
			try:
				out_rec = ip_lookup_asn_q.get(block=True, timeout=None)
			except KeyboardInterrupt:
				break
			else:
				if out_rec is None:
					break
				out_rec = explode_ip(out_rec, prefs, dests)

				if out_rec not in ip_lookup_asn_handler.ips_researched:
					ip_lookup_asn_handler.ips_researched.append(out_rec)

					for statement in ip_lookup_asn_extract(out_rec, prefs, dests):
						dests['output'].put(statement)

					Progress('a')

		debug_out('Exiting ip_lookup_asn', prefs, dests)
	elif prefs['active'] and not prefs['ip2asn_loaded']:
		debug_out('Unable to load ip2asn module, exiting ip_lookup_asn', prefs, dests)




def ip_lookup_hostname_extract(ip_addr, prefs, dests):
	"""Lookup hostnames for an IP address and return as a set of tuples."""

	state_set = set([])

	try:
		r_name, _, _ = socket.gethostbyaddr(ip_addr)		#Don't need params 2 and 3, r_alias, r_addresslist
	except (socket.herror, socket.gaierror, KeyboardInterrupt, OSError):
		pass
	else:
		if r_name:
			if not r_name.endswith("."):
				r_name += '.'
			state_set.add(("DN", ip_addr, "PTR", r_name, "", ()))

	return state_set



def ip_lookup_hostname_handler(ip_lookup_hostname_q, sh_da, prefs, dests):
	"""Lookup hostname information about IP addresses."""

	if prefs['active']:
		os.nice(nice_raise+2)							#Lower priority to give higher priority to critical tasks
		debug_out(whatami('ip_lookup_hostname'), prefs, dests)

		if "ips_researched" not in ip_lookup_hostname_handler.__dict__:
			ip_lookup_hostname_handler.ips_researched = ['', '0.0.0.0', '::', '0000:0000:0000:0000:0000:0000:0000:0000']	#No point in looking these up

		#Code left in in case we switch to dnspython/dns.resolver
		#if "unhandled_h" not in unhandled_handler.__dict__:
		#	unhandled_handler.unhandled_h = None
		#	if prefs['unhandled']:
		#		try:
		#			unhandled_handler.unhandled_h = PcapWriter(filename=prefs['unhandled'], append=True)
		#		except:
		#			debug_out("Unable to open " + prefs['unhandled'] + ", no unhandled packets will be saved.", prefs, dests)

		#if unhandled_handler.unhandled_h is not None:
		while True:
			try:
				out_rec = ip_lookup_hostname_q.get(block=True, timeout=None)
			except KeyboardInterrupt:
				break
			else:
				if out_rec is None:
					break
				out_rec = explode_ip(out_rec, prefs, dests)

				if out_rec not in ip_lookup_hostname_handler.ips_researched:
					ip_lookup_hostname_handler.ips_researched.append(out_rec)

					for statement in ip_lookup_hostname_extract(out_rec, prefs, dests):
						dests['output'].put(statement)

					Progress('i')

		debug_out('Exiting ip_lookup_hostname', prefs, dests)



def ip_lookup_traceroute_extract(ip_addr, prefs, dests):
	"""Lookup any information about an IP address and return as a set of tuples."""

	if "ips_researched" not in ip_lookup_traceroute_extract.__dict__:
		ip_lookup_traceroute_extract.ips_researched = ['', '0.0.0.0', '::', '0000:0000:0000:0000:0000:0000:0000:0000', '255.255.255.255']	#No point in looking these up


	state_set = set([])

	if ip_addr and not ip_addr.startswith(('127.', '169.254.', 'fe80:', 'FE80:')) and (ip_addr not in ip_lookup_traceroute_extract.ips_researched) and ((':' not in ip_addr) or (prefs['trace_v6'])):
		ip_lookup_traceroute_extract.ips_researched.append(ip_addr)

		try:
			compressed_path_to_ip = traceroute_hop_list(ip_addr, prefs['forced_interface'], prefs['per_packet_timeout'], prefs['hop_limit'], "")
		except:
			raise

		path_to_ip = []
		for one_hop in compressed_path_to_ip:
			if one_hop is None or ':' not in one_hop:
				path_to_ip.append(one_hop)
			else:
				path_to_ip.append(explode_ip(one_hop, prefs, dests))


		for i in range(len(path_to_ip)-1):
			#path_to_ip[i] path_to_ip[i+1] are consecutive pairs of hosts on the way to the target ip.  Either or both may be None (means no response at this TTL).
			if path_to_ip[i] and path_to_ip[i+1] and path_to_ip[i] != path_to_ip[i+1]:
				#Both are actual IP addresses.
				state_set.add(("PE", path_to_ip[i], "traceroute", "precedes", path_to_ip[i+1], ()))
				state_set.add(("PE", path_to_ip[i+1], "traceroute", "is_beyond", path_to_ip[i], ()))

		for i in range(1, len(path_to_ip)-1):									#Register all the middle IPs...
			if path_to_ip[i]:										#...that responded...
				state_set.add(("RO", path_to_ip[i], "TTLEx", "router", "", ()))				#...as routers.

		if path_to_ip[-1]:											#If we got a response as the last entry in the list...
			state_set.add(("US", path_to_ip[-1], "UDP_33434", "closed", "udptraceroute/server", ()))	#...tag it as a traceroute responder

		for one_hop in path_to_ip:
			if one_hop and one_hop not in ip_lookup_traceroute_extract.ips_researched:
				ip_lookup_traceroute_extract.ips_researched.append(one_hop)				#We add all the IPs on the way to the target as "researched" as we just effectively tracerouted to the intermediate routers as well.

	return state_set



def ip_lookup_traceroute_handler(ilth_name, ip_lookup_traceroute_q, sh_da, prefs, dests):
	"""Lookup any additional information about IP addresses."""
	#ilth_name is the unique name for this process, such as ip_lookup_traceroute_2

	if prefs['active'] and prefs['scapy_traceroute_loaded']:
		os.nice(nice_raise+2)							#Lower priority to give higher priority to critical tasks
		debug_out(whatami(ilth_name), prefs, dests)

		while True:
			try:
				out_rec = ip_lookup_traceroute_q.get(block=True, timeout=None)
			except KeyboardInterrupt:
				break
			else:
				if out_rec is None:
					break
				out_rec = explode_ip(out_rec, prefs, dests)

				if not out_rec.startswith(('127.')):
					for statement in ip_lookup_traceroute_extract(out_rec, prefs, dests):
						dests['output'].put(statement)

					Progress('r')

		debug_out('Exiting ' + ilth_name, prefs, dests)
	elif prefs['active'] and not prefs['scapy_traceroute_loaded']:
		debug_out('Unable to load scapy_traceroute module, exiting ' + ilth_name, prefs, dests)



def host_lookup_extract(host_name, prefs, dests):
	"""Lookup any information about a host and return as a set of tuples."""

	state_set = set([])

	if host_name:
		if not host_name.endswith("."):
			host_name += '.'

		try:
			for one_result in socket.getaddrinfo(host_name, None, socket.AF_INET):
				af, _, _, _, sa = one_result				#Don't need socktype, proto, canonname

				if af == socket.AF_INET:
					state_set.add(("DN", explode_ip(sa[0], prefs, dests), "A", host_name, "", ()))
				elif af == socket.AF_INET6:
					state_set.add(("DN", explode_ip(sa[0], prefs, dests), "AAAA", host_name, "", ()))
				else:
					pass
		except (socket.gaierror, KeyboardInterrupt, UnicodeError):
			return state_set

		try:
			for one_result in socket.getaddrinfo(host_name, None, socket.AF_INET6):
				af, _, _, _, sa = one_result				#Don't need socktype, proto, canonname

				if af == socket.AF_INET:
					state_set.add(("DN", explode_ip(sa[0], prefs, dests), "A", host_name, "", ()))
				elif af == socket.AF_INET6:
					state_set.add(("DN", explode_ip(sa[0], prefs, dests), "AAAA", host_name, "", ()))
				else:
					pass
		except (socket.gaierror, KeyboardInterrupt, UnicodeError):
			return state_set


		#try:
		#	resolved_ip_addr = socket.gethostbyname(host_name)
		#except:
		#	pass
		#else:
		#if resolved_ip_addr:
		#	state_set.add(("DN", explode_ip(resolved_ip_addr, prefs, dests), "A", host_name, "", ()))

	return state_set



def host_lookup_handler(host_lookup_q, sh_da, prefs, dests):
	"""Lookup any additional information about hostnames."""

	if prefs['active']:
		os.nice(nice_raise+2)							#Lower priority to give higher priority to critical tasks
		debug_out(whatami('host_lookup'), prefs, dests)

		if "ips_researched" not in host_lookup_handler.__dict__:
			host_lookup_handler.ips_researched = []

		#Code left in in case we switch to dnspython/dns.resolver
		#if "unhandled_h" not in unhandled_handler.__dict__:
		#	unhandled_handler.unhandled_h = None
		#	if prefs['unhandled']:
		#		try:
		#			unhandled_handler.unhandled_h = PcapWriter(filename=prefs['unhandled'], append=True)
		#		except:
		#			debug_out("Unable to open " + prefs['unhandled'] + ", no unhandled packets will be saved.", prefs, dests)

		#if unhandled_handler.unhandled_h is not None:
		while True:
			try:
				out_rec = host_lookup_q.get(block=True, timeout=None)
			except KeyboardInterrupt:
				break
			else:
				if out_rec is None:
					break
				if out_rec not in host_lookup_handler.ips_researched:
					host_lookup_handler.ips_researched.append(out_rec)

					for statement in host_lookup_extract(out_rec, prefs, dests):
						dests['output'].put(statement)
					Progress('h')

		debug_out('Exiting host_lookup', prefs, dests)



#def template_handler(task_q, sh_da, prefs, dests):
#	"""Extracts all needed information from the template layer."""
#
#	os.nice(nice_raise + 2)							#Lower priority to give higher priority to critical tasks
#	debug_out(whatami('template'), prefs, dests)
#
#	while True:
#		try:
#			(p, meta) = task_q.get(block=True, timeout=None)
#		except KeyboardInterrupt:
#			break
#		else:

#			if p is None:
#				break
#			#Do processing here
#			#p.show()
#			#dests['output'].put('template processed: ' + str(p) + '/' + str(meta))
#
#			for statement in template_extract(p, meta, prefs, dests):
#				dests['output'].put(statement)
#
#			Progress('template')
#
#	debug_out('Exiting template', prefs, dests)


def ARP_handler(task_q, sh_da, prefs, dests):
	"""Extracts all needed information from the ARP layer."""

	os.nice(nice_raise + 2)							#Lower priority to give higher priority to critical tasks
	debug_out(whatami('ARP'), prefs, dests)

	while True:
		try:
			(p, meta) = task_q.get(block=True, timeout=None)
		except KeyboardInterrupt:
			break
		else:
			if p is None:
				break
			for statement in ARP_extract(p, meta, prefs, dests):
				dests['output'].put(statement)

			Progress('A')

	debug_out('Exiting ARP', prefs, dests)



def IP_handler(task_q, sh_da, prefs, dests):
	"""Extracts all needed information from the IP layer."""

	os.nice(nice_raise)							#Lower priority to give higher priority to critical tasks
	debug_out(whatami('IP'), prefs, dests)

	while True:
		try:
			(p, meta) = task_q.get(block=True, timeout=None)
		except KeyboardInterrupt:
			break
		else:
			if p is None:
				break
			for statement in IP_extract(p, meta, prefs, dests):
				dests['output'].put(statement)

			#Progress('I')

	debug_out('Exiting IP', prefs, dests)



def TCP_handler(task_q, sh_da, prefs, dests):
	"""Extracts all needed information from the TCP layer."""

	os.nice(nice_raise)							#Lower priority to give higher priority to critical tasks
	debug_out(whatami('TCP'), prefs, dests)

	#No longer tracked here - see single_packet_handler
	#if 'ack_count' not in TCP_handler.__dict__:
	#	TCP_handler.ack_count = {}

	while True:
		try:
			(p, meta) = task_q.get(block=True, timeout=None)
		except KeyboardInterrupt:
			break
		else:
			if p is None:
				break

			#port_tuple = (meta['sIP'], meta['sport'], meta['dIP'], meta['dport'])
			#if port_tuple not in TCP_handler.ack_count:
			#	TCP_handler.ack_count[port_tuple] = 0

			#if (meta['flags'] & 0x17) == 0x10:	#ACK (RST, SYN, and FIN off)
			#	TCP_handler.ack_count[port_tuple] += 1
			#	if TCP_handler.ack_count[port_tuple] <= max_processed_acks:
			#		for statement in TCP_extract(p, meta, prefs, dests):
			#			dests['output'].put(statement)
			#		Progress('T')
			#	else:
			#		Progress('t')
			#else:
			for statement in TCP_extract(p, meta, prefs, dests):
				dests['output'].put(statement)
			Progress('T')

	debug_out('Exiting TCP', prefs, dests)


def UDP_handler(task_q, sh_da, prefs, dests):
	"""Extracts all needed information from the UDP layer."""

	os.nice(nice_raise + 2)							#Lower priority to give higher priority to critical tasks
	debug_out(whatami('UDP'), prefs, dests)

	while True:
		try:
			(p, meta) = task_q.get(block=True, timeout=None)
		except KeyboardInterrupt:
			break
		else:

			if p is None:
				break

			for statement in UDP_extract(p, meta, prefs, dests):
				dests['output'].put(statement)

			Progress('U')

	debug_out('Exiting UDP', prefs, dests)


def DNS_handler(task_q, sh_da, prefs, dests):
	"""Extracts all needed information from the DNS layer."""

	os.nice(nice_raise + 2)							#Lower priority to give higher priority to critical tasks
	debug_out(whatami('DNS'), prefs, dests)

	while True:
		try:
			(p, meta) = task_q.get(block=True, timeout=None)
		except KeyboardInterrupt:
			break
		except struct.error:								#We're getting odd unpacking errors here.
			pass
			#debug_out("DNS Unpacking error?", prefs, dests)
			##  File "/opt/local/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages/scapy/layers/dns.py", line 143, in decodeRR
			##type,cls,ttl,rdlen = struct.unpack("!HHIH", ret)
			##error: unpack requires a string argument of length 10
			#raise
		except ValueError:
			pass
			#File "/opt/local/Library/Frameworks/Python.framework/Versions/3.5/lib/python3.5/site-packages/scapy/layers/dns.py", line 337, in m2i
			#  s = inet_ntop(family, s)
			#File "/opt/local/Library/Frameworks/Python.framework/Versions/3.5/lib/python3.5/site-packages/scapy/pton_ntop.py", line 132, in inet_ntop
			#  return socket.inet_ntop(af, addr)
			#ValueError: invalid length of packed IP address string
		else:

			if p is None:
				break

			for statement in DNS_extract(p, meta, prefs, dests):
				dests['output'].put(statement)

			Progress('D')

	debug_out('Exiting DNS', prefs, dests)


def single_packet_handler(highpri_task_q, lowpri_task_q, sh_da, layer_qs, prefs, dests):		#pylint: disable=unused-argument
	"""This gets a single packet and doles it out to the available layers.  We totally drain the low priority queue before handling a single high priority packet, then go back to check the high priority queue."""

	if 'ack_count' not in single_packet_handler.__dict__:
		single_packet_handler.ack_count = {}

	exit_once_queues_drained = False

	debug_out(whatami('single_packet'), prefs, dests)
	#Layers that we won't send off for processing (though they may be used as part of processing their parent or other ancestor)
	nosubmit_layers = ('DHCP options', 'DHCP6 Client Identifier Option', 'DHCP6 Elapsed Time Option', 'DHCP6 Identity Association for Non-temporary Addresses Option', 'DHCP6 Option Request Option', 'Ethernet', 'ICMPv6 Neighbor Discovery Option - Prefix Information', 'ICMPv6 Neighbor Discovery Option - Recursive DNS Server Option', 'ICMPv6 Neighbor Discovery Option - Route Information Option', 'ICMPv6 Neighbor Discovery Option - Source Link-Layer Address', 'Padding', 'Raw')

	while True:
		#FIXME - the logic for when to exit is not correct.
		if exit_once_queues_drained and highpri_task_q.empty() and lowpri_task_q.empty():
			break

		while highpri_task_q.empty() and lowpri_task_q.empty():		#We only do this if there a _no packets at all_ waiting to be processed, so we should rarely hit this if ever.
			Progress('.')
			try:
				time.sleep(0.05)
			except KeyboardInterrupt:
				exit_once_queues_drained = True

		pkt = ''
		try:
			pkt = highpri_task_q.get(block=False, timeout=None)
			Progress('+')
		except Empty:
			try:
				pkt = lowpri_task_q.get(block=False, timeout=None)
				Progress('_')
			except Empty:
				pass

		if pkt is None or pkt == (None, None):
			exit_once_queues_drained = True
		elif pkt == '':							#Neither attempt to retrieve a packet passed, skip and try again.
			pass
		#We don't process ack packets past the first few .  Flags & 0x17 = 0x10 is ACK (RST, SYN, and FIN off):
		#We perform the check here to avoid any queue processing or generate_meta work
		elif pkt.haslayer('IP') and pkt.haslayer('TCP') and ((pkt['TCP'].flags & 0x17) == 0x10) and single_packet_handler.ack_count.get((pkt['IP'].src, pkt['TCP'].sport, pkt['IP'].dst, pkt['TCP'].dport), 0) > max_processed_acks:
			Progress('t')
		elif pkt.haslayer('IPv6') and pkt.haslayer('TCP') and ((pkt['TCP'].flags & 0x17) == 0x10) and single_packet_handler.ack_count.get((pkt['IPv6'].src, pkt['TCP'].sport, pkt['IPv6'].dst, pkt['TCP'].dport), 0) > max_processed_acks:
			Progress('t')
		else:
			packet_meta = generate_meta_from_packet(pkt, prefs, dests)

			if pkt.haslayer('TCP') and (packet_meta['flags'] & 0x17) == 0x10:	#ACK (RST, SYN, and FIN off)
				port_tuple = (packet_meta['sIP'], packet_meta['sport'], packet_meta['dIP'], packet_meta['dport'])
				if port_tuple not in single_packet_handler.ack_count:
					single_packet_handler.ack_count[port_tuple] = 0

				single_packet_handler.ack_count[port_tuple] += 1

			for packet_layer in packet_meta['pkt_layers']:
				if packet_layer in layer_qs:
					if layer_qs[packet_layer].full():
						debug_out(str(packet_layer) + ' layer is full.', prefs, dests)
					try:
						#FIXME if coming from a file, Block.  If coming from an interface, don't block.  ?
						layer_qs[packet_layer].put((pkt[packet_layer], packet_meta), block=False)		#COMMENT NOT CURRENTLY CORRECT: Default is block=True, timeout=None , so if the queue is full we'll get held up here until space is available.
					except Full:
						pass
				elif packet_layer not in nosubmit_layers:
					if Verbose:
						debug_out('\nMissing layer: ' + packet_layer, prefs, dests)
					else:
						debug_out('Missing layer: ' + packet_layer, prefs, dests)

	debug_out('Exiting single_packet', prefs, dests)



def packet_stream_processor(name_param, pcap_interface, pcap_source_file, highpri_single_packet_q, lowpri_single_packet_q, sh_da, prefs, dests):	#pylint: disable=unused-argument
	"""This starts a scapy.sniff() process on either an input file or interface (only request one, the other should be None).  Packets are handed off to single_packet_handler.  If both None, sniff from all interfaces."""

	#Note - we do not lower priority if sniffing from an interface, only if reading from a pcap file; see below for "nice" statement
	debug_out(whatami(name_param), prefs, dests)

	if pcap_interface and pcap_source_file:
		debug_out('Both pcap_interface: ' + str(pcap_interface) + ' and pcap_source_file: ' + str(pcap_source_file) + ' requested at the same time, exiting.', prefs, dests)
	elif pcap_interface:
		try:
			if prefs['bpf']:
				sniff(store=0, filter=prefs['bpf'], iface=pcap_interface, prn=highpri_single_packet_q.put)		#Default is block=True, timeout=None , so if the queue is full we'll get held up here until space is available.
			else:
				sniff(store=0, iface=pcap_interface, prn=highpri_single_packet_q.put)
			debug_out('Finished processing packets from ' + str(pcap_interface), prefs, dests)
		except Scapy_Exception:
			debug_out('Attempt to listen on an interface failed: are you running this as root or under sudo?', prefs, dests)
	elif pcap_source_file:
		os.nice(nice_raise + 2)												#Lower priority to give higher priority to critical tasks
		work_filename = None
		delete_temp = False

		if not os.path.exists(pcap_source_file):
			debug_out(pcap_source_file + ' does not exist, skipping.', prefs, dests)
		elif not os.access(pcap_source_file, os.R_OK):
			debug_out(pcap_source_file + ' is not readable, skipping.', prefs, dests)
		elif pcap_source_file.endswith('.bz2'):
			os.nice(4)											#Lower priority a little more for processing a compressed file
			work_filename = open_bzip2_file_to_tmp_file(pcap_source_file)
			delete_temp = True
		elif pcap_source_file.endswith('.gz'):
			os.nice(4)
			work_filename = open_gzip_file_to_tmp_file(pcap_source_file)
			delete_temp = True
		else:		#File exists and is neither a bzip2 file nor a gzip file.  Process as is.
			work_filename = pcap_source_file

		try:
			if prefs['bpf']:
				sniff(store=0, filter=prefs['bpf'], offline=work_filename, prn=lowpri_single_packet_q.put)	#Default is block=True, timeout=None , so if the queue is full we'll get held up here until space is available.
			else:
				sniff(store=0, offline=work_filename, prn=lowpri_single_packet_q.put)
		except Scapy_Exception:
			if delete_temp:
				debug_out('Error opening ' + pcap_source_file + ' (temp decompressed file: ' + work_filename + ' )', prefs, dests)
			else:
				debug_out('Error opening ' + pcap_source_file, prefs, dests)

		if delete_temp and work_filename != pcap_source_file and os.path.exists(work_filename):
			os.remove(work_filename)

		debug_out('Finished processing packets from ' + str(pcap_source_file), prefs, dests)
	else:		#Neither specified, so this means sniff from all interfaces
		try:
			if prefs['bpf']:
				sniff(store=0, filter=prefs['bpf'], prn=highpri_single_packet_q.put)
			else:
				sniff(store=0, prn=highpri_single_packet_q.put)
		except Scapy_Exception:
			debug_out('Attempt to listen on all interfaces failed: are you running this as root or under sudo?', prefs, dests)
			raise
		debug_out('Finished processing packets from ANY', prefs, dests)



if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(description='Passer version ' + str(p_test_version))
	parser.add_argument('-i', '--interface', help='Interface(s) from which to read packets (default is all interfaces)', required=False, default=[], nargs='*')
	#parser.add_argument('-r', '--read', help='Pcap file(s) from which to read packets (use   -   for stdin)', required=False, default=[], nargs='*')	#Not supporting stdin at the moment
	parser.add_argument('-r', '--read', help='Pcap file(s) from which to read packets', required=False, default=[], nargs='*')
	parser.add_argument('-l', '--log', help='File to which to write output csv lines', required=False, default=None)
	parser.add_argument('-s', '--suspicious', help='File to which to write packets to/from suspicious IPs', required=False, default=None)
	parser.add_argument('-u', '--unhandled', help='File to which to write unhandled packets', required=False, default=None)
	#parser.add_argument('--acks', help='Save unhandled ack packets as well', required=False, default=False, action='store_true')
	parser.add_argument('-d', '--devel', help='Enable development/debug statements', required=False, default=False, action='store_true')
	parser.add_argument('-q', '--quit', help='With -d, force passer to quit when debug packets are shown', required=False, default=False, action='store_true')
	parser.add_argument('--nxdomain', help='Show NXDomain DNS answers', required=False, default=False, action='store_true')
	#parser.add_argument('--creds', help='Show credentials as well', required=False, default=False, action='store_true')
	parser.add_argument('-b', '--bpf', help='BPF to restrict which packets are processed', required=False, default='')
	#parser.add_argument('--debuglayers', required=False, default=False, action='store_true', help=argparse.SUPPRESS)						#Debug scapy layers, hidden option
	parser.add_argument('-a', '--active', help='Perform active scanning to look up additional info', required=False, default=False, action='store_true')
	parser.add_argument('--forced_interface', help='Interface to which to write active scan packets (not needed on Linux)', required=False, default=None)
	parser.add_argument('-p', '--passive-fingerprinting', help='Enable Passive Fingerprinting Capabilities.', required=False, default=False, action='store_true')
	(parsed, unparsed) = parser.parse_known_args()
	cl_args = vars(parsed)

	cl_args['geolite_loaded'] = geolite_loaded
	cl_args['scapy_traceroute_loaded'] = scapy_traceroute_loaded
	cl_args['ip2asn_loaded'] = ip2asn_loaded

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

	#Not currently offered as actual user-supplied parameters, but could easily be done so
	cl_args['per_packet_timeout'] = 1		#_Could_ shorten this to speed up traceroutes, but if too low we may miss responses.  Better to have more parallel traceroutes, below.
	cl_args['hop_limit'] = 30
	cl_args['trace_v6'] = True
	cl_args['max_traceroutes'] = 4

	mkdir_p(config_dir)
	mkdir_p(cache_dir)
	mkdir_p(cache_dir + '/ipv4/')
	mkdir_p(cache_dir + '/ipv6/')
	mkdir_p(cache_dir + '/dom/')

	# If Passive Finger Printing Capability is enabled.
	if cl_args['passive_fingerprinting']:
		passive_data.setup_db()
		conn = passive_data.create_con()
		if passive_data.test_github_con():
			tcp_sig_data = pull_data.import_data()

   			# Iterate over JSON Objects
			for i in tcp_sig_data['signature_list']:
				try:
					signature = tcp_sig(i)
					author_id = passive_data.author_insert(conn, signature.author, signature.author_email, signature.author_github)
					os_id = passive_data.os_insert(conn, signature.os_name, signature.os_version, signature.os_class, signature.os_vendor, signature.os_url)
					device_id = passive_data.device_insert(conn, signature.device_type, signature.device_vendor, signature.device_url)
					passive_data.signature_insert(conn, signature.sig_acid, signature.sig_tcp_flag, signature.signature['ver'], signature.signature['ittl'], signature.signature['olen'], signature.signature['mss'], signature.signature['wsize'], signature.signature['scale'], signature.signature['olayout'], signature.signature['quirks'], signature.signature['pclass'], signature.sig_comments, os_id, device_id, author_id)
				except Exception as e:
					print(e)


	mgr = Manager()				#This section sets up a shared data dictionary; all items in it must be Manager()-based shared data structures
	shared_data = {}
	shared_data['suspects'] = mgr.dict()

	destinations = {}		#These allow us to pass down queues to lower level functions
	destinations['output'] = multiprocessing.Queue(maxsize=output_qsz)
	destinations['unhandled'] = multiprocessing.Queue(maxsize=unhandled_qsz)
	destinations['suspicious'] = multiprocessing.Queue(maxsize=unhandled_qsz)
	if cl_args['active']:
		destinations['ip_lookup_asn'] = multiprocessing.Queue(maxsize=ip_lookup_qsz)
		destinations['ip_lookup_geoip'] = multiprocessing.Queue(maxsize=ip_lookup_qsz)
		destinations['ip_lookup_hostname'] = multiprocessing.Queue(maxsize=ip_lookup_qsz)
		destinations['ip_lookup_traceroute'] = multiprocessing.Queue(maxsize=ip_lookup_qsz)
		destinations['host_lookup'] = multiprocessing.Queue(maxsize=host_lookup_qsz)
	#FIXME - removeme
	#else:
	#	destinations['ip_lookup_asn'] = multiprocessing.Queue(maxsize=2)
	#	destinations['ip_lookup_geoip'] = multiprocessing.Queue(maxsize=2)
	#	destinations['ip_lookup_hostname'] = multiprocessing.Queue(maxsize=2)
	#	destinations['ip_lookup_traceroute'] = multiprocessing.Queue(maxsize=2)
	#	destinations['host_lookup'] = multiprocessing.Queue(maxsize=2)

	output_p = Process(name='output_p', target=output_handler, args=(shared_data, cl_args, destinations))
	output_p.start()

	debug_out(whatami('main'), cl_args, destinations)

	unhandled_p = Process(name='unhandled_p', target=unhandled_handler, args=(shared_data, cl_args, destinations))
	unhandled_p.start()

	suspicious_p = Process(name='suspicious_p', target=suspicious_handler, args=(shared_data, cl_args, destinations))
	suspicious_p.start()

	if cl_args['active']:
		ip_lookup_asn_p = Process(name='ip_lookup_asn_p', target=ip_lookup_asn_handler, args=(destinations['ip_lookup_asn'], shared_data, cl_args, destinations))
		ip_lookup_asn_p.start()

		ip_lookup_geoip_p = Process(name='ip_lookup_geoip_p', target=ip_lookup_geoip_handler, args=(destinations['ip_lookup_geoip'], shared_data, cl_args, destinations))
		ip_lookup_geoip_p.start()

		ip_lookup_hostname_p = Process(name='ip_lookup_hostname_p', target=ip_lookup_hostname_handler, args=(destinations['ip_lookup_hostname'], shared_data, cl_args, destinations))
		ip_lookup_hostname_p.start()

		ip_lookup_traceroute_p = [None] * cl_args['max_traceroutes']
		for tr_index in list(range(0, cl_args['max_traceroutes'])):
			ip_lookup_traceroute_p[tr_index] = Process(name='ip_lookup_traceroute_p' + str(tr_index), target=ip_lookup_traceroute_handler, args=('ip_lookup_traceroute_' + str(tr_index), destinations['ip_lookup_traceroute'], shared_data, cl_args, destinations))
			ip_lookup_traceroute_p[tr_index].start()

		host_lookup_p = Process(name='host_lookup_p', target=host_lookup_handler, args=(destinations['host_lookup'], shared_data, cl_args, destinations))
		host_lookup_p.start()

	layer_queues = {}

	#layer_queues['template'] = multiprocessing.Queue(maxsize=max_handler_qsz)
	#template_p = Process(name='template_p', target=template_handler, args=(layer_queues['template'], shared_data, cl_args, destinations))
	#template_p.start()

	layer_queues['ARP'] = multiprocessing.Queue(maxsize=max_handler_qsz)
	ARP_p = Process(name='ARP_p', target=ARP_handler, args=(layer_queues['ARP'], shared_data, cl_args, destinations))
	ARP_p.start()

	layer_queues['IP'] = multiprocessing.Queue(maxsize=max_handler_qsz)
	IP_p = Process(name='IP_p', target=IP_handler, args=(layer_queues['IP'], shared_data, cl_args, destinations))
	IP_p.start()

	layer_queues['TCP'] = multiprocessing.Queue(maxsize=max_handler_qsz)
	TCP_p = Process(name='TCP_p', target=TCP_handler, args=(layer_queues['TCP'], shared_data, cl_args, destinations))
	TCP_p.start()

	layer_queues['UDP'] = multiprocessing.Queue(maxsize=max_handler_qsz)
	UDP_p = Process(name='UDP_p', target=UDP_handler, args=(layer_queues['UDP'], shared_data, cl_args, destinations))
	UDP_p.start()

	layer_queues['DNS'] = multiprocessing.Queue(maxsize=max_handler_qsz)
	DNS_p = Process(name='DNS_p', target=DNS_handler, args=(layer_queues['DNS'], shared_data, cl_args, destinations))
	DNS_p.start()

	#Note that single_packet_handler not only reads from highpri_single_packet_queue and lowpri_single_packet_queue but also writes to one or the other when nested packets are found.  Consider deadlocks.
	highpri_single_packet_queue = multiprocessing.Queue(maxsize=highpri_packet_qsz)
	lowpri_single_packet_queue = multiprocessing.Queue(maxsize=lowpri_packet_qsz)
	layer_queues['single_packet_high'] = highpri_single_packet_queue	#At the moment we only use this for shutdown, so we don't have to add both queues
	single_packet_p = Process(name='single_packet_p', target=single_packet_handler, args=(highpri_single_packet_queue, lowpri_single_packet_queue, shared_data, layer_queues, cl_args, destinations))
	single_packet_p.start()

	#All _handler processes should be started above before any packet_stream_processor(s) are started below.
	all_packet_stream_processors = []
	for one_interface in cl_args['interface']:
		new_psp = Process(name='packet_stream_processor_p', target=packet_stream_processor, args=('packet_stream_processor_interface_' + str(one_interface), one_interface, None, highpri_single_packet_queue, lowpri_single_packet_queue, shared_data, cl_args, destinations))
		new_psp.start()
		all_packet_stream_processors.append(new_psp)

	if cl_args['interface'] == [] and cl_args['read'] == []:
		#If the user didn't specify any files or interfaces to read from, read from all interfaces.
		new_psp = Process(name='packet_stream_processor_p', target=packet_stream_processor, args=('packet_stream_processor_interface_ANY', None, None, highpri_single_packet_queue, lowpri_single_packet_queue, shared_data, cl_args, destinations))
		new_psp.start()
		all_packet_stream_processors.append(new_psp)

	for one_file in cl_args['read']:
		if os.path.exists(one_file):
			if os.access(one_file, os.R_OK):
				new_psp = Process(name='packet_stream_processor_p', target=packet_stream_processor, args=('packet_stream_processor_file_' + os.path.split(one_file)[1], None, one_file, highpri_single_packet_queue, lowpri_single_packet_queue, shared_data, cl_args, destinations))
				new_psp.start()
				all_packet_stream_processors.append(new_psp)
			else:
				debug_out(str(one_file) + ' unreadable.', cl_args, destinations)
		else:
			debug_out('Cannot find ' + str(one_file), cl_args, destinations)

	try:
		#Wait until all packet sources finish:
		for one_p in all_packet_stream_processors:
			one_p.join()
	except KeyboardInterrupt:
		pass

	#Shutdown other processes by submitting None to their respective input queues.  Ideally this should be done starting with the processes that feed queues, then moving down the handler list.
	for shutdown_layer in layer_queues:
		layer_queues[shutdown_layer].put((None, None))
	for one_q in ('ip_lookup_asn', 'ip_lookup_geoip', 'ip_lookup_hostname', 'host_lookup'):
		if one_q in destinations:
			destinations[one_q].put(None)

	if 'ip_lookup_traceroute' in destinations:				#Because we start multiple traceroutes, we have to queue a "None" shutdown signal for each
		for tr_index in list(range(0, cl_args['max_traceroutes'])):
			destinations['ip_lookup_traceroute'].put(None)


	#Wait until all other processes finish:
	#template_p.join()
	ARP_p.join()
	IP_p.join()
	TCP_p.join()
	UDP_p.join()
	DNS_p.join()
	single_packet_p.join()

	time.sleep(1)
	destinations['output'].put(None)
	if 'unhandled' in destinations:
		destinations['unhandled'].put(None)
	if 'suspicious' in destinations:
		destinations['suspicious'].put(None)

	sys.stderr.write('\nDone.\n')
