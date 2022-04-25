#!/usr/bin/env python3
"""Traceroute to a remote host and return the list of IPs transited (specific entries in that list may be None if no reply from that hop).
In the case of an error such as an unresolvable target hostname, a list of (30, by default) Nones will come back."""
#Program works fine under python2 and python3.
#Many thanks to https://jvns.ca/blog/2013/10/31/day-20-scapy-and-traceroute/ for the initial idea.

__version__ = '0.3.2'

__author__ = 'William Stearns'
__copyright__ = 'Copyright 2018-2022, William Stearns'
__credits__ = ['William Stearns']
__email__ = 'william.l.stearns@gmail.com'
__license__ = 'GPL 3.0'
__maintainer__ = 'William Stearns'
__status__ = 'Production'				#Prototype, Development or Production


import os
import sys
import socket
import random
import json
import ipaddress
import errno
#from scapy.all import *
from scapy.all import ICMP, ICMPv6TimeExceeded, IP, IPv6, Raw, Scapy_Exception, UDP, sr1	# pylint: disable=no-name-in-module
sys.path.insert(0, os.getcwd())
from db_lib import add_to_db_list				# pylint: disable=wrong-import-position
								#Sqlite3 database library


def ip_addr_obj(raw_addr):
	"""Returns an ip obj for the input string.  The raw_addr string should already have leading and trailing whitespace removed before being handed to this function."""

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
				#if Devel:
				#	Debug(raw_addr_string)
				#	raise
				#else:
				pass

	return ip_obj


def explode_ip(ip_obj):
	"""Converts the input IP object to its exploded form (type "unicode" in python2) ready for printing.  If the IP/IP object is invalid, returns an empty string."""

	if ip_obj is None:				# pylint: disable=no-else-return
		return ''
	else:
		return ip_obj.exploded


def is_valid_ipv4_address(address):
	"""Returns True or False based on whether the address is a valid IPv4 address."""

	try:
		socket.inet_pton(socket.AF_INET, address)
	except AttributeError:
		try:
			socket.inet_aton(address)
		except socket.error:
			return False
		return address.count('.') == 3
	except socket.error:  # not a valid address
		return False

	return True


def is_valid_ipv6_address(address):
	"""Returns True or False based on whether the address is a valid IPv6 address."""

	try:
		socket.inet_pton(socket.AF_INET6, address)
	except socket.error:  # not a valid address
		return False
	return True


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


def write_object(filename, generic_object):
	"""Write out an object to a file."""

	try:
		with open(filename, "wb") as write_h:
			write_h.write(generic_object.encode('utf-8'))
	except:
		sys.stderr.write("Problem writing " + filename + ", skipping.")
		raise

	#return


def mkdir_p(path):
	"""Create an entire directory branch.  Will not complain if the directory already exists."""

	if not os.path.isdir(path):
		try:
			os.makedirs(path)
		except FileExistsError:
			pass
		except OSError as exc:
			if exc.errno == errno.EEXIST and os.path.isdir(path):
				pass
			else:
				raise


def cache_file(parent_cache_dir, ip_addr):
	"""Returns the correct filename that would hold the path to that IP.  Does not care if the file exists or not, but does create the directory that would hold it."""

	if ':' in ip_addr:				#ipv6 address
		cache_obj_path = parent_cache_dir + '/ipv6/' + '/'.join(ip_addr.split(':')) + '/'
	else:						#ipv4 address
		cache_obj_path = parent_cache_dir + '/ipv4/' + '/'.join(ip_addr.split('.')) + '/'

	mkdir_p(cache_obj_path)

	return cache_obj_path + ip_addr + '.traceroute.json'


def ips_of(one_target):
	"""Finds a list of IP addresses of the given target, which could be a hostname, an IPv4 address, or an IPv6 address."""

	ip_list = set([])

	if is_valid_ipv4_address(one_target):
		ip_list.add(one_target)
	elif is_valid_ipv6_address(one_target):
		ip_list.add(explode_ip(ip_addr_obj(one_target)))
	else:
		if not one_target.endswith("."):
			one_target += '.'

		try:
			for one_result in socket.getaddrinfo(one_target, None, socket.AF_INET):
				af, _, _, _, sa = one_result				#Don't need socktype, proto, canonname

				if af == socket.AF_INET:
					ip_list.add(sa[0])
				elif af == socket.AF_INET6:
					ip_list.add(explode_ip(ip_addr_obj(sa[0])))
				else:
					sys.stderr.write(str(af) + '\n')
					#pass
		except (socket.gaierror, KeyboardInterrupt, UnicodeError):
			return ip_list

		try:
			for one_result in socket.getaddrinfo(one_target, None, socket.AF_INET6):
				af, _, _, _, sa = one_result				#Don't need socktype, proto, canonname

				if af == socket.AF_INET:
					ip_list.add(sa[0])
				elif af == socket.AF_INET6:
					ip_list.add(explode_ip(ip_addr_obj(sa[0])))
				else:
					sys.stderr.write(str(af) + '\n')
					#pass
		except (socket.gaierror, KeyboardInterrupt, UnicodeError):
			return ip_list

	return ip_list


def traceroute_hop_list(compressed_target, required_interface, max_packet_wait, max_hops, tr_cache_dir):			# pylint: disable=too-many-branches,too-many-statements
	"""Traceroute to the target IP address (NOT hostname) and return a list of all hops with their IPs (or None if no response)."""
	#If you have a hostname, use "for one_ip in ips_of(target_host):" around this function.
	#If tr_cache_dir is None, do not cache.  If tr_cache_dir is "", use traceroute_cache_dir_default .

	target = explode_ip(ip_addr_obj(compressed_target))

	hop_list = [None for j in range(max_hops)]
	loaded_cached_list = False

	if tr_cache_dir == "":
		tr_cache_dir = traceroute_cache_dir_default
	if tr_cache_dir:
		mkdir_p(tr_cache_dir)

		if os.path.exists(cache_file(tr_cache_dir, target)):
			#try:
			hop_list = load_json_from_file(cache_file(tr_cache_dir, target))
			loaded_cached_list = True
			#Umm, "try...except raise" doesn't actually change the default behaviour.
			#except:
			#	raise

	if not loaded_cached_list:
		flowlabel_value = random.randrange(1, 2**20)

		for i in range(0, max_hops):
			#sys.stderr.write('.')

			#payload_string = r"abcdefghijklmnopqrstuvwabcdefghi"	#Windows ICMP traceroute
			payload_string = r"@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_"	#Linux UDP traceroute

			pkt = None
			try:
				pkt = IP(dst=target, ttl=i)/UDP(sport=random.randrange(32768, 65534), dport=33434+i)/Raw(load=payload_string)
				address_layer = IP
				del pkt[IP].chksum
			except socket.gaierror:					#We weren't able to find an IPv4 address for this host, retry with IPv6
				try:
					pkt = IPv6(dst=target, hlim=i, fl=flowlabel_value)/UDP(sport=random.randrange(32768, 65534), dport=33434+i)/Raw(load=payload_string)
					address_layer = IPv6
					del pkt[IPv6].chksum
				except socket.gaierror:				#Couldn't find IPv6 either, so assume this is a nonexistant hostname.
					sys.stderr.write("No IP found for " + str(target) + ", exiting.\n")
					break
			del pkt[UDP].chksum

			reply = None
			if required_interface:
				try:
					reply = sr1(pkt, verbose=0, timeout=max_packet_wait, iface=required_interface)
				except Scapy_Exception:
					sys.stderr.write("Unable to write to " + str(required_interface) + ".  Are you running as root?  Exiting.\n")
					break
				except KeyError:
					pass
				except IndexError:		#Working around a bug in scapy's sendrecv.py/supersocket.py which gives an IndexError: pop from empty list
					pass
			else:
				try:
					reply = sr1(pkt, verbose=0, timeout=max_packet_wait)
				except KeyError:
					pass
				except IndexError:		#Working around a bug in scapy's sendrecv.py/supersocket.py which gives an IndexError: pop from empty list
					pass

			#sys.stderr.write("intermediate reply: " + str(reply) + '\n')
			#sys.stderr.flush()

			if reply is None:		#No response received
				pass			#No need to fill in, we already have None's there.
			elif reply.haslayer(ICMPv6TimeExceeded) or (reply.haslayer(ICMP) and reply[ICMP].type == 11):	#Intermediate host (Type is time-exceeded)
				hop_list[i] = explode_ip(ip_addr_obj(reply[address_layer].src))
			elif reply.haslayer('ICMPv6 Destination Unreachable') or (reply.haslayer(ICMP) and reply[ICMP].type == 3):	#Reached target (Type is dest-unreach)
				hop_list[i] = explode_ip(ip_addr_obj(reply[address_layer].src))
				del hop_list[i+1:]	#Truncate any following nulls
				break
			else:				#Unknown
				sys.stderr.write("Unknown reply type:\n")
				reply.show()
				break

		#sys.stderr.write('\n')

		try:
			write_object(cache_file(tr_cache_dir, target), json.dumps(hop_list))
		except:
			pass

		#Loop that truncates the list by one element, saves each sublist under the intermediate IP address (and mkdir_p that address too)
		truncated_path_to_ip = list(hop_list)		#Make a shallow copy of the list so we don't affect the original
		del truncated_path_to_ip[-1]			#Loop, dropping the rightmost entry each time.  Working back through the list of routers, save any that are actually routers for which we don't already have a path to that router.
		while truncated_path_to_ip:
			if truncated_path_to_ip[-1]:		#If not null, i.e., we have an actual router IP address:
				router_ip = truncated_path_to_ip[-1]
				if not os.path.exists(cache_file(tr_cache_dir, router_ip)):
					#sys.stderr.write("____ writing router path:" + router_ip + ":" + str(truncated_path_to_ip)
					#sys.stderr.flush
					try:
						write_object(cache_file(tr_cache_dir, router_ip), json.dumps(truncated_path_to_ip))
					except:
						pass
				add_to_db_list(ip_traceroutes, router_ip, json.dumps(truncated_path_to_ip))

			del truncated_path_to_ip[-1]
	add_to_db_list(ip_traceroutes, target, json.dumps(hop_list))


	return hop_list



per_packet_timeout_default = 1
forced_interface_default = None
ttl_default = 30
traceroute_cache_dir_default = os.environ["HOME"] + '/.cache/scapy_traceroute/'
ip_cache_dir_default = os.environ["HOME"] + '/.cache/ip/'

ip_cache_dir = ip_cache_dir_default
mkdir_p(ip_cache_dir)
ip_traceroutes = ip_cache_dir + 'ip_traceroutes.sqlite3'

if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(description='scapy_traceroute version ' + str(__version__))
	parser.add_argument('-p', '--per_packet_timeout', help='Time to wait for a reply for a single packet, can be fractional (default: ' + str(per_packet_timeout_default) + ' ).', required=False, default=per_packet_timeout_default)
	parser.add_argument('-f', '--forced_interface', help='Force packets through this interface (needed on macos, default: ' + str(forced_interface_default) + ' ).', required=False, default=forced_interface_default)
	parser.add_argument('-t', '--ttl', help='Maximum number of hops to try (default: ' + str(ttl_default) + ')', required=False, default=ttl_default)
	parser.add_argument('-c', '--cache_dir', help='Directory tree to hold cached traceroutes (default: ' + str(traceroute_cache_dir_default) + ' ).  Use None to not cache results.', required=False, default=traceroute_cache_dir_default)
	#parser.add_argument('--debug', help='Show additional debugging information on stderr', required=False, default=False, action='store_true')
	(parsed, unparsed) = parser.parse_known_args()
	cl_args = vars(parsed)

	for target_host in unparsed:
		for one_ip in ips_of(target_host):
			sys.stderr.write("==== Traceroute to: " + one_ip + '\n')
			sys.stderr.flush()
			print(traceroute_hop_list(one_ip, cl_args['forced_interface'], cl_args['per_packet_timeout'], int(cl_args['ttl']), cl_args['cache_dir']))
