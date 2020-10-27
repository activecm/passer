#!/usr/bin/python
"""Converts ip addresses (ipv4 or ipv6) on stdin to fully exploded ip addresses."""

import ipaddress
import sys


Devel = False


def Debug(DebugStr):
	"""Prints a note to stderr"""
	if Devel != False:
		sys.stderr.write(DebugStr + '\n')


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
				if Devel:
					Debug(raw_addr_string)
					raise
				else:
					pass

	return ip_obj


def explode_ip(ip_obj):
	"""Converts the input IP object to its exploded form (type "unicode" in python2) ready for printing.  If the IP/IP object is invalid, returns an empty string."""

	if ip_obj is None:
		return ''
	else:
		return ip_obj.exploded



if __name__ == "__main__":
	AllSucceeded = True

	for InLine in sys.stdin:
		InLine = InLine.replace('\n', '').replace('\r', '')
		#Debug('======== ' + InLine)
		user_ip_obj = ip_addr_obj(InLine)

		if user_ip_obj is None:
			AllSucceeded = False
			if Devel:
				print('Invalid: ' + InLine)
			else:
				print('')
		else:
			print(explode_ip(user_ip_obj))

		#If not interested in detailed error checking, can also do:
		#print(explode_ip(ip_addr_obj(InLine)))


	if AllSucceeded:
		quit(0)
	else:
		Debug('One or more input lines were not recognized as cidr networks or hosts')
		quit(1)
