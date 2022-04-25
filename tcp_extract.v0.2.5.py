#!/usr/bin/env python3
"""Listen for packets on an interface and do something with the TCP header fields on SYN packets."""
#Copyright 2018-2021 William Stearns <william.l.stearns@gmail.com>


__version__ = '0.2.5'

__author__ = 'William Stearns'
__copyright__ = 'Copyright 2018-2021, William Stearns'
__credits__ = ['William Stearns']
__email__ = 'william.l.stearns@gmail.com'
__license__ = 'GPL 3.0'
__maintainer__ = 'William Stearns'
__status__ = 'Prototype'				#Prototype, Development or Production


import os
import sys
from scapy.all import sniff, Raw, Scapy_Exception, IP, IPv6, TCP				# pylint: disable=no-name-in-module

def test_mss(MSS):
	'''Look for MSS in TCP Option.'''
	d = dict(MSS)
	try:
		return d['MSS']
	except:
		return '*'


def debug_out(output_string):
	"""Send debuging output to stderr."""
	if cl_args['devel']:
		sys.stderr.write(output_string + '\n')
		sys.stderr.flush()


def processpacket(p):
	"""Process a single packet; for this tool that means extracting the TCP fields and TCP payload and doing something with them."""


	if ((p.haslayer(IP) and p[IP].proto == 6) or (p.haslayer(IPv6) and p[IPv6].nh == 6)) and p.haslayer(TCP) and isinstance(p[TCP], TCP):		# pylint: disable=too-many-boolean-expressions
		if (p[TCP].flags & 0x17) == 0x02:		#SYN (ACK, RST, and FIN off)
			tcp_attributes = {}
			tcp_attributes['ver'] = p[IP].version
			tcp_attributes['ittl'] = p[IP].ttl
			tcp_attributes['olen'] = len(p[IP].options)
			tcp_attributes['mss'] = test_mss(p[TCP].options)
			tcp_attributes['window'] = p[TCP].window
			tcp_attributes['frag'] = p[IP].frag
			tcp_attributes['len'] = p[IP].len
			tcp_attributes['sport'] = p[TCP].sport
			tcp_attributes['dport'] = p[TCP].dport
			tcp_attributes['seq'] = p[TCP].seq
			tcp_attributes['ack'] = p[TCP].ack
			tcp_attributes['dataofs'] = p[TCP].dataofs
			tcp_attributes['reserved'] = p[TCP].reserved
			tcp_attributes['flags'] = p[TCP].flags
			tcp_attributes['chksum'] = p[TCP].chksum
			tcp_attributes['urgptr'] = p[TCP].urgptr
			tcp_attributes['options'] = p[TCP].options

			if p.getlayer(Raw):
				Payload = p.getlayer(Raw).load				#Note, binary value.  Use force_string to make a string
			else:
				Payload = b""

			#At this point we have the fields from the TCP header in tcp_attributes and the Payload - if any - in Payload.  (Payload will normally be empty on a SYN, but this is not a rule (BSD's actually stuff early payload into syn packets so as soon as the handshake is done the server end has data to work with.)
			#Where would you like to send it?
			#p[TCP].show()
			#p.show()
			print(tcp_attributes)
			if Payload:
				print("Payload: " + str(Payload))
			#sys.exit(2)



if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(description='tcp_extract version ' + str(__version__))
	parser.add_argument('-i', '--interface', help='Interface from which to read packets', required=False, default=None)
	parser.add_argument('-r', '--read', help='Pcap file(s) from which to read packets', required=False, default=[], nargs='*')
	parser.add_argument('-d', '--devel', help='Enable development/debug statements', required=False, default=False, action='store_true')
	parser.add_argument('-b', '--bpf', help='BPF to restrict which packets are processed', required=False, default='')
	parser.add_argument('-c', '--count', help='Number of packets to sniff (if not specified, sniff forever/until end of pcap file)', type=int, required=False, default=None)
	(parsed, unparsed) = parser.parse_known_args()
	cl_args = vars(parsed)

	debug_out("BPF we'll use is: " + cl_args['bpf'])

	if cl_args['interface']:
		try:
			if cl_args['count']:
				sniff(store=0, iface=cl_args['interface'], filter=cl_args['bpf'], count=cl_args['count'], prn=lambda x: processpacket(x))	# pylint: disable=unnecessary-lambda
			else:
				sniff(store=0, iface=cl_args['interface'], filter=cl_args['bpf'], prn=lambda x: processpacket(x))				# pylint: disable=unnecessary-lambda
		except Scapy_Exception:
			debug_out('Attempt to listen on an interface failed: are you running this as root or under sudo?')
		sys.stderr.write('\n')
		sys.stderr.flush()
	elif cl_args['read']:
		for one_pcap in cl_args['read']:
			if os.path.exists(one_pcap):
				if os.access(one_pcap, os.R_OK):
					if cl_args['count']:
						sniff(store=0, offline=one_pcap, filter=cl_args['bpf'], count=cl_args['count'], prn=lambda x: processpacket(x))	# pylint: disable=unnecessary-lambda
					else:
						sniff(store=0, offline=one_pcap, filter=cl_args['bpf'], prn=lambda x: processpacket(x))				# pylint: disable=unnecessary-lambda
				else:
					debug_out(str(one_pcap) + ' unreadable, skipping.')
			else:
				debug_out("Unable to read " + one_pcap + ", skipping.")
		sys.stderr.write('\n')
		sys.stderr.flush()
	else:
		debug_out("No interface or pcap file specified, exiting.")
