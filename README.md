# passer
Passive service locator, a python sniffer that identifies servers, clients, names and much more

## Introduction

Quick notes for getting going with passer, the passive service
sniffer.  You're responsible for getting permission to sniff.

Passer can work off a live packet capture or from a pcap file
(command line parameter, see examples below).  It reports live services
and clients, ethernet cards on the lan, dns entries, operating systems,
and routers - all passively!

If you're using windows or your paths to the support files don't
match mine for some other reason, let me know where they are and I'll be
glad to update the script.

## Installation

### Requirements
- Python >=2.4 and <3.0
- Python libraries (see [requirements.txt](/requirements.txt))
  - ipaddress
  - pytz
  - scapy>=2.4.0

### Optional (but recommended)
- nmap
	- for Ethernet manufacturers and service strings
- ettercap, wireshark, and/or arp-scan
	- for more Ethernet manufacturers
- p0f version 2
	- for the OS fingerprint file

### Ubuntu/Debian and deb-based distros
```bash
# Install system dependencies
sudo apt-get install arp-scan ettercap-text-only nmap wireshark 
# Install python dependencies
sudo pip install -r requirements.txt
# Prevent Scapy from performing DNS lookups
echo 'noenum = [ Resolve(), TCP_SERVICES, UDP_SERVICES ]' >> ~/.scapy_startup.py
```

### Redhat/CentOS/Fedora and rpm-based distros
```bash
# Install system dependencies
sudo yum install arp-scan ettercap nmap wireshark
# Install python dependencies
sudo pip install -r requirements.txt
# Prevent Scapy from performing DNS lookups
echo 'noenum = [ Resolve(), TCP_SERVICES, UDP_SERVICES ]' >> ~/.scapy_startup.py
```

### Windows (incomplete)

To install scapy, see the [installation guide](https://scapy.readthedocs.io/en/latest/installation.html#windows).

### Docker

Passer also comes packaged as a Docker image. If you don't already have Docker here is a quick and dirty way to install it on Linux:

```bash
curl -fsSL https://get.docker.com | sh -
```

Otherwise, follow the [install instructions](https://docs.docker.com/get-docker/) for your operating system.

For most uses, we recommend the [`passer`](https://github.com/activecm/passer/blob/master/passer) script included in this repo. This script will handle all docker-specific

```bash
wget https://raw.githubusercontent.com/activecm/passer/master/passer
chmod +x passer
```

You can then use this script just as you would in any of the examples below. For example:

```bash
./passer -i eth0
# The equivalent without using the included script would be:
docker run --rm --name=passer -i --init --net=host --cap-add=net_raw activecm/passer -i eth0
```

In order to stop passer run:

```bash
docker stop passer
```


## Examples

### Sniff live as root

```bash
/path/to/passer.py
```

This sniffs from all network interfaces and sends all output
lines to your console.

### Sniff live as a non-root user

```bash
sudo /path/to/passer.py
```
or
```bash
su - -c '/path/to/passer.py'
```

### Sniff live as root, but only from one interface

```bash
/path/to/passer.py -i IfaceName
```
Running `route` should give some live interfaces you might use. 
> :grey_exclamation: `-i` is incompatible with `-r`.

### Read packets from a pcap file; no root privileges needed

```bash
/path/to/passer.py -r /path/to/packets.pcap
```

> :grey_exclamation: `-r` is incompatible with `-i`.

### Accept raw pcap data on stdin

```bash
cat packetdata.pcap | ./passer.py -r /proc/self/fd/0
zcat packetdata.pcap.gz | ./passer.py -r /proc/self/fd/0
bzcat packetdata.pcap.bz2 | ./passer.py -r /proc/self/fd/0
tcpdump -i eth0 -qtnp -w - | ./passer.py -r /proc/self/fd/0
# etc...
```

This lets you capture packets with any tool that can save
packets to a pcap file, and later process them with passer on a
different system.

### Save output lines to a text file for later processing

```bash
/path/to/passer.py -l /path/to/networkinfo.txt
```

### Suppress warnings and other debugging info

```bash
/path/to/passer.py 2>/dev/null
```

### Show help screen

```bash
/path/to/passer.py -h
```

### Save "odd"/unhandled packets to a pcap file

```bash
/path/to/passer.py -u /path/to/oddpackets.pcap
```

This is generally intended for the development process; packets
saved to this file are ones that need to have signatures written.  If
you'd like to help improve the program, get in touch with the author,
Bill Stearns (william.l.stearns@gmail.com).  Contributions of odd packets,
descriptions of services, and patches to the program are gratefully
accepted.

### Apply a BPF filter to limit which packets are processed

This _should_ be as simple as placing the BPF filter in single
quotes at the end of the command line.  As of version 1.16, the
underlying library does not appear to successfully use the supplied
filter, but there's a workaround.  Use tcpdump to do the filtering, and
hand the pared-down set of packets to passer on stdin, like above:

```bash
tcpdump -r packets.pcap -w - 'icmp or arp' | ./passer.py -r /proc/self/fd/0
```

See the "Sample filters" section, below, for some suggestions of
filters to use in either capturing packets in advance or live sniffing.

## Troubleshooting

```
socket.error: (1, 'Operation not permitted')
```
You're probably trying to sniff live as a non-root user.  Either
log in as root, use sudo/su, or work with pcap files.

If passer crashes or won't work on your system, send me an email
(Bill Stearns, william.l.stearns@gmail.com).  It would be very helpful if you
could include the error message, if any, and any details about your
operating system.

### Output format

Passer's output goes to stdout, and if you give the command line
parameter `-l /path/to/logfile`, to that file as well.  Here's the format:

Type | IPAddr | Proto        | State               | Optional description (may be empty)
-----|--------|--------------|---------------------|--------------------
'IP' | IPaddr | 'IP'         | dead or live        | p0f OS description
'MA' | IPaddr | 'Ethernet'   | MacAddr             | ManufDescription
'TC' | IPaddr | 'TCP_'Port   | closed or open      | client description
'TS' | IPaddr | 'TCP_'Port   | closed or listening | server description
'UC' | IPaddr | 'UDP_'Port   | open or closed      | udp client port description
'US' | IPaddr | 'UDP_'Port   | open or closed      | udp server port description
'DN' | IPaddr | 'A' or 'PTR' | hostname            | possible extra info
'RO' | IPaddr | 'TTLEx'      | router              | possible extra info

- Column 1: A 2 letter code for the record type
- Column 2: The IP address being characterized.
- Column 3: The protocol involved, or "how do we know this?"
- Column 4: the state of the object being described
- Column 5: additional information about the object

Lines are comma separated for easy loading into a spreadsheet or
SQL import.  None of the fields should contain commas.  There is a
sample output file at http://www.stearns.org/passer/passer-sample-log.txt .

Here are some examples of how to get the data you want out of
these lines:

1) Remove duplicate lines:
```bash
cat /var/tmp/passer-log | sort -u | less
```

2) Remove duplicate lines and group all records for a given IP together:
```bash
cat /var/tmp/passer-log | sort -t, -k2 -u | less
```

3) Grab just the DNS and Router records:
```bash
cat /var/tmp/passer-log | sort -u | egrep '(^DN|^RO)' | less
```

4) See all records for a particular IP address:
```bash
cat /var/tmp/passer-log | sort -u | grep ',192\.168\.0\.17,' | less
```

5) See all records for a particular network:
```bash
cat /var/tmp/passer-log | sort -u | grep ',192\.168\.' | less
```

6) See all machines that are listing on TCP port 25 (smtp servers):
```bash
cat /var/tmp/passer-log | sort -u | grep ',TCP_25,listening,' | less
```

7) Don't display closed ports:
```bash
cat /var/tmp/passer-log | sort -u | grep -v ',closed,' | less
```

8) _Only_ display closed ports:
```bash
cat /var/tmp/passer-log | sort -u | grep ',closed,' | less
```

9) Show all DNS records in the "google.com" domains:
```bash
cat /var/tmp/passer-log | sort -u | grep -i 'google\.com\.,' | less
```

10) Grab all the DNS address records and create a hosts-like file:
```bash
/path/to/make-hosts /var/tmp/passer-log | /path/to/mergehosts.pl >/var/tmp/passer-hosts
```
"make-hosts" and merge-hosts are separate shell and perl scripts
at http://www.stearns.org/passer/make-hosts .

This is just a start!  Send in your favourite ways to extract
items of interest and I'll add them and give you credit.

## BPF filters

The individual record types need certain types of packets to
give them their raw data.  If you want to include or exclude these, use
the accompanying filter.

  `'IP',	IPaddr,	'IP',		dead or live,		p0f OS description`

This needs TCP SYN packets:
```
'tcp[13] & 0x12 = 0x02'
```

  `'MA',	IPaddr, 'Ethernet',	MacAddr,		ManufDescription`

These come from arp replies(*1):
```
'arp'
```

  `'TC',	IPaddr,	'TCP_'Port,	closed or open,		client description`

These need TCP SYN/ACK's, FIN's and RST's(*2):
```
'tcp[13] & 0x07 != 0'
```

  `'TS',	IPaddr,	'TCP_'Port,	closed or listening,	server description`

We need TCP SYN's, SYN/ACK's, and RST's to see if the port is
open or closed:
```
'tcp[13] & 0x06 != 0'
```
To come up with a server description string, we also need to see
the ACK packets that make up the bulk of the traffic on the wire:
```
'tcp[13] & 0x17 = 0x10'
```
If you want both, just grab all TCP traffic:
```
'tcp'
```

  `'UC',	IPaddr,	'UDP_'Port,	open or closed,		udp client port description`

Easiest to just hand it all udp ports and ICMP port unreachables:
```
'udp or icmp[0:2] = 0x0303'
```

  `'US',	IPaddr,	'UDP_'Port,	open or closed,		udp server port description`

Same as above:
```
'udp or icmp[0:2] = 0x0303'
```

  `'DN',	IPaddr,	A,AAAA,PTR,CNAME hostname,		possible extra info`

UDP or TCP port 53 (*3):
```
'udp src port 53 or tcp src port 53'
```

  `'RO',	IPaddr,	'TTLEx',	router,			possible extra info`

We identify routers because they're sending
Time-To-Live-Exceeded or unreachable messages:
```
'icmp[0:2] = 0x0B00 or icmp[0] = 0x03'
```

*1 This grabs arp requests too, but these are ignored.

*2 The filter technically includes SYNs as well, but that's a small
amount of extra data

*3 As of version 1.16, only _UDP_ port 53 answers are extracted.

### Sample BPF filters

1) To drastically reduce the number of packets to be parsed, losing only
the tcp server description strings, don't process ACK-only packets:
```
'not(tcp[13] & 0x17 = 0x10)'
```
This chops out 90+% of the number and volume of packets to be
handled, letting passer keep up with moderate bandwidth links.


2) If you're not interested in DNS servers:
```
'not udp src port 53'
```
There's quite a bit of work to extract dns records; this may
also be a good one to turn off if you're trying to keep up with a fast
link.


3) If you want to focus on packets to or from a particular machine or
network:
```
'host 1.2.3.4'
'net 1.2'
```

## More info

Questions?  Bug reports?  Issues?  Try william.l.stearns@gmail.com and
please include "passer" somewhere in the subject line.

* Home site:
  * http://www.stearns.org/passer/
* Github repository:
  * https://github.com/activecm/passer
