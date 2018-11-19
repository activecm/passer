FROM python:2.7-alpine

# Shorten common strings
ARG GH=https://raw.githubusercontent.com
ARG USR=/usr/share
# Install data files
ADD $GH/Ettercap/ettercap/master/share/etter.finger.mac $USR/ettercap/etter.finger.mac
ADD $GH/nmap/nmap/master/nmap-mac-prefixes              $USR/nmap/nmap-mac-prefixes
ADD $GH/wireshark/wireshark/master/manuf                $USR/wireshark/manuf
ADD $GH/royhills/arp-scan/master/ieee-oui.txt           $USR/arp-scan/ieee-oui.txt
ADD $GH/nmap/nmap/master/nmap-service-probes            $USR/nmap/nmap-service-probes

# tcpdump is needed by scapy to replay pcaps
RUN apk update && apk add --no-cache tcpdump

# Install and configure python libraries
COPY requirements.txt /requirements.txt
RUN pip install --no-cache-dir -r /requirements.txt && \
# Disable scapy DNS lookups
echo 'noenum = [ Resolve(), TCP_SERVICES, UDP_SERVICES ]' >> $HOME/.scapy_startup.py && \
# Create passer's cache directory for suspicious and trusted IPs
mkdir $HOME/.passer/
VOLUME $HOME/.passer/

COPY passer.py /passer.py
COPY passer_lib.py /passer_lib.py

ENTRYPOINT ["python", "/passer.py"]

# https://github.com/opencontainers/image-spec/blob/master/annotations.md
LABEL org.opencontainers.image.title="passer"
LABEL org.opencontainers.image.description="PASsive SERvice sniffer"
LABEL org.opencontainers.image.url="https://github.com/activecm/passer"
LABEL org.opencontainers.image.documentation="https://github.com/activecm/passer/blob/master/README.md"
