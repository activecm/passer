FROM python:2.7-slim

# Prevent packages like wireshark from prompting
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    arp-scan \
    ettercap-text-only \
    nmap \
    wireshark \
    && rm -rf /var/lib/apt/lists/

ADD requirements.txt /requirements.txt
RUN pip install --no-cache-dir -r /requirements.txt
RUN echo 'noenum = [ Resolve(), TCP_SERVICES, UDP_SERVICES ]' >> $HOME/.scapy_startup.py

ADD passer.py /passer.py

ENTRYPOINT ["python", "/passer.py"]

# https://github.com/opencontainers/image-spec/blob/master/annotations.md
LABEL org.opencontainers.image.title="passer"
LABEL org.opencontainers.image.description="PASsive SERvice sniffer"
LABEL org.opencontainers.image.url="https://github.com/activecm/passer"
LABEL org.opencontainers.image.documentation="https://github.com/activecm/passer/blob/master/README.md"

# docker build -t passer .
# docker run --rm -it --name=passer --net=host passer
