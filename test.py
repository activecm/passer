#Imports
from scapy.all import sniff
from smudge.passive_data import passive_data
from smudge.passive_data import pull_data
from smudge.passive_data import tcp_sig
from smudge.signature_matching import signature
from smudge.signature_matching import matching
from smudge.signature_matching import query_object
import time


# Setup
############################################

# Create Sqlite DB
passive_data.setup_db()

# Create DB  Connection
conn = passive_data.create_con()

# Pull data from Github Ram JSON if Github is resolvable.
if passive_data.test_github_con():
    tcp_sig_data = pull_data.import_data()

    # Iterate over JSON Objects
    for i in tcp_sig_data['signature_list']:
        try:
            smud = tcp_sig(i)
            passive_data.signature_insert(conn, smud)
        except Exception as e:
            print(e)

# SNIFFFFFFFFING
############################################
# Takes the packet and onLY LOOKS AT sYNs
packets = sniff(offline="smudge/bap.pcap", filter="tcp[tcpflags] & tcp-syn != 0")


# Extracts the signature
for i in packets:
    try:
        packet_signature = signature(i)
        print("\n\nSignature Identified for: {IP} --> {signature}".format(IP=i['IP'].src, signature=str(packet_signature)))
        time.sleep(1.5)
# Matches
        mo = matching.match(packet_signature)
        a = mo[1][0]
        b = query_object(acid=a[1], platform=a[2], tcp_flag=a[3], comments=a[13], version=a[4], ittl=a[5], olen=a[6], mss=a[7], wsize=a[8], scale=a[9], olayout=a[10], quirks=a[11], pclass=a[12])
        print("Match at: {percent} to signature {signature}".format(percent=mo[0], signature=b))
        print("Signature identified as {platform}".format(platform=b.platform))
        print("Comments: {comments}\n\n".format(comments=b.sig_comments))
    except:
        pass






