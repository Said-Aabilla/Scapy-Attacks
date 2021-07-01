from scapy.all import *

# Cette fonction prend en param un paquet HTTP de type POST et le decompose :
def sniffer(packet):
    http_packet = packet
    if 'POST' in str(http_packet):
        domain = str(http_packet).split("\\r\\n")[1].split(": ")[1]
        info = str(http_packet).split("\\r\\n\\r\\n")[1]

        print("les informations : ")
        print("---------------------")
        print("Nom de Domaine: " + domain)
        print("Les info recupérés: " + info)
        print("---------------------")

sniff(iface='wlp2s0', prn=sniffer, filter='tcp port 80')
# La fonction sniff fait apelle a la fonction sniffer et lui transmet le paquet.
