from scapy.all import srp
from scapy.all import Ether, ARP, conf
import sys
import re
import sys

def dotreplace(matchobj):
       if matchobj.group(0) == '.':
            return ''
       elif  matchobj.group(0) == ':':
            return ''

def get_vendor(mac):
    macs = open('mac-database.txt','r')
    macs_lines=macs.readlines()
    popa = re.search('.*([a-f0-9]{4}\.[a-f0-9]{4}\.[a-f0-9]{4}).*',mac,re.IGNORECASE)
    if popa:
        newpopa = re.sub('\.', dotreplace, popa.group(1))[0:6]
        newpopa_re = re.compile(newpopa, re.IGNORECASE)
        for mac_db in macs_lines:
            vendor = re.search(newpopa_re, mac)
            if vendor:
                return mac_db[7:].strip()

    popalinux = re.search('.*([a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}).*',mac,re.IGNORECASE)
    if popalinux:
        newpopalinux = re.sub(':', dotreplace, popalinux.group(1))[0:6]
        newpopalinux_re = re.compile(newpopalinux, re.IGNORECASE)
        for mac_db in macs_lines:
            vendor = re.search(newpopalinux_re, mac_db)
            if vendor:
                return mac_db[7:].strip()


def arping(iprange, interface):

    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=iprange),iface=interface, timeout=2)
    print("\n       IP       <--->       MAC\n")
    collection = []
    for snd, rcv in ans:
        result = rcv.sprintf(r"%ARP.psrc% %Ether.src%").split()
        collection.append(result)
    return collection

if __name__ == "__main__":
    if len(sys.argv) > 2:
        print("arping", sys.argv[1])
        for pair in arping(sys.argv[1], sys.argv[2]):
            print("%15s <---> %17s (%s)" % (pair[0], pair[1], get_vendor(pair[1])))
    else:
        print("Please Enter ip range as an argument")
