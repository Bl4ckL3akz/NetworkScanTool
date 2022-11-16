import sys
import time
import colorama
from scapy.all import*
from socket import *
import platform
from icmplib import ping, multiping, traceroute, resolve
from datetime import datetime
import whois
from ip2geotools.databases.noncommercial import DbIpCity
def platform_check():
    sysx = platform.system()
    if sysx == "Windows":
        print("")
        print("Detected OS: Windows.")
        main_windows()
    if sysx == "Linux":
        print("")
        print("Detected OS: Linux")
        main_linux()


def net_scan():
    print("")
    target_ip = input("Enter target-ip: ")
    target = target_ip + "\24"
# IP Address for the destination
# create ARP packet
    arp = ARP(pdst=target)
# create the Ether broadcast packet
# ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
# stack them
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

# a list of clients, we will fill this in the upcoming loop
    clients = []

    for sent, received in result:
    # for each response, append ip and mac address to `clients` list
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

# print clients
    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))
    sysx = platform.system()
    if sysx == "Windows":
        main_windows()
    if sysx == "Linux":
        main_linux()

def geolocation():
    print("")
    ip_target = input("Enter ip-2-geolacte: ")
    response = DbIpCity.get(ip_target, api_key='free')
    print("")
    print("Response IP ADDRESS:")
    print(response.ip_address)
    print("")
    print("RESPONSE CITY:")
    print(response.city)
    print("")
    print("RESPONSE REGION:")
    print(response.region)
    print("")
    print("RESPONSE COUNTRY:")
    print(response.country)
    print(response.to_json())
    print("")
    sysx = platform.system()
    if sysx == "Windows":
        main_windows()
    if sysx == "Linux":
        main_linux()

def whois():
    import whois
    print("")
    name = input("Enter whois-target: ")
    w = whois.whois(name)
    print(w.expiration_date)
    print(w.text)
    print(w)
    print("")
    sysx = platform.system()
    if sysx == "Windows":
        main_windows()
    if sysx == "Linux":
        main_linux()

def netstat():
    print("")
    sysx = platform.system()
    os.system("netstat -at")
    print("")
    if sysx == "Windows":
        main_windows()
    if sysx == "Linux":
        main_linux()

def ping():
    print("")
    ip_target = input("Enter ip for ping-test: ")
    ping(ip_target, count=4, interval=1, timeout=2)
    sysx = platform.system()
    print("")
    if sysx == "Windows":
        main_windows()
    if sysx == "Linux":
        main_linux()

def portscan():
   print("")
   ip_target = input('Enter the host to be scanned: ')
   t_IP = gethostbyname(ip_target)
   print ('Starting scan on host: ', t_IP)
   print("")
   for i in range(50, 500):
      s = socket(AF_INET, SOCK_STREAM)

      conn = s.connect_ex((t_IP, i))
      if(conn == 0) :
         print ('Port %d: OPEN' % (i,))
      s.close()
   sysx = platform.system()
   if sysx == "Windows":
       main_windows()
   if sysx == "Linux":
       main_linux()

def trace():
    print("")
    ip_target = input("Enter target-ip:" )
    hops = traceroute(ip_target)
    print('Distance/TTL    Address    Average round-trip time')
    last_distance = 0
    for hop in hops:
        if last_distance + 1 != hop.distance:
            print("Some gateways are not responding")
        print(f'{hop.distance}  {hop.address}   {hop.avg_rtt} ms')
        last_distance = hop.distance
    print("")
    sysx = platform.system()
    if sysx == "Windows":
        main_windows()
    if sysx == "Linux":
        main_linux()

def arp():
    print("")
    os.system('arp -a')
    print("")
    sysx = platform.system()
    if sysx == "Windows":
        main_windows()
    if sysx == "Linux":
        main_windows()




def linuxtrace():
    print("")
    ip_target = input("Enter target-ip: ")
    os.system('traceroute ' + ip_target)
    print("")

def linuxportscan():
    print("")
    ip_target = input("Enter target-ip: ")
    os.system('nmap -v -p0 -A ' + ip_target)
    print("")

def linuxping():
    print("")
    ip_target = input("Enter target-ip: ")
    os.system('ping ' + ip_target)
    print("")

def main_linux():
    print("")
    print("")
    print("=======================================")
    print("== Network-Scan | v0.1a by BlackLeakz==")
    print("=======================================")
    print("== 1: portscan    | 2: traceroute    ==")
    print("== 3: ping        | 4: arp           ==")
    print("== 5: netstat     | 6: geolacte      ==")
    print("== 7: whois       | 8: net_scan      ==")
    print("=======================================")
    print("")
    print("")
    choice = input("user@env:~$ ")


    if choice == "1":
        linuxportscan()

    if choice == "2":
        linuxtrace()

    if choice == "3":
        linuxping()

    if choice == "4":
        arp()

    if choice == "5":
        netstat()

    if choice == "6":
        geolocation()

    if choice == "7":
        whois()

    if choice == "8":
        net_scan()


def windowsping():
    print("")
    ip_target = input("Enter target-ip: ")
    os.system("ping " + ip_target)
    print("")
    main_windows()

def windowstrace():
    print("")
    ip_target = input("Enter target-ip: ")
    os.system('tracert ' + ip_target)
    main_windows()

def main_windows():
    print("")
    print("")
    print("=======================================")
    print("== Network-Scan | v0.1a by BlackLeakz==")
    print("=======================================")
    print("== 1: portscan    | 2: traceroute    ==")
    print("== 3: ping        | 4: arp           ==")
    print("== 5: netstat     | 6: geolocate     ==")
    print("== 7: whois       | 8: net_scan      ==")
    print("=======================================")
    print("")
    print("")

    choice = input("user@env:~$ ")

    if choice == "1":
        portscan()

    if choice == "2":
        windowstrace()

    if choice == "3":
        windowsping()

    if choice == "4":
        arp()

    if choice == "5":
        netstat()

    if choice == "6":
        geolocation()

    if choice == "7":
        whois()

    if choice == "8":
        net_scan()




if __name__ == '__main__':
    platform_check()
