import socket
import dns.resolver
import requests
import shodan
import whois
import argparse
from colorama import init, Fore

#COLOR SETTINGS
red = Fore.RED
green = Fore.GREEN
blue = Fore.BLUE
reset = Fore.RESET

#ARGUMENTS SETTINGS
argparse = argparse.ArgumentParser(description="This is basic Information gathering tool",usage="python3 info2.py -d DOMAIN [-s IP]")
argparse.add_argument("-d", "--domain", help="Enter the domain name for printing")
argparse.add_argument("-s", "--shodan", help="Enter the IP for Shodan Search")

#ARGUMENTS OBJECTS
args = argparse.parse_args()
domain = args.domain
ip = args.shodan

#WHOIS MODULE
print(f"{blue}[+] Getting whois info.. {reset}")
print(f"{red} DOMAIN ......{domain} {ip} {reset}")
print("[+] Domain {} and IP Address {}".format(domain, ip))
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------")
#whois library & one more thing pip3 install python-whois
p = whois.whois(domain)
try:
    print("Name: {}".format(p.domain_name))
    print("Registrar: {}".format(p.registrar))
    print("Creation Date: {}".format(p.creation_date))
    print("Expired Date: {}".format(p.expiration_date))
    print("Update Date:{} ".format(p.updated_date))
    print("WhoisName Server: {}".format(p.whois_server))
    for x in p.name_servers:
        print("Name Servers: {}".format(x))
    print("Emails {}".format(p.emails))
    print("Country {}".format(p.country))
except:
    pass
    print("INTERNET IS NOT FOUND")


print("-------------------------------------------------------------------------------------------------------------------------------------------------------------")
#DNS MODULE
print("[+] Getting DNS info ..")

#implementing dns.resolver from dns python

try:
    for a in dns.resolver.resolve(domain,'A'):
        print("[+] A Record OR IPV4: {}".format(a.to_text()))
    for aaaa in dns.resolver.resolve(domain, 'AAAA'):
         print("[+] AAAA Record OR IPV6: {}".format(aaaa.to_text()))
    for ns in dns.resolver.resolve(domain,'NS'):
        print("[+] NS Record: {}".format(ns.to_text()))
    for mx in dns.resolver.resolve(domain,'MX'):
        print("[+] MX Record {}".format(mx.to_text()))
    for txt in dns.resolver.resolve(domain,'TXT'):
        print("[+] TXT Record {}".format(txt.to_text()))
    for soa in dns.resolver.resolve(domain, 'SOA'):
        print("[+] SOA Record {}".format(soa.to_text()))
except:
    pass
    print("DNS NOT FOUND")
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------")
#GEOLOCATION MODULE
print()
print("[+] GETTING GEOLOCATION INFORMATION....")

#implementing request for web requests
try:
    response = requests.request('GET',"https://geolocation-db.com/json/" + socket.gethostbyname(domain)).json()
    print("[+] IPV4:{}".format(response['IPv4']))
    print("[+] City:{}".format(response['city']))
    print("[+] State:{}".format(response['state']))
    print("[+] Postal Code:{}".format(response['postal']))
    print("[+] Country:{}".format(response['country_name']))
    print("[+] Country Code:{}".format(response['country_code']))
    print("[+] Latitude:{}".format(response['latitude']))
    print("[+] Longitiude:{}".format(response['longitude']))

except:
    pass
    print("UNABLE TO FOUND GEO-LOCATION")


print("-------------------------------------------------------------------------------------------------------------------------------------------------------------")

#SHODAN MODULE
ip=socket.gethostbyname(domain)
if ip:
    print("[+] Getting info from Shodan for IP {}".format(ip))
    #SHDOAN API
    api =shodan.Shodan("WU27WnCcAIvJJxuZHz1OtvIya2WmTuf1")
    try:
        results = api.search(ip)
        print("[+] RESULTS FOUND: {}".format(results['total']))
        for result in results['matches']:
            print("[+] IP: {}".format(result['ip_str']))
            print("[+] HOSTNAMES: {}".format(result['hostnames']))
            print("[+] PORT: {}".format(result['port']))
            print("[+] Data: \n {}".format(result['data']))
    except:
        print("SHODAN SEARCH ERROR")
