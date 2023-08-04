import dns.resolver
import socket
import shodan
import whois
import argparse
import concurrent.futures
import requests
import threading
import time
from colorama import Fore, Style

#COLOR SETTINGS
red = Fore.RED
green = Fore.GREEN
blue = Fore.BLUE
reset = Fore.RESET


#ARGUMENTS SETTINGS
argparse = argparse.ArgumentParser(description="This is basic Information gathering tool",usage="python3 info2.py -d DOMAIN [-s IP]")
argparse.add_argument("-d", "--domain", help="Enter the domain name for printing")
argparse.add_argument("-s", "--shodan", help="Enter the IP for Shodan Search")
argparse.add_argument("-o","--output", help="Enter file name you want to save")

#ARGUMENTS OBJECTS
args = argparse.parse_args()
domain = args.domain
ip = args.shodan
out = args.output

#WHOIS MODULE
print(f"{blue}[+] Getting whois info.. {reset}")
print(f"{red} DOMAIN ......{domain} {ip} {reset}")
print("[+] Domain {} and IP Address {}".format(domain, ip))
print("-------------------------------------------------------------------------------------------------------------------------------------------------------------")
#whois library & one more thing pip3 install python-whois
p = whois.whois(domain)
try:
    print(Style.BRIGHT + Fore.WHITE + "Name: {}".format(p.domain_name))
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
        print("[+] A Record : {}".format(a.to_text()))
    for aaaa in dns.resolver.resolve(domain, 'AAAA'):
         print("[+] AAAA Record: {}".format(aaaa.to_text()))
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
#ip=socket.gethostbyname(domain)
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

# the domain to scan for subdomains
print("Printed immediately.")
time.sleep(2)
print("Wait for a 3 seconds.")
print(Style.BRIGHT + Fore.GREEN + '''
FINDING SUBDOMAINS ''')
# read all subdomains
file = open("subdomains.txt")
# read all content
content = file.read()
# split by new lines
subdomains = content.splitlines()

# a list of discovered subdomains
discovered_subdomains = []
for subdomain in subdomains:
    # construct the url
    url = f"https://{subdomain}.{domain}"
    try:
        # if this raises an ERROR, that means the subdomain does not exist
        requests.get(url)
    except requests.ConnectionError:
        # if the subdomain does not exist, just pass, print nothing
        pass
    else:
        print(" [+] Discovered subdomain:", url)

        # append the discovered subdomain to our list
        discovered_subdomains.append(url)

    # save the discovered subdomains into a file
    with open("discovered_subdomains.txt", "w") as f:
        for subdomain in discovered_subdomains:
            print(subdomain, file=f)

# REPLACING HTTPS:// ----- >>>> This help to find the ip of subdomains
search_txt = "https://"

replace_text = ""

with open("discovered_subdomains.txt", "r") as file:
    data = file.read()
    data = data.replace(search_txt, replace_text)

with open("discovered_subdomains.txt", "w") as file:
    file.write(data)

print()
print("GOING TO THE NEXT STEPS FOR RESOLVING IP HTTPS REMOVING")

# RESOLVING SUBDOMAINS TO IP


print(Style.BRIGHT + Fore.CYAN + '''
SUBDOAMIN FINDING ''')

print(Style.BRIGHT + Fore.YELLOW + 'PREPARING FOR GETTING IPs')

inputfile = "discovered_subdomains.txt"
outputfile = out+".txt"
output = open(outputfile, "a")
with open(inputfile, "r") as f:
    inputurl = [line.rstrip() for line in f]
threadLocal = threading.local()
count = len(inputurl)
print("number of subdomains = " + str(count))


def get_session():
    if not hasattr(threadLocal, "session"):
        threadLocal.session = requests.Session()
    return threadLocal.session


def check_sub(url):
    try:
        res = requests.get(url, stream=True)
        ip = res.raw._original_response.fp.raw._sock.getpeername()[0]
        res2 = url + " : " + str(ip)
        print(Style.BRIGHT + Fore.WHITE + url[7:] + " : " + Fore.CYAN + str(ip))
        output.write(res2[7:] + "\n")
    except:
        pass


def itterate_url(inputurl):
    url = "http://" + inputurl
    check_sub(url)


if __name__ == "__main__":
    start_time = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as executor:
        executor.map(itterate_url, inputurl)

duration = time.time() - start_time
print("Finished in : " + str(duration) + "  sec")
