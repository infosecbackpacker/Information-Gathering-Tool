import whois
import argparse
import dns.resolver
import requests
import shodan

argparse = argparse.ArgumentParser(description="This is basic Information gathering tool",usage="python3 Jannkari.py -d DOMAIN [-s IP]")
argparse.add_argument("-d", "--domain", help="Enter the domain name for printing")
argparse.add_argument("-s", "--shodan", help="Enter the IP for Shodan Search")

args = argparse.parse_args()
domain = args.domain
ip = args.shodan

# whois module
print("[+] Getting whois info..")
print("[+] Domain {} and IP Address {}".format(domain, ip))
py = whois.whois(domain)
print("whois info found")
print("name {}".format(py.domain_name))