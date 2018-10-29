import sys
from ipwhois import IPWhois
from pprint import pprint


def ipWhois():
    # Call backup_myIPwhois.py
    # myIPwhois.IPWhoisChecker("https://www.abuseipdb.com/whois/" + sys.argv[1])

    # IPWhois (pip3 install ipwhois == 0.10.3)
    ipwhoisInfo = IPWhois(sys.argv[1])
    ipwhoisResults = ipwhoisInfo.lookup_rws()
    pprint(ipwhoisResults)

def main():
    ipWhois()

if __name__ == '__main__':
    main()