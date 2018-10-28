#!/usr/bin/env python3.7
import os, platform, re
import sys, getopt, subprocess

from time import sleep

import tqdm
from tqdm import trange

# Windows 10 Environment
# pythonEXE="/mnt/c/Users/superpb9/AppData/Local/Programs/Python/Python37/python.exe"

PLATFORM = platform.system()
WIN_PROJECT_PATH = "C:\\Users\\superpb9\\iCloudDrive\\Documents\\myProject\\mysoc\\"
LINUX_PROJECT_PATH = "/mnt/c/Users/superpb9/iCloudDrive/Documents/myProject/mysoc/"
MAC_PROJECT_PATH = "/Users/pippo-mbp2016/mysoc_clone"

ip_regex = "^(?:(?:1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.)(?:(?:1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.){2}(?:1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$"
domain_regex = "^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?$"

def banner():
    print("#######################################\n"
          "----- Welcome to SuperPB SOC Tool -----\n"
          "------  Author: pippo9 Sep 2018  ------\n"
          "#######################################")
    print("[+] INFO: The programme is currently running on " + PLATFORM)

def usage():
    # cwd = os.getcwd()
    # filePath = os.path.dirname(__file__)
    # filePathName = os.path.abspath(__file__)
    fileName = os.path.basename(__file__)
    print("Usage: " + fileName + " [-i IPv4] [-d Domain] [-s ET Signature]")
    print("The script acts as a single entrance for all soc tools, developed by superpb9.")
    print("    -i   Call IP Reputation Checker.")
    print("    -d   Call Domain Reputation Checker.")
    print("    -s   Search ET Signature online.")  # http://docs.emergingthreats.net/bin/view/Main/2001978
    exit()


def myGetOpt(myFilePath):
    try:
        # Call banner() function
        banner()

        # Check argument
        opts, args = getopt.getopt(sys.argv[1:], '-i:-d:-s:', ['IPv4=', 'Domain=', 'Signature='])
        # If user input an invalid argument, program will exit after calling usage()
        if len(opts) == 0:
            print("[-] ERROR: An invalid argument detected")
            usage()
            exit()
        for opt_name, opt_value in opts:
            if opt_name in ('-i', '--IPv4'):
                ip = opt_value
                # IPv4 validation using Regex
                re_ip = re.compile(ip_regex)
                if re_ip.match(ip):
                    print('[+] IP Regex successfully matches! \n'
                          '[+] Now Calling IP Reputation Checker for ' + ip + '\n'
                          '... IP Reputation Report')
                    # Call ipReputation.py fomr ipReputation
                    myFilePath = myFilePath + "ipReputation"
                    owd = os.getcwd()
                    os.chdir(myFilePath)

                    subprocess.call(['python.exe', 'ipReputation.py', ip])
                    '''
                    p = subprocess.Popen(['python.exe', 'ipReputation.py', ip], stdout=subprocess.PIPE)
                    for line in iter(p.stdout.readline, b''):
                        print (line.strip())
                    p.stdout.close()
                    p.kill()
                    '''
                    # Change the Path back to SYSTEM Default
                    os.chdir(owd)
                else:
                    print('[-] WARNING: Please type a valid IPv4 address. \n'
                          '[-] Program will exit ...')
                    exit()
            elif opt_name in ('-d', '--Domain'):
                domain = opt_value
                # Domain validation using Regex
                re_domain = re.compile(domain_regex)
                if re_domain.match(domain):
                    print('[+] Domain Regex successfully matches! \n'
                          '[+] Now Calling Domain Reputation Checker for ' + domain + '\n')
                    # domainReputation.py
                else:
                    print('[-] WARNING: Please type a valid Domain. \n'
                          '[-] Program will exit ...')
                    exit()
            elif opt_name in ('-s', '--Signature'):
                signature = opt_value
                print("[+] Now Calling ET Signature Checker for " + signature)
                # ...
    except getopt.GetoptError as g:
        print('[-] ERROR: ' + str(g) + '\n'
              '[-] Program will exit ...')


if __name__ == "__main__":
    try:
        # Get the myFilePath in different OS ...
        myFilePath = ''
        if "Windows" in PLATFORM:
            myFilePath = WIN_PROJECT_PATH
        elif "Linux" in PLATFORM:
            myFilePath = LINUX_PROJECT_PATH
        elif "Mac" in PLATFORM:
            myFilePath = MAC_PROJECT_PATH

        # Call getopt
        myGetOpt(myFilePath)

    except IndexError:
        print("[-] ERROR: List index out of range")
