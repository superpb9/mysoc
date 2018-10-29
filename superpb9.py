#!/usr/bin/env python3.7
import multiprocessing
import os, platform, re
import sys, getopt, subprocess
from multiprocessing import Process

from selenium import webdriver


# Windows 10 Environment
# pythonEXE="/mnt/c/Users/superpb9/AppData/Local/Programs/Python/Python37/python.exe"

PLATFORM = platform.system()
PYTHON_EXEC_FORMAT = ""

WIN_PROJECT_PATH = "C:\\Users\\superpb9\\iCloudDrive\\Documents\\myProject\\mysoc\\"
LINUX_PROJECT_PATH = "/mnt/c/Users/superpb9/iCloudDrive/Documents/myProject/mysoc/"
MAC_PROJECT_PATH = "/Users/pippo-mbp2016/mysoc_clone"

ip_regex = "^(?:(?:1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.)(?:(?:1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.){2}(?:1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$"
domain_regex = "^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?$"
sid_regex="^[0-9]+$"

def banner():
    print("#######################################\n"
          "----- Welcome to SuperPB SOC Tool -----\n"
          "------  Author: pippo9 Sep 2018  ------\n"
          "#######################################")
    print("[+] INFO: Current Platform is " + PLATFORM)

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
        if "Windows" in PLATFORM:
            PYTHON_EXEC_FORMAT = "python.exe"
        # For "Linux" or "Darwin"
        else:
            PYTHON_EXEC_FORMAT = "python3"

        # Check argument
        opts, args = getopt.getopt(sys.argv[1:], '-i:-d:-s:', ['IPv4=', 'Domain=', 'Signature='])
        # If user input an invalid argument, program will exit after calling usage()
        if len(opts) == 0:
            print("[-] ERROR: An invalid argument detected")
            usage()
            exit()

        for opt_name, opt_value in opts:
            #######################
            # IP Reputation Check #
            #######################
            if opt_name in ('-i', '--IPv4'):
                def run_proc(name):
                    # print("[*] Current Child process ---- %s (%s)..." % (name, os.getpid()))
                    ip = opt_value
                    re_ip = re.compile(ip_regex)
                    if re_ip.match(ip):
                        print('[+] IP Regex successfully matches! Now checking ' + ip)
                        # Call ipReputation.py from ipReputation
                        myFilePath1 = myFilePath + "ipReputation"
                        owd = os.getcwd()
                        os.chdir(myFilePath1)
                        subprocess.call([PYTHON_EXEC_FORMAT, 'ipReputation.py', ip])
                        '''
                        p = subprocess.Popen(['python.exe', 'ipReputation.py', ip], stdout=subprocess.PIPE)
                        for line in iter(p.stdout.readline, b''):
                            print (line.strip())
                        p.stdout.close()
                        p.kill()
                        '''
                        print("<><><> IP Whois Result <><><>")
                        subprocess.call([PYTHON_EXEC_FORMAT, 'ipWhois.py', ip])
                        # Change the Path back to SYSTEM Default
                        os.chdir(owd)
                    else:
                        print('[-] WARNING: Please type a valid IPv4 address. \n'
                              '[-] Program will exit ...')
                        exit()
                # ************************* #
                # Parent Process Running Block
                # print('[*] Current Parent process ---- %s.' % os.getpid())
                # Call the Child Process Running Block above
                p = Process(target=run_proc, args=('test',))
                p.start()
                # Note: We don't want to wait for Parent Process; Otherwise, please use p.join()
                # p.join()

            ###########################
            # Domain Reputation Check #
            ###########################
            elif opt_name in ('-d', '--Domain'):
                # ************************* #
                # Child Process Running Block
                # Use Child Process to do Domain Reputation Check
                def run_proc(name):
                    # print("[*] Current Child process ---- %s (%s)..." % (name, os.getpid()))
                    domain = opt_value
                    re_domain = re.compile(domain_regex)
                    if re_domain.match(domain):
                        print('[+] Domain Regex successfully matches! Now checking ' + domain)
                        # Call domainReputation.py from domainReputation
                        myFilePath2 = myFilePath + "domainReputation"
                        owd = os.getcwd()
                        os.chdir(myFilePath2)
                        subprocess.call([PYTHON_EXEC_FORMAT, 'domainReputation.py', domain])
                        # Change the Path back to SYSTEM Default
                        os.chdir(owd)
                    else:
                        print('[-] WARNING: Please type a valid Domain. \n'
                              '[-] Program will exit ...')
                        exit()
                # ************************* #
                # Parent Process Running Block
                # print('[*] Current Parent process ---- %s.' % os.getpid())
                # Call the Child Process Running Block above
                p = Process(target=run_proc, args=('test',))
                p.start()
                # Note: We don't want to wait for Parent Process; Otherwise, please use p.join()
                # p.join()


            #############################
            # ET(Snort) Signature Check #
            #############################
            elif opt_name in ('-s', '--Signature'):
                # ************************* #
                # Use Child Process to do ET(Snort) Check
                def run_proc(name):
                    # print("[*] Current Child process ---- %s (%s)..." % (name, os.getpid()))
                    signature = opt_value
                    re_signature = re.compile(sid_regex)
                    if re_signature.match(signature):
                        print("[+] Signature Regex successfully matches! Now checking " + signature)
                        # Call sidSearchET.py from signatureSearch
                        myFilePath3 = myFilePath + "signatureSearch"
                        owd = os.getcwd()
                        os.chdir(myFilePath3)
                        subprocess.call([PYTHON_EXEC_FORMAT, 'sidSearchET.py', signature])
                        # Change the Path back to SYSTEM Default
                        os.chdir(owd)
                    else:
                        print('[-] WARNING: Please type a valid signature. \n'
                              '[-] Program will exit ...')
                        exit()
                # ************************* #
                # Parent Process Running Block
                # print('[*] Current Parent process ---- %s.' % os.getpid())
                # Call the Child Process Running Block above
                p = Process(target=run_proc, args=('test',))
                p.start()
                # Note: We don't want to wait for Parent Process; Otherwise, please use p.join()
                # p.join()

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
