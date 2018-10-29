import platform
import sys,re,os,time
import subprocess
import shlex

import selenium
from selenium import webdriver
from pyvirtualdisplay import Display
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.remote.command import Command

# Domain Validation with Regex
#  ^(?!:\/\/)
#   ([a-zA-Z0-9-_]+\.)*
#   [a-zA-Z0-9][a-zA-Z0-9-_]+\.
#   [a-zA-Z]{2,11}?$
from selenium.webdriver.common.keys import Keys

domain_regex="^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?$"
SYSTEM_PLATFORM = platform.system()

def browserStatusCheck(myBrowser):
    for i in range(180):
        try:
            # It will return 'True' is Web Browser remains opened ..
            myBrowser.title
            time.sleep(0.5)
        except WebDriverException as w:
            print(w)
            break


def seleniumDomainReputation(domain):

    try:
        URL1='https://www.virustotal.com/#/home/search'
        URL2='https://www.talosintelligence.com/reputation_center/lookup?search=' + domain

        if "Windows" in SYSTEM_PLATFORM:
            myBrowser = webdriver.Chrome('C:\Windows\System32\chromedriver.exe')
        elif "Darwin" in SYSTEM_PLATFORM:
            myBrowser = webdriver.Chrome('/usr/local/bin/chromedriver')
        elif "Linux" in SYSTEM_PLATFORM:
            myBrowser = webdriver.Chrome('/usr//bin/chromedriver')

        #  # ******* Tab 1: VirusTotal *******
        myBrowser.get(URL1);
        time.sleep(4)
        searchElem = myBrowser.find_element_by_css_selector('div.iron-selected > vt-omnibar:nth-child(2) > div:nth-child(1) > span:nth-child(1) > input:nth-child(1)')
        searchElem.send_keys(domain)
        # searchElem.submit()
        time.sleep(3)
        clickElem = myBrowser.find_element_by_css_selector('div.iron-selected > vt-omnibar:nth-child(2) > div:nth-child(1) > span:nth-child(1) > paper-icon-button:nth-child(3) > iron-icon:nth-child(1)')
        clickElem.click()

        # ******* Tab 2: Cisco Talos *******
        myScript = 'window.open("' + URL2 + '");'
        myBrowser.execute_script(myScript)

        browserStatusCheck(myBrowser)
        myBrowser.quit()

    except selenium.common.exceptions.NoSuchElementException:
        print("[-] ERROR: Unable to locate element. Please re-try...")
    except selenium.common.exceptions.NoSuchWindowException:
        print("[-] WARNING: Target window already closed...")


if __name__ == '__main__':
    try:
        re_domain = re.compile(domain_regex)
        if re_domain.match(sys.argv[1]):
            # ****** Step 1: Call Linux DIG ******
            # For Linux & Mac Platform
            print("***************************************\n"
                  "***    Domain Reputation Checking   ***\n"
                  "****    Powered by DIG|Selenium    ****\n"
                  "***************************************")

            if "Windows" not in SYSTEM_PLATFORM:
                print("[+] Linux DIG Answer Section")
                # os.system('dig %s @8.8.8.8 +noall +answer | grep -Ev \'\^\$\' | grep -Ev "^; <<>>" | grep -Ev ";; global"' %(sys.argv[1]))
                process = os.popen('dig %s @8.8.8.8 ANY +noall +answer'
                                   '| grep -Ev "^;"'
                                   '| grep -Ev ";;"'
                                   '| grep -Ev \'^$\''
                                   '| sort -k4'
                                   % (sys.argv[1]))
                lines = process.readlines()
                for line in lines:
                    # Exclusive an empty line using strip()
                    line = line.strip()
                    if line:
                        print(line)
                process.close()
            else:
                # For Windows Platform
                print("[+] Windows DIG Answer Section")
                process = os.popen('"C:\\Program Files\\dig\\bin\\dig" %s @8.8.8.8 ANY +noall +answer'
                                   '| findstr /v "^;"'
                                   '| findstr /v ";;"'
                                   '| findstr /v \'^$\''
                                   '| sort /+4'
                                   % (sys.argv[1]))
                lines = process.readlines()
                for line in lines:
                    # Exclusive an empty line using strip()
                    line = line.strip()
                    if line:
                        print(line)
                process.close()

            # ****** Step 2: Call Selenium ******
            print("[+] Please check your web browser\n")
            seleniumDomainReputation(sys.argv[1])
        else:
            print('[-] WARNING: Please type a valid Domain.')
    except IndexError:
        print("[-] ERROR: List index out of range")
