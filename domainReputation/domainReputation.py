import sys,re,os,time

import selenium
from pyvirtualdisplay import Display
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

# Domain Validation with Regex
#  ^(?!:\/\/)
#   ([a-zA-Z0-9-_]+\.)*
#   [a-zA-Z0-9][a-zA-Z0-9-_]+\.
#   [a-zA-Z]{2,11}?$
from selenium.webdriver.common.keys import Keys

domain_regex="^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?$"


def seleniumDomainReputation(domain):

    try:
        URL1='https://www.virustotal.com/#/home/search'
        URL2='https://www.talosintelligence.com/reputation_center/lookup?search=' + domain
        # Mac
        # myBrowser = webdriver.Chrome('/usr/local/bin/chromedriver')
        # Windows
        myBrowser = webdriver.Chrome('/mnt/c/Windows/System32/chromedriver.exe')

        # ==========
        # VirusTotal
        print('[+] Now calling VirusTotal')
        myBrowser.get(URL1);
        time.sleep(2)
        searchElem = myBrowser.find_element_by_css_selector('div.iron-selected > vt-omnibar:nth-child(2) > div:nth-child(1) > span:nth-child(1) > input:nth-child(1)')
        searchElem.send_keys(domain)
        # searchElem.submit()
        time.sleep(2)
        clickElem = myBrowser.find_element_by_css_selector('div.iron-selected > vt-omnibar:nth-child(2) > div:nth-child(1) > span:nth-child(1) > paper-icon-button:nth-child(3) > iron-icon:nth-child(1)')
        clickElem.click()

        # ===========
        # Cisco Talos
        # Opening a New Tab in Chrome
        print('[+] Now calling Cisco Talos Intelligence')
        myScript = 'window.open("' + URL2 + '");'
        myBrowser.execute_script(myScript)
        time.sleep(2)  # Let the user actually see something!

        







        myBrowser.quite()

        # Call Cisco Talos Intelligence

        # Firefox
        # display = Display(visible=0, size=(1024, 768))
        # display.start()
        # cap = DesiredCapabilities().FIREFOX
        # cap["marionette"] = False
        # myBrowser = webdriver.Firefox(capabilities=cap, executable_path="C:\Windows\System32\geckodriver.exe")
        # myBrowser = webdriver.Firefox(capabilities=cap, executable_path="/usr/local/bin/geckodriver")
        # myBrowser.get('https://www.talosintelligence.com/reputation_center')
        # myBrowser.quit()
        # display.stop()

    except selenium.common.exceptions.NoSuchElementException:
        print("Error: Unable to locate element. Please re-try...")
    except selenium.common.exceptions.NoSuchWindowException:
        print("Warning: Target window already closed...")


if __name__ == '__main__':
    try:
        re_domain = re.compile(domain_regex)
        if re_domain.match(sys.argv[1]):
            print('[+] Domain Regex successful matches ...')
            print('[+] Linux DIG Answer Section')
            # Call Linux DIG
            #os.system('dig %s @8.8.8.8 +noall +answer | grep -Ev \'\^\$\' | grep -Ev "^; <<>>" | grep -Ev ";; global"' %(sys.argv[1]))
            process = os.popen('dig %s @8.8.8.8 ANY +noall +answer'
                               '| grep -Ev "^;"'
                               '| grep -Ev ";;"'
                               '| grep -Ev \'^$\''
                               '| sort -k4'
                               %(sys.argv[1]))
            print(process.read())
            process.close()
            # Call Selenium
            seleniumDomainReputation(sys.argv[1])
        else:
            print('[-] Warning: Please type a valid Domain.')
    except IndexError:
        print("[-] Error: List index out of range")
