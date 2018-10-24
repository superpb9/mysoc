import sys,re,os

from pyvirtualdisplay import Display
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

# Domain Validation with Regex
#  ^(?!:\/\/)
#   ([a-zA-Z0-9-_]+\.)*
#   [a-zA-Z0-9][a-zA-Z0-9-_]+\.
#   [a-zA-Z]{2,11}?$
domain_regex="^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?$"

def seleniumDomainReputation():
    # Call Cisco Talos Intelligence

    display = Display(visible=0, size=(1024, 768))
    display.start()

    print('[+] Now calling Cisco Talos Intelligence')
    cap = DesiredCapabilities().FIREFOX
    cap["marionette"] = True
    myBrowser = webdriver.Firefox(capabilities=cap, executable_path="/usr/bin/geckodriver")
    #myBrowser = webdriver.Firefox(capabilities=cap, executable_path="C:\Windows\System32\geckodriver.exe")
    myBrowser.get('https://www.talosintelligence.com/reputation_center')
    #myBrowser.close()
    #display.stop()

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
            seleniumDomainReputation()
        else:
            print('[-] Warning: Please type a valid Domain.')
    except IndexError:
        print("[-] Error: List index out of range")
