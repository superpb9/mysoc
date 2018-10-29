import sys,re,platform

import selenium,time
from selenium import webdriver
from selenium.webdriver.remote.command import Command
from selenium.common.exceptions import WebDriverException

sid_regex="^[0-9]+$"

def browserStatusCheck(myBrowser):
    for i in range(180):
        try:
            # It will return 'True' is Web Browser remains opened ..
            myBrowser.title
            time.sleep(0.5)
        except WebDriverException as w:
            print(w)
            break


def seleniumSignatureSearch():

    sid = sys.argv[1]
    URL = "http://docs.emergingthreats.net/bin/view/Main/WebSearch?search=" + sid + "&scope=all"

    systemPlatform = platform.system()
    if "Windows" in systemPlatform:
        myBrowser = webdriver.Chrome('C:\Windows\System32\chromedriver.exe')
    elif "Darwin" in systemPlatform:
        myBrowser = webdriver.Chrome('/usr/local/bin/chromedriver')
    elif "Linux" in systemPlatform:
        myBrowser = webdriver.Chrome('/usr//bin/chromedriver')

    myBrowser.get(URL);
    browserStatusCheck(myBrowser)
    myBrowser.quit()

if __name__ == '__main__':
    try:
        re_signature = re.compile(sid_regex)
        if re_signature.match(sys.argv[1]):
            # Call ET(Snort) Web Searcher
            print("\n"
                  "***************************************\n"
                  "**** ET (Snort) Signature Checking ****\n"
                  "****       Powered by Selenium     ****\n"
                  "***************************************\n"
                  "[+] Please check your web browser ...\n")
            seleniumSignatureSearch()
        else:
            print('[-] WARNING: Please type a valid Signature.')
    except IndexError:
        print("[-] ERROR: List index out of range")