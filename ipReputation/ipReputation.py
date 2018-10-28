import sys,re,json

import dns.resolver
from bs4 import BeautifulSoup

import requests
from requests.auth import HTTPBasicAuth

import pandas as pd
from pandas import Series, DataFrame

# IPv4 Validation with Regex
#  ^((1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.)
#   ((1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.){2}
#   (1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$
# ip_regex="^((1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.)((1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.){2}(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$"
ip_regex="^(?:(?:1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.)(?:(?:1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.){2}(?:1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$"


def ipvoidChecker(ip):

    url = "http://www.ipvoid.com/ip-blacklist-check/"
    headers = {"Content-Type": "application/x-www-form-urlencoded",
               "Referer":"http://www.ipvoid.com/ip-blacklist-check/",}
    payload = {'ip':ip}
    # Note: Using 'data' instead of 'params'
    r = requests.post(url, headers=headers, data=payload)
    returnData = r.content
    soup = BeautifulSoup(returnData, "lxml")

    #mySoup = soup.find('div', {'class': 'responsive'})
    tables = soup.find_all(class_="table table-striped table-bordered")

    column1 = []
    column2 = []
    printResult = ''

    if tables !=[]:
        rows = tables[0].findAll('tr')
        i = 0
        for tr in rows:
            i+=1
            cols = tr.findAll('td')
            column1.append(cols[0].text)
            column2.append(cols[1].text.
                           replace(" Find Sites | IP Whois","").
                           replace(" Google Map",""))
            #Get the Blacklist Status
            if i == 3:
                printResult = cols[1].text
    # Panda Series
    column1 = Series(column1)
    column2 = Series(column2)

    # Concatenate into a DataFrame
    legislative_df = pd.concat([column1, column2], axis=1)

    # Set up the columns
    legislative_df.columns = ['ITEM', 'DATA']

    # Show the finished DataFrame
    #print ('[.] IPVoid Result: ')
    #print (legislative_df,'\n\n')
    return printResult

def sansChecker(IPOrDomain):
    # HTTP Query
    url = "https://isc.sans.edu/api/ip/" + IPOrDomain

    # If the input value is a domain
    re_ip = re.compile('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    if not re_ip.match(IPOrDomain):
        #Try to resolve the domain first
        aRecord = []
        my_resolver = dns.resolver.Resolver()
        my_resolver.nameservers = ['8.8.8.8']
        for rdata in my_resolver.query(IPOrDomain, "A"):
            aRecord.append(rdata.address)
        # Only use the 1st A record
        url = "https://isc.sans.edu/api/ip/" + aRecord[0]

    # Our actual checking begins from here
    printResult = []
    myResult = requests.get(url)
    c = myResult.content
    soup = BeautifulSoup(c, "lxml")
    mySoup = soup.find('error')
    # #print ('[.] SANS Result:')

    # If the input IP has a correct format
    if mySoup is None:
        c = myResult.content
        soup = BeautifulSoup(c, "lxml")
        try:
            reportedTimes = soup.find('count')
            if reportedTimes.text != '':
                #print ('Report Times ' + reportedTimes.text)
                printResult.append('Report Times ' + reportedTimes.text)
            else:
                #print ('Report Times 0')
                printResult.append("Report Times 0")
        except Exception:
            #print ('Report Times 0')
            printResult.append("Report Times 0")

        try:
            targets = soup.find('attacks')
            if targets.text != '':
                #print ('Total Targets ' + targets.text)
                printResult.append('Total Targets ' + targets.text)
            else:
                #print ('Total Targets 0')
                printResult.append('Total Targets 0')
        except Exception:
            #print ('Total Targets 0')
            printResult.append('Total Targets 0')

        try:
            firstReported = soup.find('mindate')
            if firstReported.text != '':
                #print ('First Reported ' + firstReported.text)
                printResult.append('First Reported ' + firstReported.text)
            else:
                #print ('First Reported 0')
                printResult.append('First Reported 0')
        except Exception:
            #print ('First Reported 0')
            printResult.append('First Reported 0')

        try:
            latestReported = soup.find('updated')
            if latestReported.text != '':
                #print ('Recent Report ' + latestReported.text)
                printResult.append('Recent Report ' + latestReported.text)
            else:
                #print ('Recent Report 0')
                printResult.append('Recent Report 0')
        except Exception:
            #print ('Recent Report 0')
            printResult.append('Recent Report 0')

        #print ("\n")

    # Elif the input IP is wrong
    elif mySoup.text == 'bad IP address':
        #print ('We expected a valid IP address.')
        exit()

    return printResult

def abuseipdbChecker(url):

    # e.g. url = "https://www.abuseipdb.com/check/220.191.211.7"
    #      url = "https://www.abuseipdb.com/check/baidu.com"
    # HTTP Query
    myResult = requests.get(url)
    printResult = ''
    #print ("[.] AbuseIPDB Result:")

    # if the input value is invalid, such as 'baidu.comx', 'x.x.x.x.x', etc.
    # Invalid Input: '422 Unprocessable Entity'
    if myResult.status_code == 422:
        #print ('Error: 422 Unprocessable Entity (e.g. http://www.com)')
        #print ("We expected a valid IP address or Domain name.")
        exit()
    else:
        # If domain resolved to an IP
        if url != myResult.url:
            print ("Your request has been resolved to ") + myResult.url
        c = myResult.content
        soup = BeautifulSoup(c, "lxml")

        # Part 1: Locate the reporting times that we want
        # reportTimes = soup.find_all(class_="well")
        mySoup = soup.find('div', {'class': 'col-md-6'})

        # Http Response code is still 200 but we got a message:
        #      'We can't resolve the domain www.comz! Please try your query again.'
        if mySoup is None:
            print ('We expected a valid IP address or Domain name.')
        else:
            # Get the first 'p' tag in <div class="well">
            # You can only put 'find_all' after 'find'
            pTag = mySoup.find('p')
            reportTimes = pTag.find('b')

            # Print reporting times
            try:
                if reportTimes.string == "Important Note:":
                    #print ("Note: You probably input a private IP. Please check again ...")
                    exit()
                else:
                    #print ("Reported" + reportTimes.string + " times")
                    printResult = 'Reported ' + reportTimes.string + ' times'
            # if result equals 'None'
            except Exception:
                reportTimes = 0
                #print ('Reported ' + str(reportTimes) + ' times')
                printResult = 'Reported ' + str(reportTimes) + ' times'
                #print ('')

            # Part 2: Locate the table that we want
            tables = soup.find_all(class_="table table-striped responsive-table")

            if tables != []:
                # Use BeautifulSoup to find the table entries with a For Loop
                rawData = []

                # Looking for every row in a table
                # table[0] is just the format for BeautifulSoup
                rows = tables[0].findAll('tr')

                for tr in rows:
                    cols = tr.findAll('td')
                    for td in cols:
                        # data-title = "Reporter"
                        text = cols[0].text
                        rawData.append(text)
                        # data-title = "Date"
                        text = cols[1].text
                        rawData.append(text)
                        '''
                        # data-title = "Comment" (Ingnored)
                        text = cols[2].text
                        rawData.append(text)
                        '''
                        # data-title = "Categories"
                        text = cols[3].text + '\n'
                        rawData.append(text)

                # Modify rawData
                reporter = []
                date = []
                category = []

                itemNum = len(rawData)
                index = 0

                # For 'reporter'
                index1 = 0
                # For 'date'
                index2 = 1
                # For 'category'
                index3 = 2

                for index in range(0, itemNum - 1):
                    # Make sure this loop will not exceed the limit
                    if index1 <= itemNum - 3:
                        # Reporter
                        reporter.append(rawData[index1].replace('\n', ''))
                        index1 += 3

                        # Date
                        date.append(rawData[index2].replace('\n', ''))
                        index2 += 3

                        # Category
                        category.append(rawData[index3].replace('\n\n', ' | ').replace('\n', ' | '))
                        index3 += 3

                        # Global Index
                        index += 1

                # Panda Series
                reporter = Series(reporter)
                date = Series(date)
                category = Series(category)

                # Concatenate into a DataFrame
                pd.set_option('display.width', 5000)
                legislative_df = pd.concat([date, reporter, category], axis=1)

                # Set up the columns
                legislative_df.columns = ['Date', 'Reporter', 'Category']

                # Delete the dups and reset index (and drop the old index)
                legislative_df = legislative_df.drop_duplicates().reset_index(drop=True)

                # Show the finished DataFrame
                #Using IPython instead ($ sudo pip install ipython)
                #print legislative_df,
                #display(legislative_df)

                #print ('')

    return printResult

def myXForceChecker(url):

    # User: 473284ee-2c45-4719-a201-5e6c81c0253a
    # Password: 8acd0774-7238-4ad7-bc09-a2003ca6e80f

    # Auth first
    #print ('')
    #print ('[.] IBM X-Force Result:')

    printResult = []
    # e.g. url = "https://exchange.xforce.ibmcloud.com/ip//114.200.4.207"
    # IP Report
    myResult1 = requests.get(url, auth=HTTPBasicAuth('473284ee-2c45-4719-a201-5e6c81c0253a',
                                                     '8acd0774-7238-4ad7-bc09-a2003ca6e80f'))
    c1 = myResult1.content
    myJson1 = json.loads(c1)

    # >>>>>>>>>>>  IP/Domain Report Check <<<<<<<<<<<<<
    # ...........
    '''
    # indent = 2
    # json.dumps() change data to python dictionary
    # sortedData = json.dumps(myJson1, sort_keys=True, indent=2)
    # print sortedData
    '''

    #----------These three keys are for IP checker----------
    # [Print] Geo information
    if "geo" in myJson1:
        for key, value in myJson1["geo"].items():
            geo = "Country" + ": " + str(value)
            #print (geo)
            printResult.append(geo)
            # Only print country
            # (Ingore country code)
            break
    # [Print] Overrall Risk Score
    if "score" in myJson1:
        if myJson1["score"] == 1:
            #print ("Risk Score: " + str(myJson1["score"]) + " (low)")
            printResult.append("Risk Score: " + str(myJson1["score"]) + " (low)")
        else:
            #print ("Risk Score: " + str(myJson1["score"]))
            printResult.append("Risk Score: " + str(myJson1["score"]))
    # [Print] Categorization:
    if "cats" in myJson1:
        if myJson1["cats"]:
            for key, value in myJson1["cats"].items():
                cat = str(key) + " (" + str(value) + "%)"
                #print ("Categorization: " + cat)
                printResult.append("Categorization: " + cat)
        else:
            #print ("Categorization: Unsuspicious")
            printResult.append("Categorization: Unsuspicious")


    # ----------These keys are for Domain checker----------
    if "result" in myJson1:
        myJsonResult = myJson1["result"]
        if myJsonResult["score"] == 1:
            #print ("Risk Score: " + str(myJsonResult["score"]) + " (low)")
            printResult.append("Risk Score: " + str(myJsonResult["score"]) + " (low)")
        else:
            #print ("Risk Score: " + str(myJsonResult["score"]))
            printResult.append("Risk Score: " + str(myJsonResult["score"]))

        if myJsonResult["categoryDescriptions"]:
            for key, value in myJsonResult["categoryDescriptions"].items():
                cat = "<" + str(key).replace(" / ", "|") + ">: " + str(value)
                #print (cat)
                printResult.append(cat)

    return printResult

def ipReputationChecker():

    # Call myIPwhois.py
    #myIPwhois.IPWhoisChecker("https://www.abuseipdb.com/whois/" + sys.argv[1])

    # Call ipvoid.py
    myIPvoidPrint1 = ipvoidChecker(sys.argv[1])
    # Call sans.py
    mySansPrint2 = sansChecker(sys.argv[1])
    # Call abuseipdb.py
    myAbuseIPDBPrint3 = abuseipdbChecker("https://www.abuseipdb.com/check/" + sys.argv[1])
    # Call xforceIBM.py
    myXForcePrint4 = myXForceChecker("https://api.xforce.ibmcloud.com/ipr/" + sys.argv[1])

    message = "[.] IPVoid Result: " + myIPvoidPrint1 + '\n' +\
              "[.] SANS Result: " + ' | '.join(mySansPrint2) + '\n' +\
              "[.] AbuseIPDB Result: " + myAbuseIPDBPrint3 + '\n' +\
              "[.] XForce Result:  " + ' | '.join(myXForcePrint4)
    print(message)


def main():
    try:
        re_ip = re.compile(ip_regex)
        if re_ip.match(sys.argv[1]):
            # print('[+] IP Regex successful matches ...')
            ipReputationChecker()
        else:
            print('[-] WARNING: Please type a valid IPv4 address.')
    except IndexError:
        print("[-] ERROR: List index out of range")


if __name__ == '__main__':
    main()
