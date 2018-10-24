import sys,re,os,subprocess

# Domain Validation with Regex
#  ^(?!:\/\/)
#   ([a-zA-Z0-9-_]+\.)*
#   [a-zA-Z0-9][a-zA-Z0-9-_]+\.
#   [a-zA-Z]{2,11}?$
domain_regex="^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?$"


if __name__ == '__main__':
    try:
        re_domain = re.compile(domain_regex)
        if re_domain.match(sys.argv[1]):
            print('[+] Domain Regex successful matches ...')
            print('[+] Linux DIG Answer Section')
            # Call Linux DIG
            #os.system('dig %s @8.8.8.8 +noall +answer | grep -Ev \'\^\$\' | grep -Ev "^; <<>>" | grep -Ev ";; global"' %(sys.argv[1]))
            process = os.popen('dig %s @8.8.8.8 +noall +answer | grep -Ev "^;" | grep -Ev ";;" | grep -Ev \'^$\'' %(sys.argv[1]))
            print(process.read())
            process.close()
            #domainReputationChecker()
            # ... ...
        else:
            print('[-] Warning: Please type a valid Domain.')
    except IndexError:
        print("[-] Error: List index out of range")
