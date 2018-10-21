import sys,re

# Domain Validation with Regex
#  ^(?!:\/\/)
#   ([a-zA-Z0-9-_]+\.)*
#   [a-zA-Z0-9][a-zA-Z0-9-_]+\.
#   [a-zA-Z]{2,11}?$
domain_regex="^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?$"

re_ip = re.compile(domain_regex)
if re_ip.match(sys.argv[1]):
    print('Matched!')
else:
    print('Warning: Domain Not Matched!')
    exit()
