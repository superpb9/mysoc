#!/bin/bash

# Windows 10 Environment
# pythonEXE="/mnt/c/Users/superpb9/AppData/Local/Programs/Python/Python37/python.exe"
#PROJECT_PATH="/Users/pippo-mbp2016/Documents/myProject/mysoc/"
PROJECT_PATH="/mnt/c/Users/superpb9/iCloudDrive/Documents/myProject/mysoc/"

# Define a usage() function
usage (){
  echo "Usage: ${0} [-i IPv4][-d Domain][-s ET Signature]" >&2
  echo "The script acts as a single entrance for all soc tools, developed by superpb9." >&2
  echo "    -i   Call IP Reputation Checker." >&2
  echo "    -d   Call Domain Reputation Checker." >&2
  echo "    -s   Search ET Signature online." >&2  # http://docs.emergingthreats.net/bin/view/Main/2001978
  exit 1
}

# Allow user to specify the following options. Any other option will cause the script to display a usage statement
while getopts i:d:s: OPTION
do
  case  ${OPTION} in
    i) IP_REP_CHECK='true' IP_RECEIVED="${OPTARG}" ;;
    d) DOMAIN_REP_CHECK='true' DOMAIN_RECEIVED="${OPTARG}" ;;
    s) ET_SIGNATURE_CHECK='true' ET_RECEIVED="${OPTARG}" ;;
    ?) usage ;;
  esac
done

# Ingore all the optional arguments and remove the options while leaving the remaining arguments.
# OPTIND is set to the index of the first non-option argument, and name is set to ?
# e.g. OPTIND will become '7' after [./superpb9.sh -i 8.8.8.8 -d www.google.com -s 200012]
shift "$(( OPTIND - 1 ))"

# Domain Format check using regex
echo "You've asked to check IP: ${IP_RECEIVED}"
# Domain Format check using regex
echo "You've asked to check Domain: ${DOMAIN_RECEIVED}"
# ET Signature Format check using regex
echo "You've asked to check ET Signature: ${ET_RECEIVED}"
echo ''

# Note: Python will do the IPv4 Validation
echo "Now calling IP Reputation Checker ..."
CMDLINE_STR="python3 ${PROJECT_PATH}/ipReputation/ipReputation.py ${IP_RECEIVED}"
OUTPUT=$(eval "$CMDLINE_STR")
echo "${OUTPUT}"

echo "Now calling Domain Reputation Checker ..."
CMDLINE_STR="python3 ${PROJECT_PATH}/domainReputation/domainReputation.py ${DOMAIN_RECEIVED}"
OUTPUT=$(eval "$CMDLINE_STR")
echo "${OUTPUT}"