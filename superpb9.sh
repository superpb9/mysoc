#!/bin/bash

# Windows 10 Environment
# pythonEXE="/mnt/c/Users/superpb9/AppData/Local/Programs/Python/Python37/python.exe"
# PROJECT_PATH="/mnt/c/Users/superpb9/iCloudDrive/Documents/myProject/mysoc/"

# Mac OSX Environment
PROJECT_PATH="/Users/pippo-mbp2016/mysoc_clone"

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

if [[ "${IP_REP_CHECK}" = true ]]
then
    echo "[+] Now calling 'ipReputation.py' to check ${IP_RECEIVED} ..."
    # Note: Python will do the IPv4 Validation
    CMDLINE_STR="python3 -u ${PROJECT_PATH}/ipReputation/ipReputation.py ${IP_RECEIVED}"
    OUTPUT=$(eval "$CMDLINE_STR")
    echo "${OUTPUT}"
    echo ""
fi

if [[ "${DOMAIN_REP_CHECK}" = true ]]
then
    echo "[+] Now calling 'domainReputation.py' to check ${DOMAIN_RECEIVED}"
    # Note: Python will do the Domain Validation
    CMDLINE_STR="python3 ${PROJECT_PATH}/domainReputation/domainReputation.py ${DOMAIN_RECEIVED}"
    OUTPUT=$(eval "$CMDLINE_STR")
    echo "${OUTPUT}"
    echo ""
fi


# ET Signature Format check using regex
echo "[+] You've asked to check ET Signature: ${ET_RECEIVED}"
echo ''

