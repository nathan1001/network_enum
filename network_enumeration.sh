#!/bin/bash

# Function to display help message
usage() {
    echo "Usage: $0 <nmap_output_file> --check <all|ports|eternalblue|anonymous|bluekeep|rdp|defaultcreds|httpmethods|kyocera|sslscan|cisco>"
    echo "Options:"
    echo "  all          Run all checks"
    echo "  ports        Extract hosts for specified ports from the Nmap output"
    echo "  eternalblue  Check for Eternal Blue vulnerability using Metasploit"
    echo "  anonymous    Check for anonymous FTP login using Metasploit"
    echo "  bluekeep     Check for BlueKeep vulnerability using Metasploit"
    echo "  rdp          Check for RDP NLA using Metasploit"
    echo "  defaultcreds Check for default RDP credentials using Hydra"
    echo "  httpmethods  Check HTTP and HTTPS methods using Metasploit"
    echo "  kyocera      Run Kyocera printer exploit"
    echo "  sslscan      Perform SSL scan using sslscan"
    echo "  cisco        Run Cisco Smart Install exploit"
    exit 1
}

# Check if no arguments were provided or help was requested
if [ $# -eq 0 ] || [[ "$1" == "-h" || "$1" == "--help" ]]; then
    usage
fi

# Check if the required arguments are provided
if [ $# -lt 2 ]; then
    echo "Error: Invalid number of arguments."
    usage
fi

NMAP_OUTPUT=$1
CHECK_OPTION=$2

# Validate the check option
valid_options=("all" "ports" "eternalblue" "anonymous" "bluekeep" "rdp" "defaultcreds" "httpmethods" "kyocera" "sslscan" "cisco")
if [[ ! " ${valid_options[@]} " =~ " ${CHECK_OPTION} " ]]; then
    echo "Error: Invalid check option."
    usage
fi

# Function to extract ports from Nmap output
extract_ports() {
    for x in 21 22 23 53 80 139 161 443 3306 3389 2049 6379 1433 1521 445 8080 9091 4786
    do
        cat $NMAP_OUTPUT | grep Host: | grep $x | cut -d ' ' -f 2 > port_$x.txt
    done
}

# Function to run Eternal Blue check
check_eternalblue() {
    echo "Eternal Blue Check Started"
    msfconsole -q -x "use auxiliary/scanner/smb/smb_ms17_010;set threads 200;set rhost file://port_445.txt;run;exit;" | grep "Host is likely VULNERABLE to MS17-010! " | cut -d ' ' -f 2 | tee eternal_blue
    echo "Eternal Blue Check Completed"
}

# Function to run Anonymous Login check
check_anonymous() {
    echo "Anonymous Login Check Started"
    msfconsole -q -x "use auxiliary/scanner/ftp/anonymous;set threads 200;set rhost file://port_21.txt;run;exit;" | grep "Anonymous READ" | cut -d ' ' -f 2 | tee anonymous_login
    echo "Anonymous Login Check Completed"
}

# Function to run BlueKeep check
check_bluekeep() {
    echo "BlueKeep Check Started"
    msfconsole -q -x "use auxiliary/scanner/rdp/cve_2019_0708_bluekeep;set threads 200;set rhost file://port_3389.txt;run;exit;" | grep "The target is vulnerable" | cut -d " " -f 2 | tee blue_keep
    echo "BlueKeep Check Completed"
}

# Function to run RDP NLA check
check_rdp() {
    echo "RDP NLA Check Started"
    msfconsole -q -x "use auxiliary/scanner/rdp/rdp_scanner;set threads 200;set rhost file://port_3389.txt;run;exit;" | grep -a "Requires NLA: No" | cut -d " " -f 2 | cut -d ":" -f 1 | tee nla
    echo "RDP NLA Check Completed"
}

# Function to check default RDP credentials
check_defaultcreds() {
    echo "Checking Default RDP Credentials"
    hydra -l Administrator -p 'P@ssw0rd' -M nla rdp -o rdp_default_credentials.txt -V
}

# Function to check HTTP and HTTPS methods
check_httpmethods() {
    echo "HTTP Methods Check Started"
    msfconsole -q -x "use auxiliary/scanner/http/options;set threads 200;set rhost file://port_80.txt;run;exit;" | grep "allow" | cut -d " " -f 2 | tee http_methods
    echo "HTTPS Methods Check Started"
    msfconsole -q -x "use auxiliary/scanner/http/options;set threads 200;set rport 443;set rhost file://port_443.txt;run;exit;" | grep "allow" | cut -d " " -f 2 | tee https_methods
}

# Function to run Kyocera exploit
check_kyocera() {
    echo "Running Kyocera Exploit"
    for addr in $(cat port_9091.txt); do python3 /root/Documents/kyo_exploit.py $addr | tee $addr & done
}

# Function to perform SSL scan
check_sslscan() {
    echo "Performing SSL Scan"
    sslscan --ssl2 --ssl3 --tls1 --tls11 --targets=port_443.txt > port_443_ssl_report.txt
    cat port_443_ssl_report.txt | grep Connected | cut -d " " -f 3 | tee sort_ssl_ips
}

# Function to run Cisco Smart Install exploit
check_cisco() {
    echo "Running Cisco Smart Install Exploit"
    for addr in $(cat port_4786.txt); do python3 /root/Documents/smart_install_exploit.py $addr | tee $addr & done
}

# Execute the requested checks
case $CHECK_OPTION in
    "all")
        extract_ports
        check_eternalblue
        check_anonymous
        check_bluekeep
        check_rdp
        check_defaultcreds
        check_httpmethods
        check_kyocera
        check_sslscan
        check_cisco
        ;;
    "ports")
        extract_ports
        ;;
    "eternalblue")
        extract_ports
        check_eternalblue
        ;;
    "anonymous")
        extract_ports
        check_anonymous
        ;;
    "bluekeep")
        extract_ports
        check_bluekeep
        ;;
    "rdp")
        extract_ports
        check_rdp
        ;;
    "defaultcreds")
        extract_ports
        check_defaultcreds
        ;;
    "httpmethods")
        extract_ports
        check_httpmethods
        ;;
    "kyocera")
        extract_ports
        check_kyocera
        ;;
    "sslscan")
        extract_ports
        check_sslscan
        ;;
    "cisco")
        extract_ports
        check_cisco
        ;;
    *)
        echo "Error: Invalid check option."
        usage
        ;;
esac



########################################################################################################################################################################################################################################################################################################################

#########################################################################################################################################################################################################################################################################################################################

#Kyocera CREDENTIAL LEAKAGE
#for addr in $(cat port_9091.txt);do python3 /root/Documents/kyocera_exploit.py $addr | tee $addr &done

#########################################################################################################################################
#echo "---------------cisco_smart_install_test------------------------------- "
#echo "------------------------------------------------------------"


#chmod 755 cisco_small_intall_CVE-2018-0171.py

#for addr in $(cat port_4786.txt);do python3 /root/Documents/smart_install_exploit.py $addr | tee $addr &done

#fi

#./kyocera_printer_exploit.py
#./cisco_small_intall_CVE-2018-0171.py
