#!/bin/bash
ips=10.11.1.0/24
username=$1
password=$2

nmap -sT -T4 -p445 $ips -oA creds
ips=$(grep 'Status: Up' creds.gnmap|cut -d' ' -f2)

for ip in $ips
do
	openports=$(sed -n -e 's/.*Ports: //;s_\([0-9]\{1,5\}/[^/]*/[^/]*/[^/]*/[^/]*/[^/]*/[^/]*/\),\?\s_\1\n_;t     matched;d;:matched;P;D' $(get-outfile $ip nmap_tcp gnmap)|grep /open/)
	
	while read -r port
    do
		# NetBIOS
        elif [[ $portname == "netbios-ssn" ]]
        then
			smbclient -L //10.11.1.220/ -U $username%$password
			if [[ $? == 0 ]]
			then
				echo [+] Found credentials to work on SMB of host 10.11.1.220
			fi
		fi
    done <<< "$openports"
done
