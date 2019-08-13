#!/bin/bash
#
# This software is provided under under the BSD 3-Clause License.
# See the accompanying LICENSE file for more information.
#
# Script to obtain a quick insight into an unknown network
# storing the results in a structured way.
#
# Author:
#  Arris Huijgen (@bitsadmin)
#
# Website:
#  https://github.com/bitsadmin/
#

# Instructions
# 1. Place the wordlists in the /root/hosts/_credentials folder:
#    - Generic list of users in users.txt (i.e. admin, administrator, user)
#    - Generic list of passwords in passwords.txt (i.e. admin, password, 1234)
#    - Service-specific list of users in users_[service].txt (i.e. for MySQL stored in users_mysql.txt: root, mysql)
#    - Service-specific list of passwords in passwords_[service].txt
# 2. Define the scope to be scanned below
# 3. Execute the script and wait for the results to appear in the /root/hosts/* folder structure

# Scope
cat > hosts.txt << END
10.11.1.0/24
10.11.2.5
END

# Extract last octet from IP address
function get-lastoctet {
    printf "%03d" $(echo "$1"|cut -d'.' -f 4)
}

# Compile output filename
function get-outfile {
    local ext=.txt
    if [ ! -z $3 ]
    then
        if [ $3 = "null" ]
        then
            ext=
        else
            ext=.$3
        fi
    fi
    printf "./%s/%s%s" $(get-lastoctet $1) $2 $ext
}

# Fetch path to tool-specific wordlist
function get-wordlist {
    local wltype=$1
    local tool=$2
    basedir="/root/hosts/_credentials"
    basefile="${basedir}/${wltype}.txt"
    toolfile="${basedir}/${tool}_${wltype}.txt"
    if [ -f "$toolfile" ]
    then
        outfile="/tmp/${tool}_${wltype}_$RANDOM.txt"
        cat $toolfile $basefile|sort -u>$outfile
        echo $outfile
        return
    fi
    echo $basefile
}

# ARP scan for quick insight
#start=$SECONDS
#arp-scan -I tap0 $iprange > arp-scan.txt
#echo "ARP scan took: $(($SECONDS-$start)) seconds"

# Perform Nmap Initial scan
start=$SECONDS
echo "Running initial Nmap scan"
nmap -F -n -T4 -iL hosts.txt -oA quick
echo "NMap Initial scan took: $(($SECONDS-$start)) seconds"
ips=$(grep 'Status: Up' quick.gnmap|cut -d' ' -f2)

# Create folders for output
for ip in $ips
do
    mkdir $(get-lastoctet $ip)
done

# Make screenshots of all found supported protocols found
eyewitness -x $(pwd)/quick.xml --threads 5 --timeout 3 --all-protocols -d $(pwd)/eyewitness

# Run various tools against found TCP ports
for ip in $ips
do
    start=$SECONDS
    echo "Running Nmap TCP scan against ${ip}"
    timeout --signal=INT 900 nmap -T4 -sV -sC -p- $ip -oA $(get-outfile $ip nmap_tcp null)
    rc=$?
    if [[ $rc != 0 ]]
    then
        echo $ip >> timedout_tcp
        continue
    fi
    echo "NMap TCP scan took: $(($SECONDS-$start)) seconds"

    # HOST TIMER
    hstart=$SECONDS
    
    openports=$(sed -n -e 's/.*Ports: //;s_\([0-9]\{1,5\}/[^/]*/[^/]*/[^/]*/[^/]*/[^/]*/[^/]*/\),\?\s_\1\n_;t     matched;d;:matched;P;D' $(get-outfile $ip nmap_tcp gnmap)|grep /open/)
    while read -r port
    do
        # PORT TIMER
        pstart=$SECONDS
        portname="$(echo "$port"|cut -d"/" -f5)"
        portid="$(echo "$port"|cut -d"/" -f1)"

        # Skip tcpwrapped ports and hosts without any open TCP ports
        if [[ $portname == "tcpwrapped" || $portname == "" ]]
        then
            continue
        fi

        echo "Checking ${portid}/TCP (${portname})"
        
        # HTTP (80)
        if [[ $portname == "http" || $portname == "http?" ]]
        then
            nikto -nossl -host $ip -port $portid -output $(get-outfile $ip nikto_${portid}_http)
            wfuzz -c -z file,wordlist/general/big.txt --hc 404 -R 0 http://$ip:$portid/FUZZ > $(get-outfile $ip wfuzz_${portid}_http)
            eyewitness --web -d $(get-outfile $ip eye-http null) --no-prompt --add-http-ports $portid --single $ip:$portid
        
        # HTTPS (443)
        elif [[ $portname == "https" || $portname == "https?" || $portname == "ssl|http" ]]
        then
            nikto -ssl -host $ip -port $portid -output $(get-outfile $ip nikto_${portid}_https)
            wfuzz -c -z file,wordlist/general/big.txt --hc 404 -R 0 https://$ip:$portid/FUZZ > $(get-outfile $ip wfuzz_${portid}_https)
            eyewitness --web -d $(get-outfile $ip eye-https null) --no-prompt --add-https-ports $portid --single $ip:$portid
        
        # FTP (21)
        elif [[ $portname == "ftp" || $portname == "ftp?" ]]
        then
            medusa -h $ip -U $(get-wordlist users ftp) -P $(get-wordlist passwords ftp) -O $(get-outfile $ip medusa-ftp) -e ns -M ftp -n $portid -t 10
        
        # SSH (22)
        elif [[ $portname == "ssh" ]]
        then
            medusa -h $ip -U $(get-wordlist users ssh) -P $(get-wordlist passwords ssh) -O $(get-outfile $ip medusa-ssh) -e ns -M ssh -n $portid -t 10
        
        # MSSQL (1433)
        elif [[ $portname == "ms-sql" || $portname == "ms-sql-s" ]]
        then
            medusa -h $ip -U $(get-wordlist users mssql) -P $(get-wordlist passwords mssql) -O $(get-outfile $ip medusa-mssql) -e ns -M mssql -n $portid -t 10
        
        # MySQL (3306)
        elif [[ $portname == "mysql" || $portname == "mysql?" ]]
        then
            nmap -sT -p3306 --script mysql-brute $ip -oA $(get-outfile $ip nmap_mysql null)
            medusa -h $ip -U $(get-wordlist users mysql) -P $(get-wordlist passwords mysql) -O $(get-outfile $ip medusa-mysql) -e ns -M mysql -n $portid -t 10
        
        # NetBIOS (139)
        elif [[ $portname == "netbios-ssn" ]]
        then
            enum4linux -a $ip >$(get-outfile $ip enum4linux)
            timeout --signal=INT 900 nmap -T4 -sU -sT -p U:137,T:139 --script "vuln" $ip -oN $(get-outfile $ip nmap_netbios nmap)
        
        # Microsoft-ds (445)
        elif [[ $portname == "microsoft-ds" ]]
        then
            enum4linux -a $ip >$(get-outfile $ip enum4linux)
            timeout --signal=INT 900 nmap -T4 -sT -p139,445 --script "smb-vuln-*" $ip -oN $(get-outfile $ip nmap_smbvuln nmap)
        
        # Telnet (23)
        elif [[ $portname == "telnet" || $portname == "telnet?" ]]
        then
            medusa -h $ip -U $(get-wordlist users telnet) -P $(get-wordlist passwords telnet) -O $(get-outfile $ip medusa-telnet) -e ns -M telnet -n $portid -t 10
        
        # Oracle TNS listener
        elif [[ $portname == "oracle-tns" ]]
        then
            oscanner -s $ip -P $portid > $(get-outfile $ip oracle-tns)
        
        # VNC (5900)
        elif [[ $portname == "vnc" ]]
        then
            #eyewitness --vnc -d $(get-outfile $ip eye-vnc null) --no-prompt --single $ip
            medusa -h $ip -U $(get-wordlist users vnc) -P $(get-wordlist passwords vnc) -O $(get-outfile $ip medusa-rdp) -e ns -M vnc -n $portid -t 10
        
        # SMTP (25)
        elif [[ $portname == "smtp" ]]
        then
            smtp-user-enum -U $(get-wordlist users) -t $ip -p $portid > $(get-outfile $ip smtp-users)
            smtp-user-enum -U $(get-wordlist users_extensive) -t $ip -p $portid > $(get-outfile $ip smtp-users_extensive)
            smtp-user-enum -U $(get-wordlist names) -t $ip -p $portid > $(get-outfile $ip smtp-names)
        
        # RDP (3389)
        elif [[ $portname == "ms-wbt-server" ]]
        then
            medusa -h $ip -U $(get-wordlist users rdp) -P $(get-wordlist passwords rdp) -O $(get-outfile $ip medusa-rdp) -e ns -M rdp -n $portid -t 10
        
        # RPCBIND (111)
        elif [[ $portname == "rpcbind" ]]
        then
            rpcinfo -p $ip > $(get-outfile $ip rpcinfo) 2>&1
            showmount -e $ip $(get-outfile $ip showmount) 2>&1
        fi
        
        # TIMER
        echo "Port took: $(($SECONDS-$pstart)) seconds"
    done <<< "$openports"
    
    # TIMER
    echo "Host took: $(($SECONDS-$hstart)) seconds"
done

# More advanced checks
for ip in $ips
do
    openports=$(sed -n -e 's/.*Ports: //;s_\([0-9]\{1,5\}/[^/]*/[^/]*/[^/]*/[^/]*/[^/]*/[^/]*/\),\?\s_\1\n_;t     matched;d;:matched;P;D' $(get-outfile $ip nmap_tcp gnmap)|grep /open/)
    
    while read -r port
    do
        # PORT TIMER
        pstart=$SECONDS
        portname="$(echo "$port"|cut -d"/" -f5)"
        portid="$(echo "$port"|cut -d"/" -f1)"
        
        # HTTP
        if [[ $portname == "http" || $portname == "http?" ]]
        then
            wfuzz -c -z file,wordlist/general/big.txt --hc 404 -R 0 http://$ip:$portid/FUZZ.html > $(get-outfile $ip wfuzz_${portid}_http-html)
            eyewitness --web -d $(get-outfile $ip eye-http null) --no-prompt --add-http-ports $portid --single $ip:$portid
        
        # HTTPS
        elif [[ $portname == "https" || $portname == "https?" || $portname == "ssl|http" ]]
        then
            wfuzz -c -z file,wordlist/general/big.txt --hc 404 -R 0 https://$ip:$portid/FUZZ.html > $(get-outfile $ip wfuzz_${portid}_https-html)
            eyewitness --web -d $(get-outfile $ip eye-https null) --no-prompt --add-https-ports $portid --single $ip:$portid
        fi
    done <<< "$openports"
done

# Perform Nmap top 1000 UDP scan
start=$SECONDS
for ip in $ips
do
    echo "Running Nmap UDP scan against ${ip}"
    timeout --signal=INT 900 nmap -T4 -sU -sV -sC --top-ports 1000 $ip -oA $(get-outfile $ip nmap_udp null)
    rc=$?
    if [[ $rc != 0 ]]
    then
        echo $ip >> timedout_udp
        continue
    fi
    
    # Run various tools against found UDP ports
    openports=$(sed -n -e 's/.*Ports: //;s_\([0-9]\{1,5\}/[^/]*/[^/]*/[^/]*/[^/]*/[^/]*/[^/]*/\),\?\s_\1\n_;t     matched;d;:matched;P;D' $(get-outfile $ip nmap_udp gnmap)|grep /open)

    # SNMP (161)
    if [[ $portname == "snmp" || $portname == "snmp?" ]]
    then
        snmp-check -v 2c $ip>$(get-outfile $ip snmpcheck)
    
    # DNS (53)
    elif [[ $portname == "domain" ]]
    then
        snmp-check -v 2c $ip>$(get-outfile $ip snmpcheck)
    
    # Netbios-ns (137)
    elif [[ $portname == "netbios-ns" ]]
    then
        nbtscan -v $ip >$(get-outfile $ip nbtscan txt)
    fi
done
echo "NMap UDP scan took: $(($SECONDS-$start)) seconds"