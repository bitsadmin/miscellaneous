# Title: Pseudocode for attacking the OSCP lab network
# Author: Arris Huijgen (@bitsadmin)
# Website: https://github.com/bitsadmin/

# GENERAL NOTES
# - The OSCP lab was built pre-EternalBlue, therefore many machines are vulnerable to this exploit but you won't learn anything if you exploit machines this way.
# - Make notes! What I used was a Notebook in OneNote with a section for each network segment, and a dedicated page for every host.
#     - I used a page template which contains sections for:
#         - IP(s) and hostname
#         - Raw notes
#         - Open ports (TCP/UDP)
#         - Network interfaces
#         - Credentials
#         - Filesystem (proof.txt/network-secret.txt)
#     - Filling in this template forces you to properly perform reconnaissance on every host
#     - Use this same structure on your filesystem for files collected from these hosts
# - Have some very old Linux VM (I used CentOS 4.8) to compile exploit sourcecode. Have an SSH server running on this machine and download the binaries to Kali via SFTP.
# - Spend a lot of time in the labs and #TRYHARDER or temporarily move on to another machine whenever you are stuck

# TIPS & TRICKS
# - Use the instructions in wget.cmd to download files from the Windows command prompt
# - On Linux after obtaining a (reverse) TCP shell it is often useful to turn it into a TTY shell to for example remain interactive with commands like 'sudo -s'
#     - Paste into the TCP shell: python -c 'import pty; pty.spawn("/bin/sh")'
# - Whenever an automated (Metasploit/script) exploit fails, inspect the traffic using WireShark to identify any issues
# - ...

# PREPARATION
# - Configure your Kali for example using the configure.sh script from https://github.com/bitsadmin/linuxconfig
# - Add additional console aliases for increased productivity, for example the scripts from https://github.com/bitsadmin/linuxconfig -> console
# - Familiarize yourself with the -D, -L and -R parameters of Linux' ssh client for pivoting
# - ...


def main():
    # Obtain a quick insight into the network using quickscan
    execute_script('https://github.com/bitsadmin/miscellaneous', 'quickscan')
    
    for machine in lab:
        # Perform full nmap UDP scan
        tcp_ports = perform_nmap(tcp)
        
        for port in tcp_ports:
            # Perform reconnaissance to obtain:
            # - Software running on the port
            # - Version information of software
            
            exploited = attempt_exploit(machine, port)

        if not exploited:
            # Perform full nmap UDP scan
            udp_ports = perform_nmap(udp) 


def attempt_exploit(machine, port):
    # 1. Search exploit using Kali's searchsploit tool
    # 2. Update payload to for example a reverse Meterpreter shell to your IP
    # 3. Attempt exploit
    # 4. If not working, but should work, revert the VM and try again
    
    shell = exploit(machine, port)
    
    if shell:
        local_recon()

    # From shell with limited privileges, escalate to a high-privileged user
    escalate()

    # Collect your proof.txt file and dump any other credential material you can now access
    # Add this information to your notes as you might need it later
    collect()


def local_recon():
    if windows:
        # Download localrecon.cmd in limited Windows shell
        # See https://github.com/bitsadmin/miscellaneous -> wget.cmd
        results = execute_script('https://github.com/bitsadmin/miscellaneous', 'localrecon.cmd')
        # Evaluate results looking for any:
        # - Passwords
        # - Non-default software installed -> Identify software version and check if exploitable
        # - Missing patches using https://github.com/bitsadmin/wesng
    
    elif linux:
        results = execute_script('https://github.com/mzet-/linux-exploit-suggester', 'linux-exploit-suggester.sh')
        # Evaluate results looking for any:
        # - Credential material
        # - Exploits for vulnerable software
        # - Weak file system permissions    


if __name__ == '__main__':
    main()
