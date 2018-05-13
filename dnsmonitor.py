# MIT License
# Copyright 2018 (C) dexoidan
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#!/usr/bin/env python
import sys
import os.path
import os
from subprocess import Popen, PIPE, STDOUT
import subprocess

# Network interface configuration
netwInt = ''

# Useful for monitoring tasks without output to stdout
def run_subcommand_shell(cmd):
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    output = p.stdout.read()
    print('The operation has successfully completed.')

# Real time output to stdout
def run_commandline_shell(cmd):
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout = []
    while True:
        line = p.stdout.readline()
        dump_log_file(line)
        stdout.append(line)
        print line,
        if line == '' and p.poll() != None:
            break
    return ''.join(stdout)

# writing text log file with stdout output
# text log file is overwritten when the program runs for first time
def dump_log_file(textstring):
    filehandler = open("dnsmonitor-logfile.txt","a+")
    filehandler.write(textstring)
    filehandler.close()

def check_tcpdump_placement():
    if os.path.isfile("/usr/sbin/tcpdump"):
        print('tcpdump ok!')
        print('Notice: tcpdump needs to have root privileges before it runs')
    else:
        print('tcpdump does not exists!')

def check_sudo_permission():
    if os.getuid() == 0:
        print('Checking root privileges [OK]')
    else:
        print("I cannot run as a mortal. Sorry. You are not running the program with root privileges.")

def dnsmonitor_install_tcpdump():
    print('Updating the system to have tcpdump installed!')
    try:
        # Command that installs and updating tcpdump to the latest version available
        run_subcommand_shell("sudo apt-get install -y tcpdump")
    except Exception as e:
        print(e.message)
    print('\r')
    sys.exit()

def dnsmonitor_monitor_realtime():
    try:
        check_tcpdump_placement()
        check_sudo_permission()
        # Dynamically runs tcpdump with the specific network interface to capture DNS network traffic and printing without timestamps
        run_commandline_shell("sudo tcpdump -i {0} -t udp port 53".format(netwInt))
    except Exception as e:
        print(e.message)
    finally:
        print('\r')
        print('Read text log file `dnsmonitor-logfile.txt` with the tcpdump command text from standard output')
        sys.exit()

def dnsmonitor_capture():
    # Reading captured network packets from pcap: tcpdump -r dnsmonitor-packets.pcap
    try:
        check_tcpdump_placement()
        check_sudo_permission()
        run_subcommand_shell("sudo tcpdump -i {0} udp port 53 -s 65535 -w dnsmonitor-packets.pcap".format(netwInt))
    except Exception as e:
        print(e.message)
    finally:
        print('\r')
        print('You can run following command: `sudo tcpdump -r dnsmonitor-packets.pcap` for reading the full-captured network packets in the pcap file.')
        sys.exit()

def main():
    print('\ndnsmonitor v1.01\n')
    print('dnsmonitor script program can listen for network traffic to capture DNS requests and response')
    # Call the dnsmonitor method that is needed to be used
    # dnsmonitor_install_tcpdump()
    # dnsmonitor_capture()
    dnsmonitor_monitor_realtime()

if __name__ == '__main__':
    main()
