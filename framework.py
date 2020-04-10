import sys
import pyshark
import os
import nmap
import time
from prettytable import from_csv

print("Options: 1.LiveCapture, 2.ListService, 3.JohnTheRipper a Zip file, 4.Nmap, 5. PrettyTable")
inp = int(input("Please enter the choice number: "))

if inp == 1:
	print("Please update the target ip address and eth in the script")	
	filename = input("Please enter the file name to keep LiveCapture results: ")
	cap = pyshark.LiveCapture(interface='eth0')
	cap.sniff(packet_count=100)
	for pkt in cap:
		sys.stdout = open(filename, 'w')
		print(pkt)
	sys.stdout.close()

elif inp == 2:	
	service = os.system('ps aux')
	print(service)

elif inp == 3:
	print("Please update the document name of password list and hash list in the script")
	zipfile = input('Please enter the zip file name: \n')
	c = "/usr/sbin/zip2john %s > out.txt" %zipfile

	try:
		os.popen(c)
		print("zip file hash created")

	except:
		print('zip file does not exist')
		exit()

	os.popen('john --wordlist=rockyou.txt out.txt > result')
	time.sleep(5)

	f = open('result')
	print(f)
	for line in f:
		line = line.rstrip()
		if line.startswith('Loaded'):
			continue
		elif line.startswith('No'):
			print('the password was detected previously, please check /root/.john/*.pot')
			exit()
		pwd = line.split()
		print('Password is: ', pwd[0])

	exit()

elif inp == 4:

	print("Please update the target host ip address and port range to be scanned in the script")
	nmscan = nmap.PortScanner()

	nmscan.scan('192.168.2.1','20-90')

	for host in nmscan.all_hosts():
		print('Host: %s (%s)' % (host, nmscan[host].hostname()))
		print('State: %s' % nmscan[host].state())
		for proto in nmscan[host].all_protocols():
			print('Protocol: %s ' % proto)
			lport = nmscan[host][proto].keys()
			for port in lport:
				print('port: %s\tstate: %s ' % (port, nmscan[host][proto][port]['state'] ))

elif inp == 5:
	originalfile = input("Please enter the original csv filename: \n")
	with open(originalfile, "r") as fp:
		table = from_csv(fp)
	print(table)

else:
	print("Opps...Invalid input!")
