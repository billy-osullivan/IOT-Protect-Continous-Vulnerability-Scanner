#!C:\Python27\python.exe
# Script:   		scan.py
# Author:   		William O Sullivam
# Purpose:  		This script checks devices on your network to see if they are vulnerable to Mirai and QBOT
# Created:  		20 March 2017
# Edited: 			12 June 2017
# Requirements:		shodan library - pip install shodan
# Designed for windows 10
# The following assumptions were made: The home network uses a \24 subnet


# Import libraries
import socket
import subprocess
import shodan
import urllib2
import telnetlib
import os
import re
import sys
import time
import Queue
import getpass
import tkMessageBox
import ttk
import base64
import webbrowser
from Tkinter import *
from socket import *
from datetime import datetime
from threading import Thread
from ScrolledText import *


#### Mirai default passwords & Qbot default passwords
user_root = ['changeme','login','guest','toor','','root','00000000','1111','1234','12345','123456','54321','666666','7ujMko0admin','7ujMko0vizxv','888888','admin','anko','default','dreambox','hi3518','ikwb','juantech','jvbzd','klv123','klv1234','pass','password','realtek','system','user','vizxv','xc3511','xmhdipc','zlxx.','Zte521','service ','service']
user_666666 = '666666'
user_888888 = '888888'
user_mother = 'fucker'
user_supervisor = 'supervisor'
user_support = 'support'
user_tech = 'tech'
user_ubnt = 'ubnt'
user_user = ["user","root", "toor", "admin", "user", "guest", "login", "changeme", "1234", "12345", "123456", "default", "pass", "password"]
user_guest =  ["root", "toor", "admin", "user", "guest", "login", "changeme", "1234", "12345", "123456", "default", "pass", "password"]
user_administrator = '1234'
user_Administrator = 'admin'
user_admin1 = 'password'
user_admin = ['default','user', 'guest', 'login', 'changeme','root', 'toor','','1111','1111111','1234','12345','123456','54321','7ujMko0','admin','1234','meinsm','pass','password','smcadmin']
user_login = ["root", "toor", "admin", "user", "guest", "login", "changeme", "1234", "12345", "123456", "default", "pass", "password"]


#### Mirai & QBOT default login names
mirai_name = ['login','root','666666','888888','mother','supervisor','support','tech','ubnt','user','guest','administrator','Administrator','admin1','admin','pi']

# Telnet function, gets value for user name, password and host ip passed to it. Attempts to log into device using mirai credential list
def telnet(usr,pwd,host):
	tn = telnetlib.Telnet(host,23,2)
	tn.read_until("login: ",2)
	tn.write(usr + '\n')
	if pwd:
		tn.read_until("Password: ",2)
		tn.write(pwd + "\n")
	tn.write("ls\n")
	tn.write("exit\n")
	tn.read_all()
	x = 'Host: ' + host + ' compromised. The user name is: ' + usr + ' The password is: ' + pwd
	tn.close()
	return(x)

# Telnet bruteforce function - Passes the mirai credentials to telnet function along with the ip address to attempt login.
def telnet_brute(host):
	y = 0
	port = 23
	for name in mirai_name:
		user = name
		if user == 'root':
			for password in user_root:
				try:
					y = telnet(user,password,host)					
				except:
					pass
		elif user == '666666':
			password = '666666'
			try:
				y = telnet(user,password,host)
			except:
				pass
		elif user == '888888':
			password = '888888'
			try:				
				y = telnet(user,password,host)
			except:
				pass		
		elif user == 'mother':
			password = 'fucker'
			try:				
				y = telnet(user,password,host)
			except:
				pass
		elif user == 'supervisor':
			password = 'supervisor'
			try:				
				y = telnet(user,password,host)
			except:
				pass
		elif user == 'support':
			password = 'support'
			try:				
				y = telnet(user,password,host)
			except:
				pass
		elif user == 'tech':
			password = 'tech'
			try:				
				y = telnet(user,password,host)
			except:
				pass
		elif user == 'ubnt':
			password = 'ubnt'
			try:				
				y = telnet(user,password,host)
			except:
				pass
		elif user == 'guest':
			for password in user_guest:
				try:					
					y = telnet(user,password,host)
				except:
					pass
		elif user == 'administrator':
			password = '1234'
			try:				
				y = telnet(user,password,host)
			except:
				pass
		elif user == 'Administrator':
			password = 'admin'
			try:				
				y = telnet(user,password,host)
			except:
				pass
		elif user == 'admin1':
			password = 'password'
			try:				
				y = telnet(user,password,host)
			except:
				pass
		elif user == 'admin':
			for password in user_admin:
				try:					
					y = telnet(user,password,host)
				except:
					pass
		elif user == 'login':
			for password in user_login:
				try:					
					y = telnet(user,password,host)
				except:
					pass
		elif user == 'pi':
			password = 'raspberry'
			try:
				y = telnet(user,password,host)
			except:
				pass
	return y


# Function to get ip address of main interface
def get_ip_address():
    s = socket(AF_INET, SOCK_DGRAM) 				# Set up a socket
    s.connect(("8.8.8.8", 80)) 						# Try to connect to google
    return s.getsockname()[0]  						# Return the ip address of the interface used in attempt to connect to google

# Function to get listening devices IP address range. Assumes /24 for home network. 
# Get first three octets of internal ip address and scan entire range for replys 
# Has the host ip passed into it to get first 3 octects
def iprange_ping(hostip):
	full_ips = []
	net_range = hostip[:hostip.rfind(".")] 			# Get first 3 octets
	net_range = net_range + '.'
	with open(os.devnull, "wb") as limbo:  			# os.devnull writes results to null device, i.e. it records only the reult, the rest of the data is discarded.
		for n in xrange(1, 255):					# Range for last octet (does not scan first or last address)
			full_ip = net_range + "{0}".format(n)
			result = subprocess.Popen(["ping", "-n", "1", "-w", "400", full_ip], stdout=limbo, stderr=limbo).wait() # Ping range, each ip gets only 1 ping (-n), and 400 mSec wait for no reply (-w) 
			if result:
				pass
			else:
				full_ips.append(full_ip)   			# List containing ips, these will be the keys for the dictionary of addresses and ports.
	return full_ips

# Port scan function. Scans each listening IP address for active ports. Used by 4 threads, each scans 1/4 of the ip range from 1 to 6000
# It has the host ip, port range (start and end port) and queue number passed to it	
def scan_host(host, port_start, port_end, queue):
	open_ports = [] 							# Set up list
	r_code = 1 									# Set default r_code value
	for port in range(port_start,port_end):
		try:
			a = socket(AF_INET,SOCK_STREAM)
			a.settimeout(.07)                   # Timeout for socket to connect, i think default is over a second
			code = a.connect_ex((host, port))
			if code == 0:						# If port is open
				r_code = code
				open_ports.append(port) 		# Add port number to list
				a.close() 						# Close port
		except Exception, e:
			pass
	queue.put(open_ports)  						# Method of returning value from threads.

# Function sets up threading to speed up port scan. Uses 4 threads each thread stores its result in queue()
# After the threads are have completed they are re-joined and the values are retrieved from queue()
# has the list of ip addresses ip_list passed to it
def port_scan(ip_list):
	openports = [] 														# Set up list
	init_scan_data = {} 												# Set up dictionary
	q1 = Queue.Queue() 													# Set up queue to store results from threads
	q2 = Queue.Queue()
	q3 = Queue.Queue()
	q4 = Queue.Queue()
	for item in ip_list: 												# For each value in ip_list, scan for ports
		host = item 
		thread1 = Thread(target=scan_host, args=(host, 1, 1500, q1))   	# Create threads
		thread2 = Thread(target=scan_host, args=(host, 1501, 3000, q2))
		thread3 = Thread(target=scan_host, args=(host, 3001, 4500, q3))
		thread4 = Thread(target=scan_host, args=(host, 4501, 6000, q4))
		thread1.start() 												# Start threads
		thread2.start()
		thread3.start()
		thread4.start()
		thread1.join()													# Hold threads 1 - 4 until they all finish and then re-intergrate the thread
		thread2.join()
		thread3.join()
		thread4.join()
		openports = q1.get() + q2.get() + q3.get() +q4.get() 			# Get results from port scan
		init_scan_data[host] = openports 								# Fill dictionary with results
	return init_scan_data

# Function to get external facing IP address using shodan api
def get_external_ip(shodan_api):
	try:
		externalip = urllib2.urlopen('https://api.shodan.io/tools/myip?key={' + shodan_api + '}') # prepair link to send
		extip = externalip.read()
		result = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', extip ) # get ip address
		result = str(result[0])
		return result
	except Exception, e:
		x = 0
		return x

# Function to test a single host for mirai vulnerabilities
def internal_test_function(app, progress, label2text, label2, display_field):
	compromised = 0
	op = open('Report.txt','a') 						# Open Report.txt for adding results
	x = "*** Internal Test *** \nStarted At: %s\n" % (time.strftime("%H:%M:%S")) # Time test started
	op.write(x)
	display_field.configure(state='normal')
	display_field.insert(INSERT, x)
	display_field.configure(state='disabled')
	x = '''
*****************
* Internal Scan *
*****************

Now scanning your internal network to check for 
vulnerabilities.
This scan checks your local network for open ports
and checks any device open for telnet connections
for Mirai vulnerability.

'''
	display_field.configure(state='normal')
	display_field.insert(INSERT, x)
	display_field.configure(state='disabled')
	tkMessageBox.showinfo("IOT Vulnerability Scanner", '''Before the test is run please takes the following
measures, then click 'Proceed'

1. 	Disconnect the cable connecting your modem to
	the internet.
2. 	After the cable connecting your modem to the 
	internet has been removed, reboot all your 
	devices connected to the modem.
3. 	Press 'Enter' on your keyboard to proceed

The reason for this is that some IOT malware such
as Mirai and Bashlite are removed by rebooting 
your devices.
These malware samples are capable of re-infecting 
devices in about 2 minutes, and they secure your 
devices so other malware samples cant infect them 
also.
''') 												# pause here util user ready
	x = '\n\nProceeding with scan ...\n'
	display_field.configure(state='normal')
	display_field.insert(INSERT, x)
	display_field.configure(state='disabled')
	op.close()
	label2 = Label(app, textvariable=label2text, fg="blue").grid(row=480,column=2, sticky=N)
	progress.start(1)
	thread5 = Thread(target=internal_scan, args=(app, progress, label2text, label2, display_field))
	thread5.start()
	
			
def internal_scan(app, progress, label2text, label2, display_field):
	op = open('Report.txt','a')
	start_time = datetime.now()
	address = get_ip_address() 							# Get private ip address 
	ip_list = iprange_ping(address) 					# Get list of available private ip addresses
	scan_result = port_scan(ip_list) 					# Get scan results of internal ip addresses and open ports
	x = '''
*******************
* IP & Ports Scan *
*******************
'''
	op.write(x)
	display_field.configure(state='normal')
	display_field.insert(INSERT, x)
	display_field.configure(state='disabled')
	for keys,values in scan_result.items():  			# Loop through port scan results to display and save values to Report.txt
		x = "\nIP Address: " + str(keys) + "\nOpen Ports: "
		y = str(values) + "\n"
		op.write(x)
		op.write(y)
		display_field.configure(state='normal')
		display_field.insert(INSERT, x)
		display_field.insert(INSERT, y)
		display_field.configure(state='disabled')
	x = '''
****************************
* Mirai & QBOT Telnet Scan *
****************************
'''
	display_field.configure(state='normal')
	display_field.insert(INSERT, x)
	display_field.configure(state='disabled')
	for keys,values in scan_result.items(): 						# This gives out each key with a list of its values
		for item in values:
			if item == 23:
				x = '\nScanning ' + keys + ' for Mirai and QBOT vulnerability\n'
				display_field.configure(state='normal')
				display_field.insert(INSERT, x)
				display_field.configure(state='disabled')
				compromised = telnet_brute(keys)
				if compromised != 0:
					conf = open('conf.cfg','a')
					conf.write(compromised)
					conf.close()
					op.write(compromised)
					display_field.configure(state='normal')
					display_field.insert(INSERT, compromised)
					display_field.configure(state='disabled')
				else:
					x = '\nDevice not vulnerable to Mirai or QBOT attack'
					op.write(x)
					display_field.configure(state='normal')
					display_field.insert(INSERT, x)
					display_field.configure(state='disabled')
		else:
			pass
	stop_time = datetime.now()
	total_time_duration = stop_time - start_time
	x = "\n\nScanning Finnished At %s..." %(time.strftime("%H:%M:%S"))
	y = "\nScanning Duration: %s..." %(total_time_duration)
	z = "\n\nTesting finished, your modem can be plugged back into the internet."
	op.write(x)
	op.write(y)
	display_field.configure(state='normal')
	display_field.insert(INSERT, x)
	display_field.insert(INSERT, y)
	display_field.insert(INSERT, z)
	display_field.configure(state='disabled')
	op.close()
	progress.stop()
	label2 = Label(app, textvariable=label2text, state= DISABLED, fg="blue").grid(row=480,column=2, sticky=N)
	
	
		
# Function to display the total number of avaible IP address on network	
def external_scan_function(app, progress, label2text, label2, display_field):
	op = open('Report.txt','a') 						# Open Report.txt for adding results
	x = '''
*****************
* External Scan *
*****************

Scanning your external network to check for 
vulnerabilities.
This scan checks Shodan's online database
for any information already available about your 
network.
It also scans your external interface to check
if it is vulnerable to known Mirai intrusion 
methods.
'''
	op.write(x)
	display_field.configure(state='normal')
	display_field.insert(INSERT, x)
	display_field.configure(state='disabled')
	tkMessageBox.showinfo("IOT Vulnerability Scanner",'''Before scanning can run, please re-connect your
modem to your internet connection''')					# pause here until user ready
	x = '\n\nProceeding with scan ...\n'
	display_field.configure(state='normal')
	display_field.insert(INSERT, x)
	display_field.configure(state='disabled')
	op.close()
	thread6 = Thread(target=external_scan, args=(app, progress, label2text, label2, display_field))
	label2 = Label(app, textvariable=label2text, fg="blue").grid(row=480,column=2, sticky=N)
	progress.start(1)
	thread6.start()
	

def external_scan(app, progress, label2text, label2, display_field):
	op = open('Report.txt','a')
	compromised = 0
	x = "\nStarted At: %s\n" % (time.strftime("%H:%M:%S")) # Time test started
	op.write(x)
	display_field.configure(state='normal')
	display_field.insert(INSERT, x)
	display_field.configure(state='disabled')
	start_time = datetime.now()
	x = '''
***************	
* Shodan Scan *
***************
'''
	op.write(x)
	display_field.configure(state='normal')
	display_field.insert(INSERT, x)
	display_field.configure(state='disabled')
	ak = open('conf.cfg','r')
	api_key = ak.read()
	ak.close()
	try:
		api_key = api_key.split()
		shodan_api_key = api_key[-1] 
		api_key = shodan.Shodan(shodan_api_key)
		ip = get_external_ip(shodan_api_key)
		x = '\nYour external IP is: ' + ip + '\nChecking Shodan for your external address...'
		op.write(x)
		display_field.configure(state='normal')
		display_field.insert(INSERT, x)
		display_field.configure(state='disabled')
		try:
			host = api.host(ip)
			x = "\nIP: %s \nService Provider: %s \nOperating System: %s" % (host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a'))  # Print general info
			op.write(x)
			display_field.configure(state='normal')
			display_field.insert(INSERT, x)
			display_field.configure(state='disabled')
			for item in host['data']:
				x = "\nPort: %s Banner: %s" % (item['port'], item['data']) # Print all banners
				op.write(x)
				display_field.configure(state='normal')
				display_field.insert(INSERT, x)
				display_field.configure(state='disabled')			
		except Exception, e:
			x = '\nNo information available for your IP address on Shodan\n'
			op.write(x)
			display_field.configure(state='normal')
			display_field.insert(INSERT, x)
			display_field.configure(state='disabled')	
		x = ''' 
***********************************
* Scanning External IP For Known  *
*    Mirai & QBOT Vulnerabilities *
***********************************
'''
		compromised = 0
		display_field.configure(state='normal')
		display_field.insert(INSERT, x)
		display_field.configure(state='disabled')
		x = '\nScanning your routers external IP' + ip + '\nfor Mirai & QBOT vulnerability\n'
		display_field.configure(state='normal')
		display_field.insert(INSERT, x)
		display_field.configure(state='disabled')
		compromised = telnet_brute(ip)
		if compromised != 0:
			op.write(compromised)
			display_field.configure(state='normal')
			display_field.insert(INSERT, compromised)
			display_field.configure(state='disabled')
		else:
			x = '\nDevice not vulnerable to Mirai or QBOT attack'
			op.write(x)
			display_field.configure(state='normal')
			display_field.insert(INSERT, x)
			display_field.configure(state='disabled')
		stop_time = datetime.now()
		total_time_duration = stop_time - start_time
		x = "\n\nScanning Finnished At %s..." %(time.strftime("%H:%M:%S"))
		y = "\nScanning Duration: %s..." %(total_time_duration)
		op.write(x)
		op.write(y)
		display_field.configure(state='normal')
		display_field.insert(INSERT, x)
		display_field.insert(INSERT, y)
		display_field.configure(state='disabled')
		op.close()
		progress.stop()
		label2 = Label(app, textvariable=label2text, state= DISABLED, fg="blue").grid(row=480,column=2, sticky=N)
	except:
		x = '''
  Warning - No API key present!!!
Get Shodan api key and insert for
           scan to work'''
		op.write(x)
		display_field.configure(state='normal')
		display_field.insert(INSERT, x)
		display_field.configure(state='disabled')
		op.close()
		progress.stop()
		label2 = Label(app, textvariable=label2text, state= DISABLED, fg="blue").grid(row=480,column=2, sticky=N)
	
# Function to explain about the software
def about_function():
	x = '''About IOT Vulnerability Scanner
	
IOT Vulnerability Scanner V1.0, Created by Billy O Sullivan
	
This application is designed to test your network for vulnerabilities, specifically involving the IOT malware Bashlite and Mirai. 
This includes connected devices such as web cams, seucrity systems, routers, raspberry pi's, dreambox's, etc (basically whatever you have that uses the internet).
It was created for a college project in response to the 2016 IOT botnet Mirai which brought down large parts of the internet.
The hope is that this software when used will help protect your devices from both old and emerging threats.
	
Notes about operation:
This program carries out the following tasks inorder to test your network - 
1. It checks for your IP address
2. It scans your network range for active hosts using a configured PING (assuming that you are on a /24 subnet)
3. For each device it finds it checks to see what ports are open (from port 1 to port 6000)
4. For each port found to be open, it tries to gain access using a list of default passwords
5. It will then generate a report both on your screen and in a text file titled report.txt
	
For best results:
The program will prompt for certain actions during operation, such as disconnect a cable from your router and reseting your devices.
This is due to how must infections on IOT devices work - once your IOT device is reset, any malware on it is probably removed, but re-infection
can occur within two minutes. And an infected device will take measures to lock down your device which will skew results.
To combat this the program will recommend reseting your devices and removing the cable which connects your router to the internet during port scanning.'''
	display_field.configure(state='normal')
	display_field.insert(INSERT, x)
	display_field.configure(state='disabled')


# entry widget to take in users shodan code
def shodan_user():
	conf = open('conf.cfg','w')
	x = 'Shodan API code: ' + shodan_code_entry.get() + '\n'
	conf.write(x)
	conf.close()

# link to Shodan to get API code
def OpenUrl():
    webbrowser.open_new('https://developer.shodan.io/')


def menu(opt):
	display_field.configure(state='normal')
	display_field.delete(1.0,END)
	display_field.configure(state='disabled')
	if opt == 1:
		internal_test_function(app, progress, label2text, label2, display_field)
	elif opt == 2:
		external_scan_function(app, progress, label2text, label2, display_field)
	elif opt == 3:
		about_function()
	elif opt == 5:
		shodan_user()
	
#### Main Code Calls ####

# set up text file for storing scan report
try:
	conf = open('conf.cfg','r')
except:
	conf = open('conf.cfg','w')
op = open('Report.txt','w')
now = time.strftime("%c")
user = getpass.getuser()
x = '***   IOT Scanner Report Document   ***\n\nScanner ran on: ' + now + '\nThe logged in user: ' + user + '\n'
op.write(x)
op.close()
conf.close()


# set up app frame and name	
app = Tk()
app.title("IOT Vulnerability Scanner")
app.geometry('1000x750')

# Set lables
label1text = StringVar()
label1text.set("Options")
label1 = Label(app, textvariable=label1text, fg="blue").grid(row=180,column=1, sticky=N)

# set the buttons
q5 = Queue.Queue()
button1 = Button(app, text="Internal Test", width=20, bg='green', command=lambda: menu(1))
button1.grid(row=200,column=1, columnspan=1)
button2 = Button(app, text="External Test", width=20, bg='green', command=lambda: menu(2))
button2.grid(row=200,column=2, sticky=N, columnspan=1)
button3 = Button(app, text="About", width=20, bg='green', command=lambda: menu(3))
button3.grid(row=200,column=3, sticky=N, columnspan=1)
button4 = Button(app, text="Get Shodan API",bg='blue', fg='yellow', command=OpenUrl)
button4.grid(row=750,column=2, sticky=N)
button5 = Button(app, text="Use my API code", width=20, bg='green', command=lambda: menu(5))
button5.grid(row=650,column=2, sticky=N)


# set up the text widget
display_field = ScrolledText(app, width=60, height=45, wrap=WORD)
display_field.grid(row=0, column=4, rowspan = 1000)
display_field.configure(state='normal')
x = '''*** IOT Scanner Version 1.0 ***

Select one of the buttons to the left to test your 
network for vulnerabilities common to IOT devices.

For information about the software and how best to use it
click the 'About' button




Security Tips

1. Change default passwords for your connected devices
2. Use a combination of letters, numbers and symbols where possible
3. Change your passwords regularly
4. Use different passwords for each device
5. Update your devices firmware when possible to receive latest
   manufacture security enhancements'''
display_field.insert(INSERT, x)
display_field.configure(state='disabled')

# loading bar
progress = ttk.Progressbar(app, orient='horizontal',length=300, mode='indeterminate')
progress.grid(row=500,column=1, columnspan=3)
label2text = StringVar()
label2text.set("Scan In Progress")
label2 = Label(app, textvariable=label2text, state= DISABLED, fg="blue").grid(row=480,column=1, columnspan=3)

# shodan api code entry field
label3text = StringVar()
label3text.set("Shodan API Code - Only required for external scan")
label3 = Label(app, textvariable=label3text, fg="blue").grid(row=600,column=1, columnspan=3)
shodan_code_entry = Entry(app, exportselection=0, justify=CENTER, width = 45 )
shodan_code_entry.grid(row=602,column=1, columnspan=3)


# set up loop so program runs
app.mainloop()
