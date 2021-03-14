#!/usr/bin/env python3  

import subprocess # used to run new applications or programs through Python code by creating new processes
import sys # sys library is used for importing system constants,functions and methods

if len(sys.argv)!=5 or sys.argv[2] not in ['tcp','udp']: # checking if number of arguments are 4 or not and if protocol is in tcp or udp
	print("usage: ./PortScanner.py <hostname> <protocol> <portlow> <porthigh>") # printing usage statement
	sys.exit() # exit() function terminates the program


try:
	sys.argv[3]=int(sys.argv[3]) 
	sys.argv[4]=int(sys.argv[4])
	if sys.argv[3]<0 or sys.argv[4]>65535 or sys.argv[3]>sys.argv[4]: # checking the argument conditions like port numbers should be between 0 to 65535
		print("usage: ./PortScanner.py <hostname> <protocol> <portlow> <porthigh>") # if condition is true then we will print the usage statement
except:
	print("usage: ./PortScanner.py <hostname> <protocol> <portlow> <porthigh>") # printing usage statement if there are any exceptions like host name is invalid etc
	sys.exit() # exit() function terminates the program

p1=subprocess.run(["python3","pyscanner.py",sys.argv[1],"--verbose","--"+sys.argv[2],"--ports",str(sys.argv[3]),str(sys.argv[4])]) # This statement calls the pyscanner.py file and brings all arguments and executes the pyscanner file
