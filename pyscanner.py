class bcolors:                   # This class bcolors module is used to get colours in cse machine termianl while displaying output
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
import argparse #used for creating user-friendly command-line interfaces and also automatically generates help and usage messages and issues errors
import socket # used for creating a socket
import sys # sys library is used for importing system constants,functions and methods
from multiprocessing.dummy import Pool as ThreadPool # used for creating threads in the program for suppoting parallel execution
import itertools # itertools is used for iterating through the values
import errno # used for defining error codes for identifying errors
version = "1.0.0"
parser = argparse.ArgumentParser(prog='pyScanner', description='Scan ports.', 
                                 epilog='''Project2''') # argparse deals with arguments that needs to be passed in a certain manner
parser.add_argument('address', metavar='ADDRESS', type=str, nargs=1, help='destination host/network to be scanned') # used for scanning destination host
parser.add_argument('--verbose', '-v', action='count', default=0, help='print closed ports as well') # used for checking closed ports
parser.add_argument('--version', action='version', version='%(prog)s {0}'.format(version)) # used for defining program name and version information
parser.add_argument('--ports', '-p', dest='ports', nargs=2, metavar=('INIT_PORT','END_PORT'), type=int, choices=range(1, 64999), required=True, help='ports to be analysed') # argument used for analysing ports in the given range
parser.add_argument('--tcp', '-t', dest='TCP', default=False, action='store_true', help='analyse TCP ports') # used for analysing TCP port values
parser.add_argument('--udp', '-u', dest='UDP', default=False, action='store_true', help='analyse UDP ports') # used for analysing UDP port values

 
args = parser.parse_args() # used for passing the above arguments and make it understandable to the system

timeout = 2
socket.setdefaulttimeout(timeout) # to make sure code is working correctly. It sets the default timeout for socket modules

def scan_ports(args, port):  # function for scanning network ports
    
    try: # using try function
        if not args.TCP and not args.UDP: # checks whether it is TCP or UDP. Default it takes TCP
            args.TCP = True
            args.UDP = True
        if args.TCP: # checking TCP ports
            type = "tcp" # connection type is TCP 
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # This statement is used for creating the TCP socket. SOCK_STREAM is used for TCP
            result = sock.connect_ex((args.address[0], port)) # connecting to the port address of the system
            service = socket.getservbyport(port, type) # used for knowing which service is running on the system through port number and type
            if(service==""):
               service= 'svc name unavailable'
            if result == 0: # checking port connection
                status = "Open  " # status of port is open
            else:
                status = "Closed" # status of port is closed
            return (port, service, status, type) # we get the port nmber, port service like ssh, status like open or closed and type like TCP as output
            sock.close() # closing the socket
        if args.UDP:#UDP # checking UDP ports
            type = "udp" # connection type is UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # This statement is used for creating the UDP socket. SOCK_DGRAM is used for UDP
            result = sock.connect_ex((args.address[0], port)) # connecting to the port address of the system
            service = socket.getservbyport(port, type) # used for knowing which service is running on the system through port number and type
            if(service==""):
               service= 'svc name unavailable'
            if result == 0: # checking port connection
                status = "Open  " # status of port is open
            else:
                status = "Closed" # status of port is closed
            return (port, service, status, type) # we get the port nmber, port service like ssh, status like open or closed and type like UDP as output
            sock.close() # closing the socket

    except KeyboardInterrupt: # This is for keyboard interruption by user if we press control c
        print("Program interrupted by user.") 
        sys.exit() # program is terminated

    except socket.gaierror: # gets this exception when the host name is invalid
        print('Hostname could not be resolved. Exiting')
        sys.exit() # program is terminated

    except socket.error as error: # checks for socket errors like no network connection 
        pass
       


ports = list(range(args.ports[0],args.ports[1])) # range of ports from low range to high range

print('\n{3}scanning host= {0}, ports: {1} -> {2} {4}'.format(args.address[0],args.ports[0],args.ports[1], bcolors.HEADER, bcolors.ENDC)) # scanning current given host and port ranges

pool = ThreadPool(4) # used to create pool of threads that can be used to execute tasks
result = pool.starmap(scan_ports, zip(itertools.repeat(args),list(range(args.ports[0],args.ports[1])))) # accepts sequence of argument tuples and zips the argument tuple and unpacks the arguments automatically from each tuple and passes them to the given function scan_ports 
pool.close() # close() is called when program is finished
pool.join() # join() is called to wait for the processes working to terminate
print()
result = [x for x in result if x is not None] # checking final result
for port, service, status, type in result: # result has all 4 things like port numbers, service, status and type of port
    if args.verbose > 0 or status == "Open  ": # checking if status is open
        color =  bcolors.OKGREEN if status == "Open  " else '' # if status is open then Green color is printed 
        endcolor = bcolors.ENDC if status == "Open  " else '' 
        print( "{4}Port {0}:      Status:{2}      Protocol:{3}    Service:[{1}]{5}".format(port, service, status.upper(), type.upper(), color, endcolor)) # Displaying final output like port number range, protocol TCP or UDP, status open or closed and service of port number
