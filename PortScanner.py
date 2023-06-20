import nmap
import socket
from optparse import OptionParser

parser = OptionParser("""
                 

 /$$$$$$$                        /$$            /$$$$$$                                                             
| $$__  $$                      | $$           /$$__  $$                                                            
| $$  \ $$  /$$$$$$   /$$$$$$  /$$$$$$        | $$  \__/  /$$$$$$$  /$$$$$$  /$$$$$$$  /$$$$$$$   /$$$$$$   /$$$$$$ 
| $$$$$$$/ /$$__  $$ /$$__  $$|_  $$_/        |  $$$$$$  /$$_____/ |____  $$| $$__  $$| $$__  $$ /$$__  $$ /$$__  $$
| $$____/ | $$  \ $$| $$  \__/  | $$           \____  $$| $$        /$$$$$$$| $$  \ $$| $$  \ $$| $$$$$$$$| $$  \__/
| $$      | $$  | $$| $$        | $$ /$$       /$$  \ $$| $$       /$$__  $$| $$  | $$| $$  | $$| $$_____/| $$      
| $$      |  $$$$$$/| $$        |  $$$$/      |  $$$$$$/|  $$$$$$$|  $$$$$$$| $$  | $$| $$  | $$|  $$$$$$$| $$      
|__/       \______/ |__/         \___/         \______/  \_______/ \_______/|__/  |__/|__/  |__/ \_______/|__/      
                                                                                                                    
                                                                                                                    
                                                                                                                    
                                                                                                                                          
                            			@0x3mr                        
                                                    
script.py [option]
--------------------
-d 	     :: Set Your Specific Target.
-p       :: Set The Ports number.

EX:
    PortScanner.py -H domain.com -p 80
    PortScanner.py -H domain.com -p 80,443,21,22

To Scan the target with all ports:
    dnsrecord.py -H domain.com -p ALL  
""")

parser.add_option("-H", dest = "host", type = "string", help = "Your Domain")
parser.add_option("-p", dest = "port", type = "string", help = "port number")

(options, args) = parser.parse_args()

if options.host == None or options.port == None:
    print(parser.usage)
    exit(0)

else:
	ip_target = socket.gethostbyname(options.host)

	print("The Host:", options.host)
	print("IP: ", ip_target)
	print("------------------------------")
	Scan_v = nmap.PortScanner()

	if options.port == "ALL":
		print("\nScanning ", ip_target, "for ALL 65535 port" ,"\n")

		for port in range(0, 65534):
			portscan = Scan_v.scan(ip_target, str(port))

			print('port : %s\tstate : %s' % (port, portscan['scan'][ip_target]['tcp'][port]['state']))

		print("\n Host", ip_target, "is", portscan['scan'][ip_target]['status']['state'])

	else:
		print("\nScanning ", ip_target, "for Ports" , options.port, "\n")

		ports = str(options.port)
		ports = ports.split(",")
		ports = [eval(i) for i in ports]

		for port in ports:
			portscan = Scan_v.scan(ip_target, str(port))

			print('port : %s\tstate : %s' % (port, portscan['scan'][ip_target]['tcp'][port]['state']))

		print("\n Host", ip_target, "is", portscan['scan'][ip_target]['status']['state'])