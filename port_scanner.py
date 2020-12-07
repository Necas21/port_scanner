import argparse
import sys
import socket
from socket import *
import threading
from threading import Thread


screenLock = threading.Semaphore(value=1)

def conn_scan(host, port):

	setdefaulttimeout(1)

	try:
		s = socket(AF_INET, SOCK_STREAM)
		s.connect((host, port))
		screenLock.acquire()
		print("[+] Port tcp/{} is open".format(port))

	except:
		screenLock.acquire()
		print("[-] Port tcp/{} is closed".format(port))

	finally:
		screenLock.release()
		s.close()


def port_scan(host, ports):

	try:
		#Try to resolve hostname to IP address
		target_ip = gethostbyname(host)

	except:

		print("[-] Unable to resolve {}. Please check your DNS/Network settings.".format(host))
		return

	try:
		target_name = gethostbyaddr(target_ip)
		print("[*] Scan results for: {} ({})".format(target_name[0], target_ip))

	except:
		print("[*] Scan results for: {}".format(target_ip))

	for port in ports:

		t = Thread(target=conn_scan, args=(host, int(port)))
		t.start()


def main():

	parser = argparse.ArgumentParser()
	parser.add_argument("-H", dest="hostname", help="Specify the hostname or IP address of your target.")
	parser.add_argument("-p", dest="ports", help="Specify the port(s) seperated by a comma (,) to scan on your target.")


	if len(sys.argv) != 5:
		parser.print_help(sys.stderr)
		sys.exit(1)

	args = parser.parse_args()

	hostname = args.hostname
	ports = args.ports.split(",")

	port_scan(hostname, ports)



if __name__ == '__main__':
	main()

