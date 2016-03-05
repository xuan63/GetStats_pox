#!/usr/bin/python
#-*- coding: UTF-8 -*-

from pox.core import core
from pox.lib.util import dpid_to_str,str_to_dpid
from pox.lib.revent import *
from pox.lib.recoco import *
import time
import socket
import pprint
import copy
from colorama import Fore, Back ,Style

# from GetTopo import GetTopo
# import util

log = core.getLogger()

class GetStats(Task):
	def __init__(self):
		Task.__init__(self)  # call our superconstructor

		self.sockets = self.get_sockets()
		core.addListener(pox.core.GoingUpEvent, self.start_event_loop)
		Timer(5,self.SendPortRequest)
		# Timer(15,SendPortRequest)


	def start_event_loop(self, event):
		"""
		Takes a second parameter: the GoingUpEvent object (which we ignore)
		"""
		# This causes us to be added to the scheduler's recurring Task queue
		Task.start(self)

	def get_sockets(self):
		server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		server.setblocking(0)
		server_address= ('127.0.0.1',10001)
		server.bind(server_address)
		server.listen(10)
		return [server]

	# def handle_read_events(self):
	# 	pass

	def run(self):
		global old_t,old_PortBytes,old_PortPackets,count
		while core.running:
			rlist,wlist,elist = yield Select(self.sockets, [], [], 3)
			events = []
			for read_sock in rlist:
				if read_sock in self.sockets:
					events.append(read_sock)
					connection, client_address = read_sock.accept()
					
					print(Fore.CYAN + '*'*25 + 'Statistics' + '*'*25),;print(Fore.RESET)
					print "connection from ", client_address
					print connection.recv(1024)  #读取从服务器返回的数据
					print(Fore.CYAN + 'Hosts:'),;print(Fore.RESET)
					pprint.pprint(Hosts)
					print(Fore.CYAN + 'Switches:'),;print(Fore.RESET)
					pprint.pprint(Switch_set)
					print(Fore.CYAN + 'Links:'),;print(Fore.RESET)
					pprint.pprint(Link_set)
					print(Fore.CYAN + 'ArpTable:'),;print(Fore.RESET)
					pprint.pprint(ArpTable)

					# print(Fore.CYAN + 'macToPort:'),;print(Fore.RESET)
					# pprint.pprint(macToPort)
					print(Fore.CYAN + 'PortBytes:'),;print(Fore.RESET)
					pprint.pprint(PortBytes)
					print(Fore.CYAN + 'PortPackets:'),;print(Fore.RESET)
					pprint.pprint(PortPackets)
					
					connection.setblocking(0)
					if Pingall():
						self.SendPortRequest()
						old_t=copy.deepcopy(t)
						old_PortBytes=copy.deepcopy(PortBytes)
						old_PortPackets=copy.deepcopy(PortPackets)
						count=0
						Timer(1,self.Calculate)
			# if events:
			# 		self.handle_read_events() # ...

	def SendPortRequest(self):
		for con in core.openflow.connections:
			con.send(of.ofp_stats_request(body=of.ofp_port_stats_request()))

	#计算时间t内端口发送和接收的字节数和包数
	def Calculate(self):
		# print PortBytes
		# count=0
		# print len(t)
		# self.SendPortRequest()
		if count<len(t):
			print count
			Timer(1,self.Calculate)
			return

		global PortBytes,PortPackets
		global RemainBandWidth,Loss,LinkState

		delta_t={}
		delta_PortBytes={}
		delta_PortPackets={}
		
		for dpid in t:
			delta_t[dpid]=t[dpid]-old_t[dpid]
			delta_PortBytes[dpid]={}
			delta_PortPackets[dpid]={}
			for port in PortBytes[dpid]:
				delta_PortBytes[dpid][port]=(PortBytes[dpid][port][0]-old_PortBytes[dpid][port][0],PortBytes[dpid][port][1]-old_PortBytes[dpid][port][1])
				delta_PortPackets[dpid][port]=(PortPackets[dpid][port][0]-old_PortPackets[dpid][port][0],PortPackets[dpid][port][1]-old_PortPackets[dpid][port][1])
		# print delta_PortPackets
		for link in Link_set:
			dpid1 = link[0]
			dpid2 = link[1]
			RemainBandWidth[link] = {}
			Loss[link] = {}
			for port in Switch_set[dpid1]:
				if dpid2 == Switch_set[dpid1][port][0]:
					port1 = port
					port2 = Switch_set[dpid1][port][1]
					break
			# print delta_t[dpid1],delta_t[dpid2]
			RemainBandWidth[link][dpid1] = BandWidth-(delta_PortBytes[dpid1][port1][0]+delta_PortBytes[dpid2][port2][1])*2/(delta_t[dpid1]+delta_t[dpid2])/1024/1024
			RemainBandWidth[link][dpid2] = BandWidth-(delta_PortBytes[dpid1][port1][1]+delta_PortBytes[dpid2][port2][0])*2/(delta_t[dpid1]+delta_t[dpid2])/1024/1024
			
			if delta_PortPackets[dpid2][port2][0]!=0:
				Loss[link][dpid2] = 1-delta_PortPackets[dpid1][port1][1]*1.0/delta_PortPackets[dpid2][port2][0]
			else:
				Loss[link][dpid2] = 0
			if delta_PortPackets[dpid1][port1][0]!=0:
				Loss[link][dpid1] = 1-delta_PortPackets[dpid2][port2][1]*1.0/delta_PortPackets[dpid1][port1][0]
			else:
				Loss[link][dpid1] = 0

			LinkState[link] = (RemainBandWidth[link],Loss[link],Delay[link])
		print(Fore.CYAN + 'RemainBandWidth:'),;print(Fore.RESET)
		pprint.pprint(RemainBandWidth)
		print(Fore.CYAN + 'Loss:'),;print(Fore.RESET)
		pprint.pprint(Loss)
		print(Fore.CYAN + 'Delay:'),;print(Fore.RESET)
		pprint.pprint(Delay)
		print(Fore.CYAN + 'LinkState:'),;print(Fore.RESET)
		pprint.pprint(LinkState)
		print(Fore.CYAN + '*'*60),;print(Fore.RESET)

		




from pox.core import core
from pox.lib.addresses import IPAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp
import pox.lib.packet as pkt
from pox.lib.recoco import Timer
from pox.lib.util import str_to_dpid
import pox.openflow.libopenflow_01 as of
import time
# import GetTopo
# from GetTopo import Switch_set,Link_set,ArpTable,PortBytes,PortPackets,t2,t
# global t2,t1
Delay = {}

BandWidth=100
RemainBandWidth = {}
Loss = {}
LinkState = {}             #LinkState的格式为{(dpid1,dpid2):({remainbandwidth},{loss},delay),...}

def Ping(s1,s2):
	global t1
	port1 = 0
	port2 = 0
	mac1 = 0
	mac2 = 0
	ip1 = 0
	ip2 = 0
	for item in Switch_set:
		if s1 == item:
			for item1 in Switch_set[item]:
				if s2 == Switch_set[item][item1][0]:
					port1 = item1
					port2 = Switch_set[item][item1][1]
					break
				else:
					continue
	# print s1,s2
	for dpid in ArpTable:
		if s1 == dpid:
			for ip in ArpTable[dpid]:
				if ArpTable[dpid][ip][0] == port1:
					ip1 = ip
					mac1 = ArpTable[dpid][ip][1]
					break
		elif s2 == dpid:
			for ip in ArpTable[dpid]:
				if ArpTable[dpid][ip][0] == port2:
					ip2 = ip
					mac2 = ArpTable[dpid][ip][1]
					break
	for i in [ip1,ip2,mac1,mac2]:
		if not i:
			return False
	icmp = pkt.icmp()
	icmp.type = pkt.ICMP.TYPE_ECHO_REQUEST
	icmp.payload = "PingPing" * 6

	ipp = pkt.ipv4()
	ipp.protocol = ipv4.ICMP_PROTOCOL
	ipp.srcip = IPAddr(ip1)
	ipp.dstip = IPAddr(ip2)
	ipp.payload = icmp

	e = pkt.ethernet()
	e.src = mac1
	e.dst = mac2
	e.type = ethernet.IP_TYPE
	e.payload = ipp
	# print "Send Packets!"
	# print mac1,mac2,ip1,ip2
	for i in range(10):
		msg = of.ofp_packet_out()
		msg.actions.append(of.ofp_action_output(port = port2))
		msg.data = e.pack()
		core.openflow.sendToDPID(str_to_dpid(s2), msg)
		t1[(s1,s2)]+=time.time()
		# print t1
	return True
def Pingall():
	print(Fore.CYAN + 'Ping All!:'),;print(Fore.RESET)
	global Link_set
	global t1
	global t2
	t1={}
	t2={}
	for dpid1,dpid2 in Link_set:
		t1[(dpid1,dpid2)]=0
		t2[(dpid1,dpid2)]=0
		# dpid1 = str_to_dpid(item[0])
		# dpid2 = str_to_dpid(item[1])
		# for i in range(0,9):
		if not Ping(dpid1,dpid2):
			print "ERROR!"
			return False
	Timer(1, printDelay, recurring=False)
	return True
def printDelay():
	global Delay
	counter=0
	t_min=time.time()*9
	for i in Link_set:
		while t1[i]<t_min or t2[i]<t_min:
			time.sleep(1)
			counter+=1
			if counter>10:
				print "Pingall will retry in 5s"
				time.sleep(5)
				Pingall()
				return
		Delay[i] = (t2[i]-t1[i])/10
		# print t1[i],t2[i]

	# pprint.pprint(Delay)







#!/usr/bin/python
#-*- coding: UTF-8 -*-

from pox.lib.packet.arp import arp
from pox.core import core
from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.packet.ethernet import ethernet
import time

# global Switch_set,Link_set,ArpTable,PortBytes,PortPackets,t2,t

Switch_set = {}          #Switch_set的格式为{dpid1:[(dpid2,port1,port2),...],}
Link_set = []            #Link_set的格式为[(dpid1,dpid2),...]
Hosts = {}               #Hosts的格式为{h1:s1, h2:...}
ArpTable = {}            #ArpTable的格式为{dpid:{ip:(port,mac)}...}
macToPort = {}           #macToPort的格式为{mac1:port1,...}
PortBytes = {}    #PortBytes的格式为{dpid1:[(port1,txbytes,rxbytes),...],dpid2:[...]}
PortPackets = {}  #PortPackets的格式为{dpid1:[(port1,txpackets,rxpackets),...],dpid2:[...]}
t2 = {}
t = {}
count=0

log = core.getLogger()

class GetTopo(EventMixin):
	def __init__(self):
		log.info("GetTopo has come up")
		def startup():
			core.openflow.addListeners(self)
			core.openflow_discovery.addListeners(self)
			core.host_tracker.addListeners(self)
		core.call_when_ready(startup, ('openflow','openflow_discovery','host_tracker'))

	def _handle_LinkEvent(self,event):
		global Switch_set
		global Link_set
		dpid1 = dpid_to_str(event.link.dpid1)  #OpenFlow 交换机 1 的 dpid
		dpid2 = dpid_to_str(event.link.dpid2)  #OpenFlow 交换机 2 的 dpid
		port1 = event.link.port1  #OpenFlow 交换机 1 通过端口 port1连接到该链路上
		port2 = event.link.port2  #OpenFlow 交换机 2 通过端口 port2连接到该链路上
		if event.added == True:
			# 更新 Switch_set
			if dpid1 not in Switch_set:
				Switch_set[dpid1] = {}
			Switch_set[dpid1].update({port1:(dpid2,port2)})

			if dpid2 not in Switch_set:
				Switch_set[dpid2] = {}
			Switch_set[dpid2].update({port2:(dpid1,port1)})

			# 更新 Link_set
			if (dpid1, dpid2) not in Link_set and (dpid2, dpid1) not in Link_set:
				Link_set.append((dpid1, dpid2)) 

		elif event.removed == True:
			# 更新 Switch_set
			if dpid1 not in Switch_set:
				pass

			elif not Switch_set[dpid1]:
				del Switch_set[dpid1]

			elif port1 in Switch_set[dpid1]:
				del Switch_set[dpid1][port1]

			else:
				pass

			if dpid2 not in Switch_set:
				pass

			elif not Switch_set[dpid2]:
				del Switch_set[dpid2]

			elif port2 in Switch_set[dpid2]:
				del Switch_set[dpid2][port2]

			else:
				pass

			# 更新　Link_set
			if (dpid1, dpid2) in Link_set or (dpid2, dpid1) in Link_set:
				if (dpid1, dpid2) in Link_set:
					Link_set.remove((dpid1,dpid2))

				elif (dpid2, dpid1) in Link_set:
					Link_set.remove((dpid2,dpid1)) 

		else:
			pass
		#print "Link_set:",Link_set

	def _handle_ConnectionUp(self,event):
		global Switch_set
		dpid=dpid_to_str(event.dpid)
		if dpid not in Switch_set:
			Switch_set[dpid] = {}
		#log.info("Switch %s has come up.",dpid)
		#print "Switch_set:",Switch_set

	def _handle_ConnectionDown(self,event):
		global Switch_set
		dpid=dpid_to_str(event.dpid)
		if dpid in Switch_set:
			del Switch_set[dpid]
		#log.info("Switch %s has shutdown.",dpid)
		#print "Switch_set:",Switch_set

	def _handle_HostEvent(self, event):
		global Hosts
		mac=str(event.entry.macaddr)
		to_switch=dpid_to_str(event.entry.dpid)
		if event.join == True:
			if mac not in Hosts:
				Hosts[mac] = []
				Hosts[mac].append(to_switch)

			elif to_switch not in Hosts[mac]:
				Hosts[mac].append(to_switch)

			else:
				pass
			#log.info("host %s has come up.",mac)

		elif event.leave == True:
			if mac not in Hosts:
				pass

			else:
				if to_switch in Hosts[mac]:
					Hosts[mac].remove(to_switch)
				del Hosts[mac]
		else:
			pass
		#log.info("host %s has shutdown.",mac)
		#print "Hosts:",Hosts

	def _handle_PortStatsReceived(self,event):
		global PortBytes,PortPackets,t,count

		dpid = dpid_to_str(event.connection.dpid)
		t[dpid]=time.time()
		PortBytes[dpid] = {}
		PortPackets[dpid] = {}

		for item in event.stats:
			txbytes = item.tx_bytes
			rxbytes = item.rx_bytes
			txpackets = item.tx_packets
			rxpackets = item.rx_packets
			port_no = item.port_no
			# print port_no

			#更新PortBytes
			PortBytes[dpid][port_no]=(txbytes,rxbytes)

			#更新PortPackets
			PortPackets[dpid][port_no]=(txpackets,rxpackets)
		count+=1
		# print count
		# pprint.pprint(PortBytes)

	def _handle_PacketIn(self,event):
		dpid = dpid_to_str(event.connection.dpid)
		inport = event.port
		packet = event.parsed
		if not packet.parsed:
			log.warning("%i %i ignoring unparsed packet", dpid, inport)
			return

		if packet.type == ethernet.LLDP_TYPE:
			# Ignore LLDP packets
			return

		if dpid not in ArpTable:
			ArpTable[dpid] = {}
	
		if packet.find("arp"):
			#log.info("arp is coming!")
			a = packet.find("arp")
			if a.prototype == arp.PROTO_TYPE_IP:
				if a.hwtype == arp.HW_TYPE_ETHERNET:
					if a.protosrc != 0:
						ArpTable[dpid][a.protosrc] = (inport, packet.src)
						if a.opcode == arp.REQUEST:
							if a.protodst in ArpTable[dpid]:   #目的节点在ArpTable中,无需泛洪
								macToPort[packet.src] = event.port

		elif packet.find("icmp"):
			if str(packet.payload.payload.payload.payload) == "Ping" * 11:
				# print [packet.payload.payload.payload.payload]
				# print "icmp packet.src:",packet.src
				# print "icmp packet.dst:",packet.dst
				#log.info("icmp is comeing!.")
				# Reply to pings
				global t2
				for port in Switch_set[dpid]:
					if port == inport:
						dpid1 = Switch_set[dpid][port][0]
						if (dpid,dpid1) in Link_set:
							# if (dpid,dpid1) not in t2:
							# 	t2[(dpid,dpid1)]=0
							t2[(dpid,dpid1)]+=time.time()
							
							# print t2[(dpid,dpid1)]





def launch():	

	import pox.openflow.discovery
	pox.openflow.discovery.launch()

	import pox.host_tracker
	pox.host_tracker.launch()

	core.registerNew(GetTopo)

	core.registerNew(GetStats)

