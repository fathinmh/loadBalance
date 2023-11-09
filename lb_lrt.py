import random
import ryu
from ryu.lib import dpid as dpid_lib
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib import mac as mac_lib
from ryu.lib import ip as ip_lib
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.ofproto import ether, inet
from ryu.lib.packet import tcp
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ether_types
from ryu.lib.packet import packet
from ryu.lib.packet import stream_parser
from ryu.ofproto import ofproto_v1_3
from operator import attrgetter
import os
import time
import requests
import socket

class ResponseTimeLB(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(ResponseTimeLB, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        ########## Inisialisasi IP Address Server ##########
        self.svIp1 = "10.0.0.1"
        self.svMac1 = "00:00:00:00:00:01"
        self.svIp2 = "10.0.0.2"
        self.svMac2 = "00:00:00:00:00:02"
        self.svIp3 = "10.0.0.3"
        self.svMac3 = "00:00:00:00:00:03"

        self.get_servers = ['10.0.0.1', '10.0.0.2', '10.0.0.3']

        ########## Variabel untuk menentukan server dipilih ##########
        self.svIndex = 0
        self.rrStatus = True
        self.rrIndex = 0
        self.startTimer = 0
        self.portDecline = ['LOCAL', 4, 5, 6]
        self.responseTime = [0,0,0] #Simpan response time (dipakai untuk LB)
        #Digunakan setelah RR selesai
        self.serverChoose = [] #Simpan list urutan server
        self.serverChooseIndex = 0

    ########## Fungsi untuk inisiasi hubungan switch-controller ##########
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                         actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                priority=priority, match=match,
                                instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # Buat paket ARP reply untuk ARP request dari client ke controller
    ##########
    ########## IP Address dan Mac Address controller di definisikan sendiri ##########
    def generate_arp_reply(self, dstMac, dstIp):
        srcMac = "12:34:56:78:9a:bc"
        srcIp = "10.0.0.100"
        pktRep = packet.Packet()  # Buat paket
        ethRep = ethernet.ethernet(dstMac, srcMac, 0x0806)  # Buat protokol eth
        arpRep = arp.arp(1, 0x0800, 6, 4, 2, srcMac, srcIp,
                        dstMac, dstIp)  # Buat protokol arp
        pktRep.add_protocol(ethRep)  # Tambahkan ke paket
        pktRep.add_protocol(arpRep)  # Tambahkan ke paket
        pktRep.serialize()  # Encode Paket
        return pktRep
    ########## Fungsi untuk memilih server berdasarkan response time ##########
    def getResponsetime(self):
        # Initialize the minimum response time to a very large value
        min_responseTime = float('inf')
        self.serverChoose.clear()
        self.responseTime.clear()
        # Initialize the variable to None
        # lrtServer_temp = None
        # Loop through each server in the list
        for server in self.get_servers:
            # Record the start time
            start_time = time.time()
            try:
                # Create a TCP socket and connect to the server
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.connect((server, 80))
                    # Send a HTTP GET request to the server
                    s.sendall(b'GET / HTTP/1.1\r\nHost: ' + server.encode() + b'\r\n\r\n')
                    # Receive the response from the server
                    data = s.recv(1024)
                    # Record the end time and calculate the response time
                    end_time = time.time()
                    responseTime = end_time - start_time
                    self.responseTime.append(responseTime)
            except socket.timeout:
                self.responseTime.append(float('inf'))
            except socket.error:
                self.responseTime.append(float('inf'))
            print("\n=====\nResponse Time = "+str(self.responseTime)+"\n=====\n")
            responseTime_temp = self.responseTime.copy()
            server_temp = sorted(responseTime_temp)

            # if responseTime_temp[-1] < min_responseTime:
            #     min_responseTime = responseTime_temp[-1]
            #     server_temp = server
            # if lrtServer_temp is not None:
            for i in server_temp:
                self.serverChoose.insert(0,responseTime_temp.index(i)+1)
                responseTime_temp[responseTime_temp.index(i)] = -1
                self.serverChoose.reverse()
                print("\n=====\nServer choose = "+str(self.serverChoose)+"\n=====\n")
                self.svIndex = self.serverChoose[self.serverChooseIndex]
                self.rrStatus = False
                self.startTimer = time.time()
    # # Initialize the minimum response time to a very large value
    #     min_responseTime = float('inf')
    #     self.serverChoose.clear()
    #     self.responseTime.clear()
    
    # # Loop through each server in the list
    #     for server in self.get_servers:
    #     # Send a GET request to the server and record the start time
    #         start_time = time.time()
    #         try:
    #             response = requests.get('http://' + server + '/', timeout=1000)
    #             # Record the end time and calculate the response time
    #             end_time = time.time(response)
    #             responseTime = end_time - start_time
    #             self.responseTime.append(responseTime)
    #         except requests.exceptions.RequestException:
    #             self.responseTime.append(float('inf'))
    #         print("\n=====\nResponse Time = "+str(self.responseTime)+"\n=====\n")
    #         responseTime_temp = self.responseTime.copy()

    #         if responseTime_temp[-1] < min_responseTime:
    #             min_responseTime = responseTime_temp[-1]
    #             lrtServer_temp = server #===> ganti self.serverchoose jadi lrt server
    #     # min_time = float('inf')
    #     # self.serverChoose.clear()
    #     # self.responseTime.clear()
    #     # lrtServer_temp = None
    #     # for server in self.servers:
    #     #     start = time.time()
    #     #     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     #     sock.settimeout(1.0)
    #     #     try:
    #     #         sock.connect((server, 80))
    #     #     except:
    #     #         continue
    #     #     elapsed = time.time() - start
    #     #     sock.close()
    #     #     self.responseTime.append(elapsed)
    #     #     print("\n=====\nResponse Time = "+str(self.responseTime)+"\n=====\n")
    #     #     responseTime_temp = self.responseTime.copy()
    #     #     if responseTime_temp < min_time:
    #     #         min_time = responseTime_temp
    #     #         lrtServer_temp = server
    #     # return selected_server
    #     for i in lrtServer_temp:
    #         self.serverChoose.insert(0,responseTime_temp.index(i)+1)
    #         responseTime_temp[responseTime_temp.index(i)] = -1
    #         print("\n=====\nServer choose = "+str(self.serverChoose)+"\n=====\n")
    #         self.svIndex = self.serverChoose[self.serverChooseIndex]
    #         self.rrStatus = False
    #         self.startTimer = time.time()

    ########## Fungsi untuk handle packet in ##########
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("\n packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
            
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data) #Ambil informasi paket yang masuk
        eth = pkt.get_protocols(ethernet.ethernet)[0] #Ambil ethernet frame
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        dstMac = eth.dst
        srcMac = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("\n Packet-In - DPID: %s SRC_MAC: %s DST_MAC: %s IN_PORT: %s", dpid, srcMac, dstMac, in_port)

        ########## Handle ARP Reply untuk setiap ARP request ke controller ##########
        if(eth.ethertype == 0x0806):
            self.logger.info("\n Checking ARP packet")
            arpInfo = pkt.get_protocols(arp.arp)[0] #Ambil informasi ARP
            if((arpInfo.dst_ip == "10.0.0.100") and (arpInfo.opcode == 1)):
                self.logger.info("\n ARP Packet Checking is done")
                pktRep = self.generate_arp_reply(arpInfo.src_mac, arpInfo.src_ip)
                actionsSv = [parser.OFPActionOutput(in_port)]
                arpSv = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_ANY,
                data=pktRep.data, actions=actionsSv, buffer_id=0xffffffff)
                self.logger.info("\n Packet-Out - DPID: %s SRC_MAC: 12:34:56:78:9a:bc DST_MAC: %s OUT_PORT: %s", dpid, srcMac, in_port) 
                datapath.send_msg(arpSv)
            return
        ########## Mulai koneksi TCP ke server hasil LB ##########
        self.logger.info("\n Checking TCP connection")
        if(eth.ethertype==0x0800):
            ipInfo = pkt.get_protocols(ipv4.ipv4)[0] #Ambil informasi IPv4
            if((ipInfo.dst == "10.0.0.100") and (ipInfo.proto == 0x06)):
                ########## Least Response Time ##########
                ###Start Least Response Time
                #Run Round robin
                if(self.rrIndex == 0):
                    print("\n\nLB RUNNING\n\n")
                    self.svIndex = 0
        
                if(self.rrStatus):
                    self.rrIndex += 1
                    print("\n\nRRINDEX "+str(self.rrIndex)+"\n\n")
                    self.svIndex += 1
                    if (self.svIndex == 4):
                        self.svIndex = 1
                    if (self.rrIndex == 7):
                        self.getResponsetime()
                    
                else:
                    if(time.time()-self.startTimer > 0.5):
                        temp = self.serverChoose[0]
                        self.serverChoose = self.serverChoose[1:]
                        self.serverChoose.append(temp)
                        self.startTimer = time.time()
                        print(self.serverChoose)
                    else:
                        self.svIndex = self.serverChoose[0]

            tcpInfo = pkt.get_protocols(tcp.tcp)[0] #Ambil informasi TCP
            #Buat matching properties untuk pencocok aksi TCP di switch tingkat 1
            match1 = parser.OFPMatch(
                in_port=in_port,
                eth_type=eth.ethertype,
                eth_src=eth.src,
                eth_dst=eth.dst,
                ip_proto=ipInfo.proto,
                ipv4_src=ipInfo.src,
                ipv4_dst=ipInfo.dst,
                tcp_src=tcpInfo.src_port,
                tcp_dst=tcpInfo.dst_port
            )
            actions1=[
                parser.OFPActionSetField(ipv4_src="10.0.0.100"),
                parser.OFPActionSetField(eth_dst="00:00:00:00:00:0"+str(self.svIndex)),
                parser.OFPActionSetField(ipv4_dst="10.0.0."+str(self.svIndex)),
                parser.OFPActionOutput(self.svIndex)
            ]
            ipInst1=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions1)]
            cookie1=random.randint(0, 0xffffffffffffffff)
            #Buat flow
            flow1=parser.OFPFlowMod(
                datapath=datapath,
                match=match1,
                idle_timeout=7,
                instructions=ipInst1,
                buffer_id=msg.buffer_id,
                cookie=cookie1
            )
            self.logger.info("\n Tambah flow host-server------->")
            self.logger.info("\n Request ke server "+str(self.svIndex)+" - IP: "+"10.0.0."+str(self.svIndex)+" Mac: "+"00:00:00:00:00:0"+str(self.svIndex))
            self.logger.info("\n Client-LB - SRC_IP: "+str(ipInfo.src)+" DST_IP: "+str(ipInfo.dst))
            self.logger.info("\n LB-Server - SRC_IP: 10.0.0.100 DST_IP: "+"10.0.0."+str(self.svIndex))
            datapath.send_msg(flow1)
            #TCP Reply
            match2 = parser.OFPMatch(
                self.svIndex,
                eth_type=eth.ethertype,
                eth_src="00:00:00:00:00:0"+str(self.svIndex),
                eth_dst="12:34:56:78:9a:bc",
                ip_proto=ipInfo.proto,
                ipv4_src="10.0.0."+str(self.svIndex),
                ipv4_dst="10.0.0.100",
                tcp_src=tcpInfo.dst_port,
                tcp_dst=tcpInfo.src_port
            )
            actions2=[
                parser.OFPActionSetField(eth_src="12:34:56:78:9a:bc"),
                parser.OFPActionSetField(ipv4_src="10.0.0.100"),
                parser.OFPActionSetField(eth_dst=eth.src),
                parser.OFPActionSetField(ipv4_dst=ipInfo.src),
                parser.OFPActionOutput(in_port)
            ]
            ipInst2=[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions2)]
            cookie2=random.randint(0, 0xffffffffffffffff)
            #Buat flow
            flow2=parser.OFPFlowMod(
                datapath=datapath,
                match=match2,
                idle_timeout=7,
                instructions=ipInst2,
                buffer_id=msg.buffer_id,
                cookie=cookie2
            )
            self.logger.info("\n Server-LB - SRC_IP: "+"10.0.0."+str(self.svIndex)+" DST_IP: 10.0.0.100")
            self.logger.info("\n LB-Client - SRC_IP: 10.0.0.100 DST_IP: "+str(ipInfo.src))
            self.logger.info("\n Tambah flow server-host------->")
            datapath.send_msg(flow2)