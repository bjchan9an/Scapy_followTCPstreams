# -*- coding: utf-8 -*- 
from scapy.all import *
import thread
import threading
import sys
#from MyColor import color_print
#import time

result_list=[]
TCP_stream_buf=[]  #just a buffer for the real tcp_stream
TCP_stream=[]

threadLock1=threading.Lock()   #lock for the list TCP_stream
#threadLock2=threading.Lock()
program_exit=0


class TCPstream:
    def __init__(number=0,src=(0,0),dst=(0,0),flags=[]):
       self.num=number
       self.src=src
       self.dst=dst
       self.flags=flags
       
def analyze_TCP_flags(flags):
    tcp_type=''
    if flags & 0b000010==0b000010:
       tcp_type+='SYN '
    if flags & 0b010000==0b010000:
       tcp_type+='ACK '
    if flags & 0b000001==0b000001:
       tcp_type+='FIN '
    return tcp_type


#the main analyze class
class MyAnalyze:

    def __init__(self):   
        self.result={}
        
    def analy_ARP(self,dpkt):
        #print 'ARP: fill me first'
        self.result['protocol']='ARP'
        #return self.result
   
    def analy_ICMP(self,dpkt):
        #print 'ICMP: fill me first'
        self.result['protocol']='ICMP'
    
    def analy_UDP(self,dpkt):
        assert dpkt[IP].proto==17
        self.result['protocol']='UDP'
        self.result['sport']=dpkt[UDP].sport
        self.result['dport']=dpkt[UDP].dport
        self.result['ludp_load']=dpkt[UDP].load
        self.result['udp_len']=dpkt[UDP].len
        
           
    def analy_TCP(self,dpkt):
        global threadLock1
        assert dpkt[IP].proto==6
        TCP_flags=dpkt[TCP].flags     
        tcp_type=analyze_TCP_flags(TCP_flags)
        
        self.result['protocol']='TCP'
        self.result['TCP_TYPE']=tcp_type
        self.result['TCP_flag']=dpkt[TCP].flags
        self.result['sport']=dpkt[TCP].sport
        self.result['dport']=dpkt[TCP].dport
        self.result['seq']=dpkt[TCP].seq
        self.result['ack']=dpkt[TCP].ack

        data=''
        message_state=''
        try:
           data=dpkt[Raw].load
           message_state='EXIST DATA'
           self.result['RAW Message']=message_state
        except:
           message_state='NO DATA'
           self.result['RAW Message']=message_state

        '''
        for i in TCP_stream_buf:
           if len(i)>0:
              if dpkt.time- i[-1]['time']>2: #recognize tcp streams based on time
                 print 'add to list!'
                 TCP_stream_buf.remove(i)
                 #set the lock
                 threadLock1.acquire()
                 
                 TCP_stream.append(i)
                 
                 #remove the lock
                 threadLock1.release()'''
                   
        
        if TCP_flags==0b000010:#TCP_flags & 0b000010== 0b000010:  #'SYN ':  
           TCP_stream_buf.append([self.result])
           
        elif TCP_flags==0b010010:#TCP_flags & 0b010010== 0b010010: #'SYN ACK ':
           for i in xrange(len(TCP_stream_buf)):
              #if len(TCP_stream[i])==1:
                  if TCP_stream_buf[i][0]['seq']+1==dpkt[TCP].ack:
                     TCP_stream_buf[i].append(self.result)
                     break
        elif TCP_flags==0b010000 and self.result['RAW Message']=='NO DATA':#TCP_flags & 0b010000== 0b010000: #'ACK ':
           for i in xrange(len(TCP_stream_buf)):
              if len(TCP_stream_buf[i])==2:
                  if TCP_stream_buf[i][1]['seq']+1==dpkt[TCP].ack:
                     TCP_stream_buf[i].append(self.result)
                     break
        elif self.result['RAW Message']=='EXIST DATA':
           for i in xrange(len(TCP_stream_buf)):
              if len(TCP_stream_buf[i])>=3:
                  i_port={TCP_stream_buf[i][0]['sport'],TCP_stream_buf[i][0]['dport']}
                  if {self.result['sport'],self.result['dport']}==i_port:
                     TCP_stream_buf[i].append(self.result)
                     break
        elif TCP_flags & 0b000001 == 0b000001:#TCP_flags=FIN
           #print 'find FIN:',self.result
           for i in xrange(len(TCP_stream_buf)):
              if len(TCP_stream_buf[i])>=3:
                  i_port={TCP_stream_buf[i][0]['sport'],TCP_stream_buf[i][0]['dport']}
                  if {self.result['sport'],self.result['dport']}==i_port:
                     TCP_stream_buf[i].append(self.result)
                     break
        
        
        

                
        
    
    ##############   some definations  ##########################   
    
        
    def analy_IP(self,dpkt):
        assert dpkt[Ether].type==0x800
        self.result['time']=dpkt.time
        self.result['src']=dpkt[IP].src
        self.result['dst']=dpkt[IP].dst 
        #self.result['IP_pkt_size']=len(dpkt)}
        return IP_proto_func[ dpkt[IP].proto ](self,dpkt)    #call suitable analyze func eg. ICMP TCP UDP...   
    
    
    def analy_Ether(self,dpkt):
        #print '============================'
        self.result={}
        Ethertype_func[ dpkt[Ether].type](self,dpkt)  #call suitable analyze func eg. IP ARP... 
        result_list.append(self.result)
        
        
        #return self.result
                    
    ##############   some definations  ##########################
    global Ethertype_func , IP_proto_func
    Ethertype_func={
           0x0800:analy_IP,   #'IP'    #IPv4
           0x0806:analy_ARP,  #'ARP'
           0x0808:'Frame Relay ARP',
           0x6559:'Raw Frame Relay',
           0x8035:'DARP',
           0x86DD:'IPv6',
           0x880B:'PPP'  #point to point protocol
           }
    
    IP_proto_func={  
           1:analy_ICMP,   #'ICMP',
           2:'IGMP',
           6:analy_TCP,     #'TCP',
           17:analy_UDP,    #'UDP',
           88:'IGRP',
           89:'OSPF'
           }        
           

def save_packet(dpkt):
   wrpcap("demo.pcap", dpkt)

def sniff_packets():
   global program_exit
   test=MyAnalyze()       
   dpkt_list=sniff(filter='tcp',iface="ens33",count=800,prn=test.analy_Ether)  #prn define the call back function
   program_exit=1
   thread.exit()
    
def solve_tcpstreams():   #select the tcp stream /print the tcp stream /send as json
   ####################################################
   # this is the thread for extensive analysis 
   # TCP_stream's format like this:
   # [stream1,stream2,stream3]
   # each stream is a {} contains some information of the TCP,like src (ip,port) and dst(ip,port) and so on. use them like stream['src']
   ####################################################
   global program_exit,threadLock1
   while(1):
      threadLock1.acquire()#mutex
      
      if len(TCP_stream)>0:
         print '==============================================='  
         for i in TCP_stream.pop(0):
            print i
      
      threadLock1.release()#mutex 
      if program_exit==1:
         program_exit=2
         break
        
   thread.exit()

def recog_finished_tcp():
   global program_exit,threadLock1
   while(1):
      tmp=TCP_stream_buf
      for i in tmp:
         if len(i)>0:
              if time.time()-i[-1]['time']>1: #recognize tcp streams based on time
                 print 'add to list!'
                 TCP_stream_buf.remove(i)
                 #set the lock
                 threadLock1.acquire()
                 
                 TCP_stream.append(i)
                 
                 #remove the lock
                 threadLock1.release()

      time.sleep(2)
      if program_exit==1:
         break
   thread.exit() 

if __name__ == '__main__':

   try:
      thread.start_new_thread(sniff_packets,())
      thread.start_new_thread(solve_tcpstreams,())
      thread.start_new_thread(recog_finished_tcp,())
   except:
      print "Error: unable tot start thread"
   while(1):
      if program_exit==2:
          break
      
