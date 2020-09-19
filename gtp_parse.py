#! /usr/bin/python3.8
from struct import Struct
from collections import namedtuple
from functools import partial
from scapy.all import *
import datetime
import sys
import json 
from serializer import *


# Ether.payload_guess = [({"type": 0x800}, IP)]
# IP.payload_guess = [({"frag": 0, "proto": 0x11}, UDP)]
# UDP.payload_guess = [({"dport": 53}, DNS), ({"sport": 53}, DNS)]
                     
# conf.sniff_promisc=True

#https://www.lseg.com/sites/default/files/content/documents/GTP%20002%20-%20Technical%20Guide%20-%20Issue%20v19.10.4.2.pdf
#page 25
MsgTypes={  'S':'SystemEvent',
            'p':'InstrumentDirectory',
            'H':'InstrumentStatus', #x
            'A':'AddOrder', #x
            'e':'AddOrderShort', #x
            'f':'AddOrderMBP', 
            'g':'AddOrderShortMBP',
            'F':'AddOrderIncremental',
            'D':'DeleteOrder',
            'U':'ModifyOrder',
            'i':'TopOfBook',
            'y':'OrderBookClear',
            'P':'Trade',
            'q':'TradeCross',
            'w':'Statistics',
            'j':'StatisticsUpdate',
            'k':'StatisticsSnapshot',
            'l':'FTSERussleIndicesUpdate',
            'u':'Announcements',
            'C':'IndicativeQuoteInformation',
            'Q':'MiFIDTrade',
            'T':'MiFIDTradeReport',
            'V':'MiFIDTradeCross',
            'G':'SIQuoting',
            'W':'TradeSummary',
        }

class msg():
    def __init__(self):
        pass

    def populate(self, name, value):
        field = {}
        for f in self.fields:
            if f['name'] == name:
                field = f
        if not field:
            raise Exception("Invalid field [" + name + "]")
        if sys.version_info >= (3, 5) and type(value) is str:
            value = value.encode("utf-8")
        self.values[name] = value

    def deserialize(self, data):
        fields = ''
        for f in self.fields: fields += f['name'] + ' '
        Class = namedtuple(self.__class__.__name__, fields)
        return Class._make(self.unpack(data))

    def print(self):
        x={}
        for f in self.data.keys():
            if type(self.data[f])==bytes:
                x[f]=self.data[f].decode('utf-8')
            else:
                x[f]=self.data[f]

        print(json.dumps(x))
                   

def lse_bin_symbol(i):
    if i:
        hex = i.to_bytes(((i.bit_length() + 7) // 8),"big").hex()
        s=str('0x'+hex[-6:])
        return int(s,base=16)
    else:
        return 0

TCP_field_names = ['sport', 'dport', 'len', 'chksum']
IP_field_names=['len', 'src', 'dst']

def read_block(x):
    m=msg()
    try:
        m.UDPHeader={name:str(getattr(x[UDP],name)) for name in TCP_field_names}
        m.IPHeader={name:str(getattr(x[IP],name)) for name in IP_field_names}
        m.IPHeader['time']=float(x.time)
        x=x.load
    except:
        pass
    
    m.BlockLength=int.from_bytes(x[0:2],byteorder='little')
    m.MessageCount =int.from_bytes(x[2:3],byteorder='little')
    m.MarketDataGroup=chr(int.from_bytes(x[3:4],byteorder='little'))
    m.SequenceNumber=int.from_bytes(x[4:8],byteorder='little')
    
    firstbytes=8
    l=[]
    
    for j in range(m.MessageCount):
        m.i=j
        m.MsgLength=int.from_bytes(x[firstbytes:firstbytes+2], byteorder='little')
        m.Payload=x[firstbytes:firstbytes+m.MsgLength]
        m.MsgType=chr(int.from_bytes(m.Payload[2:3],byteorder='little'))
        m.SequenceMsg=m.SequenceNumber+j
        firstbytes=firstbytes+m.MsgLength        
        yield m    
        
def parse_gtp(pk):
    data=None
    if pk.getlayer('UDP'):
        if pk.load:
            try:
                decode(pk)
            except Exception as e:
#                 raise e
                pk.show()
                print('exception parse_gtp',e)

def decode(x):
    for m in read_block(x):
        if m.MsgType:
            m.MsgTypeName=MsgTypes[m.MsgType]
            Class=globals()[MsgTypes[m.MsgType]]() #calls class function
            m.classname=MsgTypes[m.MsgType]

            val=list(struct.unpack(Class.format,m.Payload))

            fld=[n['name'] for n in Class.fields]
            Message=dict(zip(fld,val))
            m.data=Message
            m.data['InstrumentLong']=Message.get('Instrument',None)
            m.data['Instrument']=lse_bin_symbol(Message.get('Instrument',None))
            
            m.data['EventName']=m.IPHeader['time']
            m.data['src']=m.IPHeader['src']
            m.data['dst']=m.IPHeader['dst']
            m.data['len']=m.IPHeader['len']
            
            m.data['MsgTypeName']=MsgTypes[m.MsgType]
            m.data['Sequence']=m.SequenceMsg
            m.data['MarketDataGroup']=m.MarketDataGroup
            
            if m.data.get('Timestamp'):m.data['Timestamp']=m.data['Timestamp']/10**9
         
            PriceFlds=['PreviousPrice','BidLimitSize','BidLimitPrice',
                       'OfferLimitPrice','OfferLimitSize',
                       'BidMarketSize','OfferMarketSize',
                       'PreviousQuantity','Size','Price','Quantity',
                       'TotalExecutedQuantity','TotalHiddenExecutedQuantity',
                       'DeletedOrderQuantity','ExecutedSize']
            
            for fld in PriceFlds:
                if m.data.get(fld):m.data[fld]=m.data[fld]/10**8
            
            try:
                tm=m.data.get('Timestamp',None)
                m.data['latency']=m.IPHeader['time']-float(tm) 
            except: 
                pass 
            
#             m.IPHeader['time']
            
#             m.print_market_data()
            m.print()
            
        else:print("heartbeat")

# path=sys.argv[1]
seq_num=0

# path="c:\\Dev\\lse_gatelab.pcap"
path=r'c:\Dev\lse_all_G_1_udp_20200828_tshark_00020_20200828153002.pcap'
sniff(offline=path, store=False, prn=parse_gtp, count=100)
# sniff(iface='etg',store=False, prn=parse_gtp, filter='udp and host 194.169.4.55')   
