#! /usr/bin/python3
from struct import Struct
from collections import namedtuple
from functools import partial
from scapy.all import *
import datetime
import sys
# from serializer import *

conf.sniff_promisc=True

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
        print(self.__dict__)
        
    def print_market_data(self):
        print('msg:',MsgTypes[self.MsgType],  
              self.MarketDataGroup,
              self.SequenceNumber, 
              self.latency*1000000%1, 
              self.data.get('Timestamp',0)/10**9, 
              lse_bin_symbol(self.data.get('Instrument',None)), 
              self.data.get('Side',b'\x09').decode('utf-8'),
              self.data.get('Price',0)/10**8, 
              self.data.get('PreviousPrice',0)/10**8, 
              self.data.get('Size',0)/10**4,
              self.data.get('PreviousQuantity',0)/10**4
             )

def lse_bin_symbol(i):
    if i:
        hex = i.to_bytes(((i.bit_length() + 7) // 8),"big").hex()
        s=str('0x'+hex[-6:])
        return int(s,base=16)
    else:
        return None 

    
TCP_field_names = ['sport', 'dport', 'len', 'chksum']
IP_field_names=['len', 'src', 'dst','time']

def read_block(x):
    m=msg()
    m.UDPHeader={name:str(getattr(x[UDP],name)) for name in TCP_field_names}
    m.IPHeader={name:str(getattr(x[IP],name)) for name in IP_field_names}
    
    x=x.load
    
    m.BlockLength=int.from_bytes(x[0:2],byteorder='little')
    m.MessageCount =int.from_bytes(x[2:3],byteorder='little')
    m.MarketDataGroup=chr(int.from_bytes(x[3:4],byteorder='little'))
    m.SequenceNumber=int.from_bytes(x[4:8],byteorder='little')
    
    check_gap(m.SequenceNumber)
    
    firstbytes=8
    l=[]
    
    for j in range(m.MessageCount):
        m.i=j
        m.MsgLength=int.from_bytes(x[firstbytes:firstbytes+2], byteorder='little')
        m.Payload=x[firstbytes:firstbytes+m.MsgLength]
        m.MsgType=chr(int.from_bytes(m.Payload[2:3],byteorder='little'))
        firstbytes=firstbytes+m.MsgLength        
        yield m    
        
def parse_gtp(pk):
    data=None
    if pk.getlayer('UDP'):
        
        if pk.load:
            try:
                decode(pk)
            except Exception as e:
                raise e
                pk.show()
                print('exception',e)

def check_gap(sn):
    global seq_num
    sn_diff=sn-seq_num
    
    if sn_diff>1:
        print("!GAP! last:{} recieved:{} diff:{}".format(seq_num, sn, sn_diff))
    seq_num=sn
    
    
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
            
            try:
                tm=m.data.get('Timestamp',None)/10**9
                m.latency=float(time.time())-float(tm) 
            except: 
                pass 
            
            m.print()
#             print(datetime.datetime.fromtimestamp(tm), 'msg:',MsgTypes[m.MsgType], m.MarketDataGroup, 
#                   m.SequenceNumber, m.latency,m.data,m.IPHeader)
            

        else:print("heartbeat")

# path=sys.argv[1]
seq_num=0

path="c:\\Dev\\gtp.pcap"
sniff(offline=path, store=False, prn=parse_gtp)
# sniff(offline=path, store=False, prn=parse_gtp, filter='udp and host 194.169.4.55')

# sniff(iface='etg',store=False, prn=parse_gtp, filter='udp and host 194.169.4.55')   
    