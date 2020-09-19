import sys 
from struct import Struct
from collections import namedtuple
from functools import partial
import datetime

class Serializer(Struct):
    def __init__(self, tag, fields):
        self.tag = tag
        self.fields = fields

        fmt = '<'
        for f in self.fields: fmt += f['fmt']
        Struct.__init__(self, fmt)

        self.clean()
        self.header()

    def header(self):
        self.populate('Length', (self.size - 8))

    def clean(self):
        self.values = {}
        for f in self.fields:
            if 's' in f['fmt']:
                self.values[f['name']] = ''
            else:
                self.values[f['name']] = 0

    def deserialize(self, data):
        fields = ''
        for f in self.fields: fields += f['name'] + ' '
        Class = namedtuple(self.__class__.__name__, fields)
        return Class._make(self.unpack(data))

    def serialize(self):
        handler = self.pack
        for f in self.fields:
            handler = partial(handler, self.values[f['name']])

        return handler()

    def populate(self, name, value):
        field = {}
        for f in self.fields:
            if f['name'] == name:
                field = f

        if not field:
            raise Exception('Invalid field [' + name + ']')
        if sys.version_info >= (3, 5) and type(value) is str:
            value = value.encode('utf-8')
        self.values[name] = value
        
    def getName(self):
            return self.__class__.__name__


class AddOrderIncremental(Serializer):
     def __init__(self):
        tag = 'F'
        fields = [
            {'name': 'Length', 'fmt': 'H'},
            {'name': 'MessageType', 'fmt': 'c'},
            {'name': 'Timestamp', 'fmt': 'Q'},
            {'name': 'OrderID', 'fmt': 'Q'},
            {'name': 'Side', 'fmt': 'c'},
            {'name': 'Size', 'fmt': 'Q'},
            {'name': 'Instrument', 'fmt': 'Q'},
            {'name': 'Price', 'fmt': 'Q'},
            {'name': 'Yield', 'fmt': 'Q'},
            {'name': 'SourceVenue', 'fmt': 'h'},
            {'name': 'OrderBookType', 'fmt': 'B'},
            {'name': 'Participant', 'fmt': '11s'},
            {'name': 'OrderType', 'fmt': 'b'},
            {'name': 'RFQID', 'fmt': '10s'}
        ]

        Serializer.__init__(self, tag, fields)

class ModifyOrder(Serializer):
     def __init__(self):
        tag = 'U'
        fields = [
            {'name': 'Length', 'fmt': 'H'},
            {'name': 'MessageType', 'fmt': 'c'},
            {'name': 'Timestamp', 'fmt': 'Q'},
            {'name': 'OrderID', 'fmt': 'Q'},
            {'name': 'Instrument', 'fmt': 'Q'},
            {'name': 'Side', 'fmt': 'c'},
            {'name': 'Flags', 'fmt': 'b'},
            {'name': 'OrderBookType', 'fmt': 'b'},
            {'name': 'Quantity', 'fmt': 'Q'},
            {'name': 'Price', 'fmt': 'Q'},
            {'name': 'Yield', 'fmt': 'Q'},
            {'name': 'SourceVenue', 'fmt': 'H'},
            {'name': 'PreviousPrice', 'fmt': 'Q'},
            {'name': 'PreviousQuantity', 'fmt': 'Q'},
            {'name': 'PreviousYield', 'fmt': 'Q'}
        ]

        Serializer.__init__(self, tag, fields)

class DeleteOrder(Serializer):
     def __init__(self):
        tag = 'D'
        fields = [
            {'name': 'Length', 'fmt': 'H'},
            {'name': 'MessageType', 'fmt': 'c'},
            {'name': 'Timestamp', 'fmt': 'Q'},
            {'name': 'OrderID', 'fmt': 'Q'},
            {'name': 'Instrument', 'fmt': 'Q'},
            {'name': 'Side', 'fmt': 'c'},
            {'name': 'OrderBookType', 'fmt': 'B'},
            {'name': 'SourceVenue', 'fmt': 'h'},
            {'name': 'PreviousPrice', 'fmt': 'Q'},
            {'name': 'PreviousYield', 'fmt': 'Q'},
            {'name': 'PreviousQuantity', 'fmt': 'Q'}
        ]

        Serializer.__init__(self, tag, fields)

#error: unpack requires a buffer of 72 bytes
        
class TradeSummary(Serializer):
     def __init__(self):
        tag = 'W'
        fields = [
            {'name': 'Length', 'fmt': 'H'},
            {'name': 'MessageType', 'fmt': 'c'},
            {'name': 'Timestamp', 'fmt': 'Q'},
            {'name': 'Instrument', 'fmt': 'Q'},
            {'name': 'SourceVenue', 'fmt': 'h'},
            {'name': 'TransactionTime', 'fmt': 'Q'},
            {'name': 'FarPrice', 'fmt': 'Q'},
            {'name': 'TotalExecutedQuantity', 'fmt': 'Q'},
            {'name': 'TotalHiddenExecutedQuantity', 'fmt': 'Q'},
            {'name': 'DeletedOrderQuantity', 'fmt': 'Q'},
            {'name': 'Side', 'fmt': 'c'}

	]

        Serializer.__init__(self, tag, fields)
        
class Trade(Serializer):
    def __init__(self):
        tag = 'P'
        
        fields = [
            {'name': 'Length', 'fmt': 'H'},
            {'name': 'MessageType', 'fmt': 'c'},
            {'name': 'Timestamp', 'fmt': 'Q'},
            {'name': 'TransactionTime', 'fmt': 'Q'},
            {'name': 'SourceVenue', 'fmt': 'h'},
            {'name': 'ExecutedSize','fmt':'Q'},
            {'name': 'Instrument', 'fmt': 'Q'},
            {'name': 'Price', 'fmt': 'Q'},
            {'name': 'Yield', 'fmt': 'Q'},
            {'name': 'TradeID', 'fmt': 'Q'},
            {'name': 'TradeType', 'fmt': 'B'},
            {'name': 'AuctionType', 'fmt': 'c'},
            {'name': 'Flags', 'fmt': 'b'},
            {'name': 'HiddenExecutionIndicator', 'fmt': 'B'}
        ]
        Serializer.__init__(self, tag, fields)
        
        
class Statistics(Serializer):
    def __init__(self):
        tag = 'P'
        
        fields = [
            {'name': 'Length', 'fmt': 'H'},
            {'name': 'MessageType', 'fmt': 'c'},
            {'name': 'Timestamp', 'fmt': 'Q'},
            {'name': 'Instrument', 'fmt': 'Q'},
            {'name': 'SourceVenue', 'fmt': 'h'},
            {'name': 'Volume', 'fmt': 'Q'},
            {'name': 'VolumeOnBookOnly', 'fmt': 'Q'},
            {'name': 'VWAP', 'fmt': 'Q'},
            {'name': 'VWAPOnBookOnly', 'fmt': 'Q'},
            {'name': 'NumberOfTrades', 'fmt': 'L'},
            {'name': 'NumberOfTradesOnBookOnly', 'fmt': 'L'},
            {'name': 'Turnover', 'fmt': 'Q'},
            {'name': 'TurnoverOnBookOnly', 'fmt': 'Q'}       
        ]
        Serializer.__init__(self, tag, fields)
        
        
        
class InstrumentStatus(Serializer):
    def __init__(self):
        tag = 'H'
        
        fields = [
            {'name': 'Length', 'fmt': 'H'},
            {'name': 'MessageType', 'fmt': 'c'},
            {'name': 'Timestamp', 'fmt': 'Q'},
            {'name': 'Instrument', 'fmt': 'Q'},
            {'name': 'SourceVenue', 'fmt': 'h'},
            {'name': 'TradingStatus', 'fmt': 'c'},
            {'name': 'SessionChangeReason', 'fmt': 'b'},
            {'name': 'NewEndTime', 'fmt': '6s'},
            {'name': 'OrderBookType', 'fmt': 'b'}
            
        ]
        Serializer.__init__(self, tag, fields)
                
        
class TopOfBook(Serializer):
    def __init__(self):
        tag = 'i'
        
        fields = [
            {'name': 'Length', 'fmt': 'H'},
            {'name': 'MessageType', 'fmt': 'c'},
            {'name': 'Timestamp', 'fmt': 'Q'},
            {'name': 'Instrument', 'fmt': 'Q'},
            {'name': 'SourceVenue', 'fmt': 'h'},
            
            {'name': 'BidMarketSize', 'fmt': 'Q'},
            {'name': 'BidLimitPrice', 'fmt': 'Q'},
            {'name': 'BidYield', 'fmt': 'Q'},
            {'name': 'BidLimitSize', 'fmt': 'Q'},
            {'name': 'OfferMarketSize', 'fmt': 'Q'},
            {'name': 'OfferLimitPrice', 'fmt': 'Q'},
            {'name': 'OfferYield', 'fmt': 'Q'},
            {'name': 'OfferLimitSize', 'fmt': 'Q'},
            {'name': 'OrderBookType', 'fmt': 'b'},
            {'name': 'Flags', 'fmt': 'b'}
            
        ]
        Serializer.__init__(self, tag, fields)
                

class StatisticsUpdate(Serializer):
    def __init__(self):
        tag = 'j'
        
        fields = [
            {'name': 'Length', 'fmt': 'H'},
            {'name': 'MessageType', 'fmt': 'c'},
            {'name': 'Timestamp', 'fmt': 'Q'},
            {'name': 'Instrument', 'fmt': 'Q'},
            {'name': 'SourceVenue', 'fmt': 'h'},
            
            {'name': 'StatisticType', 'fmt': 'H'},
            {'name': 'StatisticPrice', 'fmt': 'Q'},
            {'name': 'StatisticSize', 'fmt': 'Q'},
            {'name': 'AuctionType', 'fmt': 'c'},
            {'name': 'ImbalanceQuantity', 'fmt': 'Q'},
            {'name': 'AuctionInfo', 'fmt': 'c'},
            {'name': 'OpeningClosingPriceIndicator', 'fmt': 'c'}
            
        ]
        Serializer.__init__(self, tag, fields)
        

class AddOrder(Serializer):
    def __init__(self):
        tag = 'A'
        
        fields = [
            {'name': 'Length', 'fmt': 'H'},
            {'name': 'MessageType', 'fmt': 'c'},
            {'name': 'Timestamp', 'fmt': 'Q'},
            {'name': 'OrderID', 'fmt': 'Q'},
            {'name': 'Side', 'fmt': 'c'},
            {'name': 'Size', 'fmt': 'Q'},
            {'name': 'Instrument', 'fmt': 'Q'},
            {'name': 'Price', 'fmt': 'Q'},
            {'name': 'Yield', 'fmt': 'Q'},
            {'name': 'SourceVenue', 'fmt': 'h'},
            {'name': 'OrderBookType', 'fmt': 'b'},
            {'name': 'Participant', 'fmt': '11s'},
            {'name': 'Depth', 'fmt': 'B'}
        ]
        Serializer.__init__(self, tag, fields) 
     
    
class AddOrderShort(Serializer):
    def __init__(self):
        tag = 'e'
        
        fields = [
            {'name': 'Length', 'fmt': 'H'},
            {'name': 'MessageType', 'fmt': 'c'},
            {'name': 'OrderID', 'fmt': 'Q'},
            {'name': 'Size', 'fmt': 'Q'},
            {'name': 'Price', 'fmt': 'Q'},
            {'name': 'Yield', 'fmt': 'Q'},
            {'name': 'Participant', 'fmt': '11s'}
        ]
        Serializer.__init__(self, tag, fields)


class OrderBookClear(Serializer):
    def __init__(self):
        tag = 'y'
        
        fields = [
            {'name': 'Length', 'fmt': 'H'},
            {'name': 'MessageType', 'fmt': 'c'},
            {'name': 'Timestamp', 'fmt': 'Q'},
            {'name': 'SourceVenue', 'fmt': 'h'},
            {'name': 'Instrument', 'fmt': 'Q'},
            {'name': 'OrderBookType', 'fmt': 'b'}
        ]
            
        Serializer.__init__(self, tag, fields)
        
class AddOrderMBP(Serializer):
    def __init__(self):
        tag = 'f'
        
        fields = [
            {'name': 'Length', 'fmt': 'H'},
            {'name': 'MessageType', 'fmt': 'c'},
            {'name': 'Timestamp', 'fmt': 'Q'},
            {'name': 'Side', 'fmt': 'c'},
            {'name': 'Size', 'fmt': 'Q'},
            {'name': 'Instrument', 'fmt': 'Q'},
            {'name': 'Price', 'fmt': 'Q'},
            {'name': 'Yield', 'fmt': 'Q'},
            {'name': 'SourceVenue', 'fmt': 'h'},
            {'name': 'OrderBookType', 'fmt': 'b'},
            {'name': 'Splits', 'fmt': 'H'},
            {'name': 'Depth', 'fmt': 'B'}
        ]
            
        Serializer.__init__(self, tag, fields)

        
class AddOrderShortMBP(Serializer):
    def __init__(self):
        tag = 'g'
        
        fields = [
            {'name': 'Length', 'fmt': 'H'},
            {'name': 'MessageType', 'fmt': 'c'},
            {'name': 'Size', 'fmt': 'Q'},
            {'name': 'Price', 'fmt': 'Q'},
            {'name': 'Yield', 'fmt': 'Q'},
            {'name': 'Splits', 'fmt': 'H'}
        ]
            
        Serializer.__init__(self, tag, fields)

               
class SystemEvent(Serializer):
    def __init__(self):
        tag = 'S'
        
        fields = [
            {'name': 'Length', 'fmt': 'H'},
            {'name': 'MessageType', 'fmt': 'c'},
            {'name': 'Timestamp', 'fmt': 'Q'},
            {'name': 'EventCode', 'fmt': 'c'},
            {'name': 'SourceVenue', 'fmt': 'h'},
            
        ]
            
        Serializer.__init__(self, tag, fields)

                      
class InstrumentDirectory(Serializer):
    def __init__(self):
        tag = 'p'
        
        fields = [
            {'name': 'Length', 'fmt': 'H'},
            {'name': 'MessageType', 'fmt': 'c'},
            {'name': 'Timestamp', 'fmt': 'Q'},
            {'name': 'Instrument', 'fmt': 'Q'},
            {'name': 'ISIN', 'fmt': '12s'},
            {'name': 'AllowedBookTypes', 'fmt': 'b'},
            {'name': 'SourceVenue', 'fmt': 'h'},
            {'name': 'VenueInstrumentID', 'fmt': '11s'},
            {'name': 'TickID', 'fmt': '2s'},
            {'name': 'PriceBandTolerances', 'fmt': 'Q'},
            {'name': 'DynamicCircuitBreakerTolerances', 'fmt': 'Q'},
            {'name': 'StaticCircuitBreakerTolerances', 'fmt': 'Q'},
            {'name': 'GroupID', 'fmt': '6s'},
            {'name': 'UnderlyingISINCode', 'fmt': '12s'},
            {'name': 'Currency', 'fmt': '3s'},
            {'name': 'ReservedField', 'fmt': 'b'},
            {'name': 'ReservedField1', 'fmt': '4s'},
            {'name': 'AverageDailyTurnover', 'fmt': 'Q'},
            {'name': 'ReservedField2', 'fmt': '8s'},
            {'name': 'Flags', 'fmt': 'b'},
            {'name': 'ReservedField3', 'fmt': 'Q'},
            {'name': 'ReservedField4', 'fmt': 'Q'}
        ]
            
        Serializer.__init__(self, tag, fields)
            
                   
class TradeCross(Serializer):
    def __init__(self):
        tag = 'q'
        
        fields = [
            {'name': 'Length', 'fmt': 'H'},
            {'name': 'MessageType', 'fmt': 'c'},
            {'name': 'Timestamp', 'fmt': 'Q'},
            {'name': 'TransactionTime', 'fmt': 'Q'},
            {'name': 'SourceVenue', 'fmt': 'h'},
            {'name': 'ExecutedSize', 'fmt': 'Q'},
            {'name': 'Instrument', 'fmt': 'Q'},
            {'name': 'Price', 'fmt': 'Q'},
            {'name': 'Yield', 'fmt': 'Q'},
            {'name': 'TradeID', 'fmt': 'Q'},
            {'name': 'CrossID', 'fmt': '20s'},
            {'name': 'CrossType', 'fmt': 'B'},
            {'name': 'Flags', 'fmt': 'b'}
        ]
            
        Serializer.__init__(self, tag, fields)
            
                   
class StatisticsSnapshot(Serializer):
    def __init__(self):
        tag = 'k'
        
        fields = [
            {'name': 'Length', 'fmt': 'H'},
            {'name': 'MessageType', 'fmt': 'c'},
            {'name': 'Timestamp', 'fmt': 'Q'},
            {'name': 'Instrument', 'fmt': 'Q'},
            {'name': 'SourceVenue', 'fmt': 'h'},
            {'name': 'Volume', 'fmt': 'Q'},
            {'name': 'VolumeOnBookOnly', 'fmt': 'Q'},
            {'name': 'VWAP', 'fmt': 'Q'},
            {'name': 'VWAPOnBookOnly', 'fmt': 'Q'},
            {'name': 'NumberOfTrades', 'fmt': 'L'},
            {'name': 'NumberOfTradesOnBookOnly', 'fmt': 'L'},
            {'name': 'Turnover', 'fmt': 'Q'},
            {'name': 'TurnoverOnBookOnly', 'fmt': 'Q'},
            {'name': 'OfficialOpeningPrice', 'fmt': 'Q'},
            {'name': 'OfficialClosingPrice', 'fmt': 'Q'},
            {'name': 'TradeHighOnBookOnly', 'fmt': 'Q'},
            {'name': 'TradeLowOnBookOnly', 'fmt': 'Q'},
            {'name': 'TradeHigh', 'fmt': 'Q'},
            {'name': 'TradeLow', 'fmt': 'Q'},
            {'name': '52wkTradeHigh', 'fmt': 'Q'},
            {'name': '52wkTradeLow', 'fmt': 'Q'},
            {'name': 'OpeningPriceIndicator', 'fmt': 'b'},
            {'name': 'ClosingPriceIndicator', 'fmt': 'b'},
            {'name': 'IAUPrice', 'fmt': 'Q'},
            {'name': 'IAUPairedSize', 'fmt': 'Q'},
            {'name': 'ImbalanceQuantity', 'fmt': 'Q'},
            {'name': 'ImbalanceDirection', 'fmt': 'b'},
            {'name': 'BestClosingBidPrice', 'fmt': 'Q'},
            {'name': 'BestClosingAskPrice', 'fmt': 'Q'},
            {'name': 'BestClosingBidSize', 'fmt': 'Q'},
            {'name': 'BestClosingAskSize', 'fmt': 'Q'},
            {'name': 'TradeHighOffBook', 'fmt': 'Q'},
            {'name': 'TradeLowOffBook', 'fmt': 'Q'},
            {'name': 'OpenInterest', 'fmt': 'Q'},
            {'name': 'Volatility', 'fmt': 'Q'},
            {'name': 'AuctionType', 'fmt': 'c'},
            {'name': 'LastTradePrice', 'fmt': 'Q'},
            {'name': 'LastTradeQuantity', 'fmt': 'Q'},
            {'name': 'LastTradeTime', 'fmt': 'Q'},
            {'name': 'StaticReferencePrice', 'fmt': 'Q'},
            {'name': 'DynamicReferencePrice', 'fmt': 'Q'}
            
        ]
            
        Serializer.__init__(self, tag, fields)
                
         
                   
class Announcements(Serializer):
    def __init__(self):
        tag = 'u'
        
        fields = [
            {'name': 'Length', 'fmt': 'H'},
            {'name': 'MessageType', 'fmt': 'c'},
            {'name': 'Timestamp', 'fmt': 'Q'},
            {'name': 'IndexCode', 'fmt': '10s'},
            {'name': 'IndexValue', 'fmt': 'Q'},
            {'name': 'IndexStatus', 'fmt': 'c'},
            {'name': 'TotalReturnValue', 'fmt': 'Q'},
            {'name': 'NetChangePreviousDay', 'fmt': 'Q'},
            {'name': 'IndexTime', 'fmt': '6s'},
            
        ]
            
        Serializer.__init__(self, tag, fields)


