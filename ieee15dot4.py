#!/usr/bin/env python

"""
   ieee15dot4 - a python module defining IEEE 802.15.4 MAC frames

   Copyright (c) 2014, Andrew Dodd (andrew.john.dodd@gmail.com)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
"""

import binascii
from datetime import datetime
import struct

#http://stackoverflow.com/questions/36932/how-can-i-represent-an-enum-in-python
# Usage: Numbers = enum('ZERO', 'ONE', 'TWO')
#        Numbers = enum(ONE=1, TWO=2, THREE='three')
#        Numbers.ONE
#        Numbers.fromValue['three']
def enum(*sequential, **named):
    """Build a new type that mocks an ENUM"""
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.items())
    enums['fromValue'] = reverse
    return type('Enum', (), enums)

def checkAndUnpack(fmt, buffer, offset, default):
    """Checks that there are enough bytes in the buffer before unpacking
    
    This function uses the provided format string to check if there are
    enough bytes to unpack from the buffer. If not it returns the default
    provided."""
    
    if len(buffer[offset:]) < struct.calcsize(fmt):
        return default

    return struct.unpack_from(fmt, buffer, offset)

class FrameType(object):
    BEACON = 0
    DATA = 1
    ACK = 2
    MAC_CMD = 3
    LLDN = 4
    MULTIPURPOSE = 5
    UNKNOWN = 255
    MASK = 7

    @staticmethod
    def classify(value):
        maskedValue = (FrameType.MASK & value)
        if maskedValue is FrameType.BEACON:
            return FrameType.BEACON
        if maskedValue is FrameType.DATA:
            return FrameType.DATA
        if maskedValue is FrameType.ACK:
            return FrameType.ACK
        if maskedValue is FrameType.MAC_CMD:
            return FrameType.MAC_CMD
        if maskedValue is FrameType.LLDN:
            return FrameType.LLDN
        if maskedValue is FrameType.MULTIPURPOSE:
            FrameType.MULTIPURPOSE

        return FrameType.UNKNOWN

    @staticmethod
    def toString(value):
        if value is FrameType.BEACON:
            return "Beacon"
        if value is FrameType.DATA:
            return "Data"
        if value is FrameType.ACK:
            return "Acknowledgment"
        if value is FrameType.MAC_CMD:
            return "MAC Command"
        if value is FrameType.LLDN:
            return "LLDN"
        if value is FrameType.MULTIPURPOSE:
            return "Multipurpose"

        return "Unknown"

class AddressingMode(object):
    NONE = 0
    SIMPLE = 1
    SHORT = 2
    EXTENDED = 3
    UNKNOWN = 255
    MASK = 3

    @staticmethod
    def classify(value):
        if (AddressingMode.NONE == (AddressingMode.MASK & value)):
            return AddressingMode.NONE
        if (AddressingMode.SIMPLE == (AddressingMode.MASK & value)):
            return AddressingMode.SIMPLE
        if (AddressingMode.SHORT == (AddressingMode.MASK & value)):
            return AddressingMode.SHORT
        if (AddressingMode.EXTENDED == (AddressingMode.MASK & value)):
            return AddressingMode.EXTENDED

        return AddressingMode.UNKNOWN

    @staticmethod
    def toString(value):
        if (AddressingMode.NONE == value):
            return "None"
        if (AddressingMode.SIMPLE == value):
            return "Simple"
        if (AddressingMode.SHORT == value):
            return "Short"
        if (AddressingMode.EXTENDED == value):
            return "Extended"

        raise ValueError(value)

class FCF(object):
    def __init__(self, frametype, securityEnabled, framePending, ackRequested, panIDCompression, destAddressingMode, frameVersion, sourceAddressingMode):
        self.frametype = frametype
        self.securityEnabled = securityEnabled
        self.framePending= framePending
        self.ackRequested = ackRequested
        self.panIdCompression = panIDCompression
        self.destAddressingMode = destAddressingMode
        self.frameVersion = frameVersion
        self.sourceAddressingMode = sourceAddressingMode

    @staticmethod
    def parse(fcf):

        return FCF(FrameType.classify(fcf), # FrameType.MASK & value
                   bool((fcf >> 3) & 0x01),
                   bool((fcf >> 4) & 0x01),
                   bool((fcf >> 5) & 0x01),
                   bool((fcf >> 6) & 0x01),
                   # 7-9: reserved
                   AddressingMode.classify(fcf >> 10),
                   (fcf >> 12) & 0x03,
                   AddressingMode.classify(fcf >> 14))

class SFS(object):
    def __init__(self, beaconOrder, superframeOrder, finalCAPSlot, ble, isPANCoordinator, isAssociationPermitted):
        self.beaconOrder = beaconOrder
        self.superframeOrder = superframeOrder
        self.finalCAPSlot = finalCAPSlot
        self.ble = ble
        self.isPANCoordinator = isPANCoordinator
        self.isAssociationPermitted = isAssociationPermitted
        
    def __repr__(self, *args, **kwargs):
        return "SFS[BO[{}] SO[{}]]".format(self.beaconOrder, self.superframeOrder)

    @staticmethod
    def parse(sfs):
        return SFS(0x0F & sfs,
                   0x0F & (sfs >> 4),
                   0x0F & (sfs >> 8),
                   bool(0x01 & (sfs >> 12)),
                   bool(0x01 & (sfs >> 14)),
                   bool(0x01 & (sfs >> 15)))

class SimpleAddress(object):
    def __init__(self, panId, simpleAddress):
        self.panId = panId
        self.address = simpleAddress

    def __repr__(self, *args, **kwargs):
        return "PAN[{:x}] SimpleAddr[{:x}]".format(self.panId, self.address)

class ShortAddress(object):
    def __init__(self, panId, shortAddress):
        self.panId = panId
        self.address = shortAddress
    
    def __repr__(self, *args, **kwargs):
        return "PAN[{:x}] ShortAddr[{:x}]".format(self.panId, self.address)

class ExtendedAddress(object):
    def __init__(self, panId, extAddress):
        self.panId = panId
        self.address = extAddress

    def __repr__(self, *args, **kwargs):
        return "PAN[{:x}] ExtAddr[{:x}]".format(self.panId, self.address)

class AddressingFields(object):
    def __init__(self, length, destinationAddress, sourceAddress):
        self.length = length
        self.destinationAddress = destinationAddress
        self.sourceAddress = sourceAddress
    
    def __repr__(self, *args, **kwargs):
        output = []
        if self.destinationAddress is not None:
            output.append("Destination[{}]".format(self.destinationAddress))
        if self.sourceAddress is not None:
            output.append("Source[{}]".format(self.sourceAddress))
        
        return "Addresses[{}]".format(" ".join(output))

    @staticmethod
    def parse(fcf, byteStreamAtAddresses):
        length = 0

        if fcf.destAddressingMode is AddressingMode.NONE:
            destinationAddress = None
        else:
            (destPANId, ) = struct.unpack_from("<H", byteStreamAtAddresses, length)
            length += 2

        if fcf.destAddressingMode is AddressingMode.SIMPLE:
            (destSimpleId, ) = struct.unpack_from("<B", byteStreamAtAddresses, length)
            destinationAddress = SimpleAddress(destPANId, destSimpleId)
            length += 1
        if fcf.destAddressingMode is AddressingMode.SHORT:
            (destShortId, ) = struct.unpack_from("<H", byteStreamAtAddresses, length)
            destinationAddress = ShortAddress(destPANId, destShortId)
            length += 2
        if fcf.destAddressingMode is AddressingMode.EXTENDED:
            (destExtId, ) = struct.unpack_from("<Q", byteStreamAtAddresses, length)
            destinationAddress = ExtendedAddress(destPANId, destExtId)
            length += 8


        if fcf.sourceAddressingMode is AddressingMode.NONE:
            sourceAddress = None
        else:
            if False is fcf.panIdCompression:
                (srcPANId, ) = struct.unpack_from("<H", byteStreamAtAddresses, length)
                length += 2
            else:
                if fcf.destAddressingMode is AddressingMode.NONE:
                    print("error, pan compression but no destination address!")
                    destPANId = None
                
                srcPANId = destPANId

        if fcf.sourceAddressingMode is AddressingMode.SIMPLE:
            (srcSimpleId, ) = struct.unpack_from("<B", byteStreamAtAddresses, length)
            sourceAddress = SimpleAddress(srcPANId, srcSimpleId)
            length += 1
        if fcf.sourceAddressingMode is AddressingMode.SHORT:
            (srcShortId, ) = struct.unpack_from("<H", byteStreamAtAddresses, length)
            sourceAddress = ShortAddress(srcPANId, srcShortId)
            length += 2
        if fcf.sourceAddressingMode is AddressingMode.EXTENDED:
            (srcExtId, ) = struct.unpack_from("<Q", byteStreamAtAddresses, length)
            sourceAddress = ExtendedAddress(srcPANId, srcExtId)
            length += 8

        return AddressingFields(length, destinationAddress, sourceAddress)
 
class IEEE15dot4Frame(object):
    def __init__(self, timestamp, fcf, sequenceNumber, addressing, msdu, *args, **kwargs):
        self.time = datetime.now();
        self.timestamp = timestamp
        self.fcf = fcf
        self.sequenceNumber = sequenceNumber
        self.addressing = addressing
        self.msdu = msdu
        
    def __repr__(self, *args, **kwargs):
        output = []
        output.append("{} -".format(FrameType.toString(self.fcf.frametype)))
        output.append("Time[{}]".format(self.time))
        output.append("{}".format(self.addressing))
        output.append("MSDU[{}]".format(binascii.hexlify(self.msdu)))
        
        return " ".join(output)
        
class IEEE15dot4AckFrame(IEEE15dot4Frame):
    def __init__(self, *args, **kwargs):
        super(IEEE15dot4AckFrame, self).__init__(*args, **kwargs)
        
    def __repr__(self, *args, **kwargs):
        output = []
        output.append("{} -".format(FrameType.toString(self.fcf.frametype)))
        output.append("SeqNum[{}]".format(self.sequenceNumber))
        
        return " ".join(output)
    
class IEEE15dot4BeaconFrame(IEEE15dot4Frame):
    def __init__(self, sfs, gts, pendingShortAddresses, pendingExtAddresses, beaconPayload, *args, **kwargs):
        super(IEEE15dot4BeaconFrame, self).__init__( *args, **kwargs)
        self.sfs = sfs
        self.gts = gts
        self.pendingShortAddresses = pendingShortAddresses
        self.pendingExtAddresses = pendingExtAddresses
        self.beaconPayload = beaconPayload
        
    def __repr__(self, *args, **kwargs):
        output = []
        output.append("{} -".format(FrameType.toString(self.fcf.frametype)))
        output.append("Time[{}]".format(self.time))
        output.append("{}".format(self.sfs))
        output.append("{}".format(self.addressing))
        
        if len(self.pendingShortAddresses) > 0:
            addresses = ["{:x}".format(addr) for addr in self.pendingShortAddresses]
            output.append("PendingShort[{}]".format(",".join(addresses)))
        
        if len(self.pendingExtAddresses) > 0:
            addresses = ["{:x}".format(addr) for addr in self.pendingExtAddresses]
            output.append("PendingExt[{}]".format(",".join(addresses)))
        
        output.append("Payload[{}]".format(binascii.hexlify(self.beaconPayload)))
        
        return " ".join(output)
        
CommandFrameType = enum(
    AssociationRequest = 1,
    AssociationResponse = 2,
    DisassociationNotification = 3,
    DataRequest = 4,
    PANIdConflictNotification = 5,
    OrphanNotification = 6,
    BeaconRequest = 7,
    CoordinatorRealignment = 8,
    GTSRequest = 9)
    
        
class IEEE15dot4CommandFrame(IEEE15dot4Frame):
    def __init__(self, commandId, payload, *args, **kwargs):
        super(IEEE15dot4CommandFrame, self).__init__(*args, **kwargs)
        self.commandId = commandId
        self.command = CommandFrameType.fromValue[commandId]
        self.additionalInfo = {}
        
        if self.commandId is CommandFrameType.AssociationRequest:
            fmt = "<B"
            (capabilityInfo, ) = checkAndUnpack(fmt, payload, 0, (0))
            
            self.additionalInfo["allocateAddress"] = bool(0x01 & (capabilityInfo >> 7))
            self.additionalInfo["securityCapable"] = bool(0x01 & (capabilityInfo >> 6))
            self.additionalInfo["rxOnWhenIdle"] = bool(0x01 & (capabilityInfo >> 3))
            self.additionalInfo["isPowered"] = bool(0x01 & (capabilityInfo >> 2))
            self.additionalInfo["isFullFunctionDevice"] = bool(0x01 & (capabilityInfo >> 1))
        
        elif self.commandId is CommandFrameType.AssociationResponse:
            fmt = "<HB"
            (shortAddress, associationStatus) = checkAndUnpack(fmt, payload, 0, (0))
            
            self.additionalInfo["shortAddress"] = shortAddress
            
            
            self.additionalInfo["associationStatus"] = {0: "Successful",
                                                        1: "PAN At Capacity",
                                                        2: "PAN Access Denied",
                                                        }.get(associationStatus, "Reserved")
                                                        
        elif self.commandId is CommandFrameType.DisassociationNotification:
            fmt = "<B"
            (disassociationReason,) = checkAndUnpack(fmt, payload, 0, (0))
            
            self.additionalInfo["disassociationReason"] = {0: "Reserved",
                                                        1: "Coord requested leave",
                                                        2: "Device requested leave",
                                                        }.get(disassociationReason, "Reserved")
                                                        
        elif self.commandId is CommandFrameType.CoordinatorRealignment:
            fmt = "<HHBH"
            (panId, coordShortAddress, channelNumber, shortAddress,) = checkAndUnpack(fmt, payload, 0, (0))
            # NB: Channel Page not decoded
            
            self.additionalInfo["panId"] = panId
            self.additionalInfo["coordShortAddress"] = coordShortAddress
            self.additionalInfo["channelNumber"] = channelNumber
            self.additionalInfo["shortAddress"] = shortAddress

    def __repr__(self, *args, **kwargs):
        output = []
        output.append("{} -".format(FrameType.toString(self.fcf.frametype)))
        output.append("Time[{}]".format(self.time))
        output.append("SeqNum[{}]".format(self.sequenceNumber))
        output.append("{}".format(self.addressing))
        output.append("Command[{}]".format(self.command))
        output.append("AdditionalInfo[{}]".format(self.additionalInfo))
    
        return " ".join(output)
    
class IEEE15dot4FrameFactory(object):
    @staticmethod
    def parse(packet):
        byteStream = packet.get_macPDU()
        offset = 0
        (fcfVal, seqNum) = struct.unpack_from("<HB", byteStream, offset)
        offset += 3

        fcf = FCF.parse(fcfVal)

        addressingFields = AddressingFields.parse(fcf, byteStream[offset:])
        offset += addressingFields.length
        
        frame = IEEE15dot4Frame(packet.get_timestamp(), fcf, seqNum, addressingFields, byteStream[offset:])
        
        if fcf.frametype is FrameType.ACK:
            return IEEE15dot4AckFrame(**frame.__dict__)
        elif fcf.frametype is FrameType.BEACON:
            return IEEE15dot4FrameFactory.__parseBeacon(frame)
        elif fcf.frametype is FrameType.MAC_CMD:
            return IEEE15dot4FrameFactory.__parseMACCommand(frame)

        return frame
    
    @staticmethod
    def __parseBeacon(frame, **kwargs):
        byteStream = frame.msdu
        offset = 0
        fmt = "<HB"
        (superframeSpecification, gts) = checkAndUnpack(fmt, byteStream, offset, (0,0))
        offset += struct.calcsize(fmt)

        fmt = "<B"
        (pendingAddressesSpec,) = checkAndUnpack(fmt, byteStream, offset, (0))
        offset += struct.calcsize(fmt)

        pendingShortCount = 0x07 & pendingAddressesSpec
        pendingExtCount = 0x07 & (pendingAddressesSpec >> 4)

        pendingShortAddresses = []
        pendingExtAddresses = []

        fmt = "<H"
        for i in range(pendingShortCount):
            (nextShortAddress,) = checkAndUnpack(fmt, byteStream, offset, (0))
            offset += struct.calcsize(fmt)
            pendingShortAddresses.append(nextShortAddress)


        fmt = "<Q"
        for i in range(pendingExtCount):
            (nextExtAddress,) = checkAndUnpack(fmt, byteStream, offset, (0))
            offset += struct.calcsize(fmt)
            pendingExtAddresses.append(nextExtAddress)

        return IEEE15dot4BeaconFrame(SFS.parse(superframeSpecification),
                                     gts,
                                     pendingShortAddresses,
                                     pendingExtAddresses,
                                     byteStream[offset:],
                                     **frame.__dict__)
        
    @staticmethod
    def __parseMACCommand(frame, **kwargs):
        byteStream = frame.msdu
        offset = 0
        fmt = "<B"
        (commandId, ) = checkAndUnpack(fmt, byteStream, offset, (0,0))
        offset += struct.calcsize(fmt)

        return IEEE15dot4CommandFrame(commandId,
                                     byteStream[offset:],
                                     **frame.__dict__)

