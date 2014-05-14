#!/usr/bin/env python

"""

   pyCCSniffer - a python module to connect to the CC2531emk USB dongle, decode
                 the received frames and provide a quick way to get to your
                 bytes!

   Copyright (c) 2014, Andrew Dodd (andrew.john.dodd@gmail.com)

   This is takes the best parts of two existing sniffers:
   1. ccsniffer - Copyright (c) 2012, George Oikonomou (oikonomou@users.sf.net)
   2. sensniffer - Copyright (C) 2012 Christian Panton <christian@panton.org>

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

"""
   Functionality
   -------------
   Read IEEE802.15.4 frames from the default CC2531 EMK sniffer firmware, 
   decode them and store them in memory (and maybe print them yeah!).

   In interactive mode, the user can also input commands from stdin.
"""

import argparse
import binascii
import collections
from datetime import datetime
import errno
import inspect
from locale import str
import logging.handlers
import math
import os
import select
import stat
import StringIO
import struct
import sys
import threading
import time
import types
import usb.core
import usb.util

__version__ = '0.0.1'

defaults = {
    'debug_level': 'WARN',
    'log_level': 'INFO',
    'log_file': 'pyCCSniffer.log',
    'channel': 11,
}

logger = logging.getLogger(__name__)
stats = {}

# http://stackoverflow.com/questions/3335268/are-object-literals-pythonic
def literal(**kw):
    return collections.namedtuple('literal', kw)(**kw)

#http://stackoverflow.com/questions/36932/how-can-i-represent-an-enum-in-python
# Usage: Numbers = enum('ZERO', 'ONE', 'TWO')
#        Numbers = enum(ONE=1, TWO=2, THREE='three')
#        Numbers.ONE
#        Numbers.fromValue['three']
def enum(*sequential, **named):
    """Build a new type that mocks an ENUM"""
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())
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

class SniffedPacket(object):
    def __init__(self, macPDUByteArray, timestampBy32):
        self.__macPDUByteArray = macPDUByteArray
        self.timestampBy32 = timestampBy32
        self.timestampUsec = timestampBy32 / 32.0
        self.len = len(self.__macPDUByteArray)

    def get_timestamp(self):
        return self.timestampUsec

    def get_macPDU(self):
        return self.__macPDUByteArray

class FrameType(object):
    BEACON = 0
    DATA = 1
    ACK = 2
    MAC_CMD = 3
    UNKNOWN = 255
    MASK = 7

    @staticmethod
    def classify(value):
        if (FrameType.BEACON == (FrameType.MASK & value)):
            return FrameType.BEACON
        if (FrameType.DATA == (FrameType.MASK & value)):
            return FrameType.DATA
        if (FrameType.ACK == (FrameType.MASK & value)):
            return FrameType.ACK
        if (FrameType.MAC_CMD == (FrameType.MASK & value)):
            return FrameType.MAC_CMD

        return FrameType.UNKNOWN

    @staticmethod
    def toString(value):
        if (FrameType.BEACON == value):
            return "Beacon"
        if (FrameType.DATA == value):
            return "Data"
        if (FrameType.ACK == value):
            return "Acknowledgment"
        if (FrameType.MAC_CMD == value):
            return "MAC Command"

        return "Unknown"

class AddressingMode(object):
    NONE = 0
    RESERVED = 1
    SHORT = 2
    EXTENDED = 3
    UNKNOWN = 255
    MASK = 3

    @staticmethod
    def classify(value):
        if (AddressingMode.NONE == (AddressingMode.MASK & value)):
            return AddressingMode.NONE
        if (AddressingMode.RESERVED == (AddressingMode.MASK & value)):
            return AddressingMode.RESERVED
        if (AddressingMode.SHORT == (AddressingMode.MASK & value)):
            return AddressingMode.SHORT
        if (AddressingMode.EXTENDED == (AddressingMode.MASK & value)):
            return AddressingMode.EXTENDED

        return AddressingMode.UNKNOWN

    @staticmethod
    def toString(value):
        if (AddressingMode.NONE == value):
            return "None"
        if (AddressingMode.RESERVED == value):
            return "RESERVED"
        if (AddressingMode.SHORT == value):
            return "Short"
        if (AddressingMode.EXTENDED == value):
            return "Extended"

        return "Unknown"

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
                srcPANId = destPANId

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
    def __init__(self, timestamp, fcf, sequenceNumber, addressing, msdu):
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
    def __init__(self, **kwargs):
        super(IEEE15dot4AckFrame, self).__init__(**kwargs)
        
    def __repr__(self, *args, **kwargs):
        output = []
        output.append("{} -".format(FrameType.toString(self.fcf.frametype)))
        output.append("SeqNum[{}]".format(self.sequenceNumber))
        
        return " ".join(output)
    
class IEEE15dot4BeaconFrame(IEEE15dot4Frame):
    def __init__(self, frameFields, sfs, gts, pendingShortAddresses, pendingExtAddresses, beaconPayload):
        super(IEEE15dot4BeaconFrame, self).__init__(**frameFields)
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
    def __init__(self, frameFields, commandId, payload):
        super(IEEE15dot4CommandFrame, self).__init__(**frameFields)
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
        
        frameFields = {"fcf":fcf,
                       "sequenceNumber": seqNum,
                       "addressing":addressingFields,
                       "timestamp":packet.get_timestamp(),
                       "msdu":byteStream[offset:]}
        
        if fcf.frametype is FrameType.ACK:
            return IEEE15dot4AckFrame(**frameFields)
        elif fcf.frametype is FrameType.BEACON:
            return IEEE15dot4FrameFactory.__parseBeacon(frameFields, frameFields["msdu"])
        elif fcf.frametype is FrameType.MAC_CMD:
            return IEEE15dot4FrameFactory.__parseMACCommand(frameFields, frameFields["msdu"])
        
        return IEEE15dot4Frame(**frameFields)
    
    @staticmethod
    def __parseBeacon(frameFields, beaconMSDU, **kwargs):
        byteStream = beaconMSDU
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

        return IEEE15dot4BeaconFrame(frameFields,
                                     SFS.parse(superframeSpecification),
                                     gts,
                                     pendingShortAddresses,
                                     pendingExtAddresses,
                                     byteStream[offset:],)
        
    @staticmethod
    def __parseMACCommand(frameFields, commandMSDU, **kwargs):
        byteStream = commandMSDU
        offset = 0
        fmt = "<B"
        (commandId, ) = checkAndUnpack(fmt, byteStream, offset, (0,0))
        offset += struct.calcsize(fmt)

        return IEEE15dot4CommandFrame(frameFields,
                                     commandId,
                                     byteStream[offset:])
        
        
class CapturedFrame(object):
    def __init__(self, frame, rssiSniff, annotation):
        self.frame = frame
        self.rssiSniff = rssiSniff
        self.annotation = annotation

    def __repr__(self, *args, **kwargs):
        if len(self.annotation) > 0:
            return "{} RssiSniff[{}] Annotation[{}]".format(self.frame, 
                                                            self.rssiSniff,
                                                            self.annotation)
        
        return "{} RssiSniff[{}]".format(self.frame, self.rssiSniff)

class CustomAssertFrame(object):
    def __init__(self, date, code, line, file, **kwargs):
        self.date = date
        self.code = code
        self.line = line
        self.file = file
        
    def __repr__(self, *args, **kwargs):
        return "AssertFrame Code[{}] Line[{}] File[{}] Compiled[{}]".format(self.code, self.line, self.file, self.date)
    
class PacketHandler(object):
    def __init__(self):
        stats['Dissected'] = 0
        stats["Dissection errors"]  = 0
        stats["CRC Errors"] = 0
        stats["Beacons"] = 0
        stats["Data frames"] = 0
        stats["ACKs"] = 0
        stats["Command frames"] = 0
        stats["Custom frames"] = 0
        self.__annotation = ''
        self.__samples = 0
        self.__beaconPrintingEnabled = True
        self.__dataFramePrintingEnabled = True
        self.__ackPrintingEnabled = True
        self.__commandPrintingEnabled = True
        self.captures = []
        self.enable()

    def enable(self):
        logger.info("Dissector enabled")
        self.__enabled = True
    def disable(self):
        logger.info("Dissector disabled")
        self.__enabled = False
    def isEnabled(self):
        return self.__enabled
    
    def setAnnotation(self, annotation):
        self.__annotation = annotation

        
    def printAllFrames(self):
        print "Printing all captures"
        print "-"*40
        for capture in self.captures:
            print  capture
    
        print "-"*40
        sys.stdout.flush()
        
    @staticmethod
    def handleCustomFrames(sniffedPacket):
        pdu = sniffedPacket.get_macPDU()
        (debugString,) = struct.unpack_from("<5s", pdu, 0)

        # For example, I have implemented a generic debug packet that gets sent
        # whenever there is an assert in my code. It takes control of the 
        # radio, builds a frame with info about the assert, sends it and then
        # resets the chip.
        if ("Debug" == debugString):
            (payloadVersion, ) = struct.unpack_from("<B", pdu, 5)

            if payloadVersion is 0:
                stats["Custom frames"] += 1
                (date, lineNum, code) = struct.unpack_from("<6sHB", pdu, 6)
                #                'Debug', version,  'date12', Line num, code, fcs
                #                 12345 ,  6     ,   789012 , 34      , 5
                nameLength = len(pdu) - 5 - 1 - 6 - 2 - 1 - 2
                (fileName,) = struct.unpack_from("<%ds" % nameLength, pdu, 15)
                
                return CustomAssertFrame(date, code, lineNum, fileName)

        return None # the frame was NOT consumed
          
    def handleSniffedPacket(self, sniffedPacket):
        if self.__enabled is False:
            return

        try:
            if (None == sniffedPacket) or (len(sniffedPacket.get_macPDU()) < 2):
                return


            (rssiSniff, corr, crc_ok) = self.checkPacket(sniffedPacket.get_macPDU())

            if crc_ok is False:
                stats["CRC Errors"] += 1
                return

            customFrame = self.handleCustomFrames(sniffedPacket)
            if customFrame is not None:
                # A custom, non-802.15.4 frame was received and processed
                capture = CapturedFrame(customFrame, rssiSniff, self.__annotation)
                self.captures.append(capture)
                print capture
                sys.stdout.flush()
                
            else:
                frame = IEEE15dot4FrameFactory.parse(sniffedPacket)
                capture = CapturedFrame(frame, rssiSniff, self.__annotation)
                
                if capture is not None:
                    self.captures.append(capture)
                    print capture
                    # hack here!
                    sys.stdout.flush()
    
                statsKey = {FrameType.BEACON: "Beacons",
                             FrameType.DATA: "Data frames",
                             FrameType.ACK: "ACKs",
                             FrameType.MAC_CMD: "Command frames"}[frame.fcf.frametype]
                stats[statsKey] += 1
                stats['Dissected'] += 1
            
        except Exception as e:
            logger.warn("Error dissecting frame.")
            logger.warn("The error was: %s" % (e.args))
            stats["Dissection errors"] += 1

    @staticmethod
    def checkPacket(packet):
        # used to derive other values
        fcs1, fcs2 = packet[-2:]

        # rssi is the signed value at fcs1
        rssi    = (fcs1 + 2**7) % 2**8 - 2**7  - 73

        # crc ok is the 7th bit in fcs2
        crc_ok  = fcs2 & (1 << 7) > 0

        # correlation value is the unsigned 0th-6th bit in fcs2
        corr    = fcs2 & 0x7f

        return (rssi, corr, crc_ok)



class CC2531EMK:
    """CC2531EMK is used to manage the USB device.
    """
    DEFAULT_CHANNEL = 11

    DATA_EP = 0x83
    DATA_TIMEOUT = 2500

    DIR_OUT = 0x40
    DIR_IN = 0xc0

    GET_IDENT = 0xc0
    SET_POWER = 0xc5
    GET_POWER = 0xc6

    SET_START = 0xd0  # bulk in starts
    SET_STOP = 0xd1  # bulk in stops
    SET_CHAN = 0xd2  # 0x0d (idx 0) + data)0x00 (idx 1)

    COMMAND_FRAME = 0x00
#     COMMAND_CHANNEL = ??

    def __init__(self, callback, channel=DEFAULT_CHANNEL):
        """Create a new CC2531EMK manager object
        
        This constructor consumes the first sniffer available on the USB bus.
            
        Args:
            callback(func): A function that will handle any received packets, 
                            with a signature (timestamp, frame).
            channel(int): The channel to sniff on.
        """
        
        self.dev = None
        self.channel = channel
        self.callback = callback
        self.thread = None
        self.running = False

        stats['Captured'] = 0
        stats['Non-Frame'] = 0
        
        if self.callback is None:
            raise ValueError("A valid callback must be provided")
        if len(inspect.getargspec(self.callback)[0]) < 2:
            raise ValueError("Callback must have at least 2 arguments")
        
        try:
            self.dev = usb.core.find(idVendor=0x0451, idProduct=0x16ae)
        except usb.core.USBError:
            raise OSError("Permission denied, you need to add an udev rule for this device", errno=errno.EACCES)

        if self.dev is None:
            raise IOError("Device not found")

        self.dev.set_configuration() # must call this to establish the USB's "Config"
        self.name = usb.util.get_string(self.dev, 256, 2) # get name from USB descriptor
        self.ident = self.dev.ctrl_transfer(CC2531EMK.DIR_IN, CC2531EMK.GET_IDENT, 0, 0, 256) # get identity from Firmware command

        # power on radio, wIndex = 4
        self.dev.ctrl_transfer(CC2531EMK.DIR_OUT, CC2531EMK.SET_POWER, wIndex=4)

        while True:
            # check if powered up
            power_status = self.dev.ctrl_transfer(CC2531EMK.DIR_IN, CC2531EMK.GET_POWER, 0, 0, 1)
            if power_status[0] == 4: break
            time.sleep(0.1)

        self.set_channel(channel)

    def __del__(self):
        if self.dev:
            # power off radio, wIndex = 0
            self.dev.ctrl_transfer(self.DIR_OUT, self.SET_POWER, wIndex=0)

    def start(self):
        # start sniffing
        self.running = True
        self.dev.ctrl_transfer(CC2531EMK.DIR_OUT, CC2531EMK.SET_START)
        self.thread = threading.Thread(target=self.recv)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        # end sniffing
        self.running = False
        self.thread.join()
        self.dev.ctrl_transfer(CC2531EMK.DIR_OUT, CC2531EMK.SET_STOP)

    def isRunning(self):
        return self.running

    def recv(self):

        # While the running flag is set, continue to read from the USB device
        while self.running:
            bytesteam = self.dev.read(CC2531EMK.DATA_EP, 4096, 0, CC2531EMK.DATA_TIMEOUT)
#             print "RECV>> %s" % binascii.hexlify(bytesteam)

            if len(bytesteam) >= 3:
                (cmd, cmdLen) = struct.unpack_from("<BH", bytesteam)
                bytesteam = bytesteam[3:]
                if len(bytesteam) == cmdLen:
                    # buffer contains the correct number of bytes
                    if CC2531EMK.COMMAND_FRAME == cmd:
                        logger.info('Read a frame of size %d' % (cmdLen,))
                        stats['Captured'] += 1
                        (timestamp, pktLen) = struct.unpack_from("<IB", bytesteam)
                        frame = bytesteam[5:]

                        if len(frame) == pktLen:
                            self.callback(timestamp, frame)
                        else:
                            logger.warn("Received a frame with incorrect length, pkgLen:%d, len(frame):%d" %(pktLen, len(frame)))
                            stats['Non-Frame'] += 1

#                     elif cmd == CC2531EMK.COMMAND_CHANNEL:
#                         logger.info('Received a command response: [%02x %02x]' % (cmd, bytesteam[0]))
#                         # We'll only ever see this if the user asked for it, so we are
#                         # running interactive. Print away
#                         print 'Sniffing in channel: %d' % (bytesteam[0],)
#                     else:
#                         logger.warn("Received a command response with unknown code - CMD:%02x byte:%02x]" % (cmd, bytesteam[0]))


    def set_channel(self, channel):
        was_running = self.running

        if 11 <= channel <= 26:
            if self.running:
                self.stop()

            self.channel = channel

            # set channel command
            self.dev.ctrl_transfer(CC2531EMK.DIR_OUT, CC2531EMK.SET_CHAN, 0, 0, [channel])
            self.dev.ctrl_transfer(CC2531EMK.DIR_OUT, CC2531EMK.SET_CHAN, 0, 1, [0x00])

            self.get_channel()

            if was_running:
                self.start()

        else:
            raise ValueError("Channel must be between 11 and 26")

    def get_channel(self):
        return self.channel

    def __repr__(self):
        if self.dev:
            return "%s <Channel: %d>" % (self.name, self.channel)
        else:
            return "Not connected"

def arg_parser():
    debug_choices = ('DEBUG', 'INFO', 'WARN', 'ERROR')

    parser = argparse.ArgumentParser(add_help = False,
                                     description = 'Read IEEE802.15.4 frames \
    from a CC2531EMK packet sniffer device, parse them and dispay them in text.')

    in_group = parser.add_argument_group('Input Options')
    in_group.add_argument('-c', '--channel', type = int, action = 'store',
                          choices = range(11, 27),
                          default = defaults['channel'],
                          help = 'Set the sniffer\'s CHANNEL. Valid range: 11-26. \
                                  (Default: %s)' % (defaults['channel'],))
    in_group.add_argument('-a', '--annotation', type = types.StringType,
                          help = 'Include a free-form annotation on every capture.')

    log_group = parser.add_argument_group('Verbosity and Logging')
    log_group.add_argument('-r', '--rude',
                           action = 'store_true',
                           default = False,
                           help = 'Run in non-interactive mode, without \
                                   accepting user input. (Default Disabled)')
    log_group.add_argument('-D', '--debug-level',
                           action = 'store',
                           choices = debug_choices,
                           default = defaults['debug_level'],
                           help = 'Print messages of severity DEBUG_LEVEL \
                                   or higher (Default %s)'
                                   % (defaults['debug_level'],))
    log_group.add_argument('-L', '--log-file',
                           action = 'store',
                           nargs = '?',
                           const = defaults['log_file'],
                           default = False,
                           help = 'Log output in LOG_FILE. If -L is specified \
                                   but LOG_FILE is omitted, %s will be used. \
                                   If the argument is omitted altogether, \
                                   logging will not take place at all.'
                                   % (defaults['log_file'],))
    log_group.add_argument('-l', '--log-level',
                           action = 'store',
                           choices = debug_choices,
                           default = defaults['log_level'],
                           help = 'Log messages of severity LOG_LEVEL or \
                                   higher. Only makes sense if -L is also \
                                   specified (Default %s)'
                                   % (defaults['log_level'],))

    gen_group = parser.add_argument_group('General Options')
    gen_group.add_argument('-v', '--version', action = 'version',
                           version = 'pyCCSniffer v%s' % (__version__))
    gen_group.add_argument('-h', '--help', action = 'help',
                           help = 'Shows this message and exits')

    return parser.parse_args()

def dump_stats():
    s = StringIO.StringIO()

    s.write('Frame Stats:\n')
    for k, v in stats.items():
        s.write('%20s: %d\n' % (k, v))

    print(s.getvalue())

def log_init():
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, args.debug_level))
    cf = logging.Formatter('%(message)s')
    ch.setFormatter(cf)
    logger.addHandler(ch)

    if args.log_file is not False:
        fh = logging.handlers.RotatingFileHandler(filename = args.log_file,
                                                  maxBytes = 5000000)
        fh.setLevel(getattr(logging, args.log_level))
        ff = logging.Formatter(
            '%(asctime)s - %(levelname)8s - %(message)s')
        fh.setFormatter(ff)
        logger.addHandler(fh)

if __name__ == '__main__':
    args = arg_parser()
    log_init()

    logger.info('Started logging')
    start_datetime = datetime.now()


    packetHandler = PacketHandler()
    packetHandler.enable()

    if args.annotation is not None:
        packetHandler.setAnnotation(args.annotation)

    if args.rude is False:
        h = StringIO.StringIO()
        h.write('Commands:\n')
        h.write('c: Print current RF Channel\n')
        h.write('h,?: Print this message\n')
        h.write('[11,26]: Change RF channel\n')
        h.write('s: Start/stop the packet capture\n')
        h.write('d: Toggle frame dissector\n')
        h.write('a*: Set an annotation (write "a" to remove it)\n')
        h.write('q: Quit')
        h = h.getvalue()

        e = 'Unknown Command. Type h or ? for help'

        print h

    # Create a list of handlers to dispatch to, NB: handlers must have a "handleSniffedPacket" method
    handlers = [packetHandler]
    def handlerDispatcher(timestamp, macPDU):
        """ Dispatches any received packets to all registered handlers

        Args:
            timestamp: The timestamp the packet was received, as reported by 
                       the sniffer device, in microseconds.
            macPDU: The 802.15.4 MAC-layer PDU, starting with the Frame Control 
                    Field (FCF).
        """
        if len(macPDU) > 0:
            packet = SniffedPacket(macPDU, timestamp)
            for handler in handlers:
                handler.handleSniffedPacket(packet)

    snifferDev = CC2531EMK(handlerDispatcher, args.channel)

    try:
        while 1:
            if args.rude is True:
                if snifferDev.isRunning() is False:
                    snifferDev.start()
            else:
                try:
                    # use the Windows friendly "raw_input()", instead of select()
                   cmd = raw_input('')

                   if '' != cmd:
                        logger.debug('User input: "%s"' % (cmd,))
                        if cmd in ('h', '?'):
                            print h
                        elif cmd == 'c':
                            # We'll only ever see this if the user asked for it, so we are
                            # running interactive. Print away
                            print 'Sniffing in channel: {:d}'.format(snifferDev.get_channel())
                        elif cmd == 'd':
                            if packetHandler.isEnabled():
                                packetHandler.disable()
                                print "Dissector disabled"
                            else:
                                packetHandler.enable()
                                print "Dissector enabled"
                        elif cmd == 'p':
                            logger.info('User requested print all')
                            packetHandler.printAllFrames()
                            
                        elif cmd == 'q':
                            logger.info('User requested shutdown')
                            sys.exit(0)
                        elif cmd == 's':
                            if snifferDev.isRunning():
                                snifferDev.stop()
                                print "Stopped"
                            else:
                                snifferDev.start()
                                print "Started"
                        elif 'a' == cmd[0]:
                            if 1 == len(cmd):
                                packetHandler.setAnnotation('')
                            else:
                                packetHandler.setAnnotation(cmd[1:].strip())
                        elif int(cmd) in range(11, 27):
                            snifferDev.set_channel(int(cmd))
                            print 'Sniffing in channel: %d' % (snifferDev.get_channel(),)
                        else:
                            print "Channel must be from 11 to 26 inclusive."
                except ValueError:
                    print e
                except UnboundLocalError:
                    # Raised by command 'n' when -o was specified at command line
                    pass

    except (KeyboardInterrupt, SystemExit):
        logger.info('Shutting down')
        if snifferDev.isRunning():
            snifferDev.stop()
        dump_stats()
        sys.exit(0)

