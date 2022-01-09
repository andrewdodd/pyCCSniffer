import logging
import struct
import sys
from datetime import datetime

import ieee15dot4 as ieee

logger = logging.getLogger(__name__)


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


class CapturedFrame(object):
    def __init__(self, frame, rssiSniff, annotation):
        self.frame = frame
        self.rssiSniff = rssiSniff
        self.annotation = annotation

    def __repr__(self, *args, **kwargs):
        if len(self.annotation) > 0:
            return "{} RssiSniff[{}] Annotation[{}]".format(
                self.frame, self.rssiSniff, self.annotation)

        return "{} RssiSniff[{}]".format(self.frame, self.rssiSniff)


class CustomAssertFrame(object):
    def __init__(self, date, code, line, file, **kwargs):
        self.date = date
        self.code = code
        self.line = line
        self.file = file
        self.time = datetime.now()

    def __repr__(self, *args, **kwargs):
        return "AssertFrame Time[{}] Code[{}] Line[{}] File[{}] Compiled[{}]".format(
            self.time, self.code, self.line, self.file, self.date)


class PacketHandler(object):
    def __init__(self, stats=None):
        self.stats = {} if stats is None else stats
        self.stats['Dissected'] = 0
        self.stats["Dissection errors"] = 0
        self.stats["CRC Errors"] = 0
        self.stats["Beacon"] = 0
        self.stats["Data"] = 0
        self.stats["Acknowledgment"] = 0
        self.stats["MAC Command"] = 0
        self.stats["LLDN"] = 0
        self.stats["Multipurpose"] = 0
        self.stats["Unknown"] = 0
        self.stats["Custom frames"] = 0
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
        print("Printing all captures")
        print("-" * 40)
        for capture in self.captures:
            print(capture)

        print("-" * 40)
        sys.stdout.flush()

    @staticmethod
    def handleCustomFrames(sniffedPacket):
        pdu = sniffedPacket.get_macPDU()
        (debugString, ) = struct.unpack_from("<5s", pdu, 0)

        # For example, I have implemented a generic debug packet that gets sent
        # whenever there is an assert in my code. It takes control of the
        # radio, builds a frame with info about the assert, sends it and then
        # resets the chip.
        if ("Debug" == debugString):
            (payloadVersion, ) = struct.unpack_from("<B", pdu, 5)

            if payloadVersion == 0:
                self.stats["Custom frames"] += 1
                (date, lineNum, code) = struct.unpack_from("<6sHB", pdu, 6)
                #                'Debug', version,  'date12', Line num, code, fcs
                #                 12345 ,  6     ,   789012 , 34      , 5
                nameLength = len(pdu) - 5 - 1 - 6 - 2 - 1 - 2
                (fileName, ) = struct.unpack_from("<%ds" % nameLength, pdu, 15)

                return CustomAssertFrame(date, code, lineNum, fileName)

        return None  # the frame was NOT consumed

    def handleSniffedPacket(self, sniffedPacket):
        if not self.__enabled:
            return

        try:
            if not sniffedPacket or len(sniffedPacket.get_macPDU()) < 2:
                return

            rssiSniff, corr, crc_ok = self.checkPacket(
                sniffedPacket.get_macPDU())

            if not crc_ok:
                self.stats["CRC Errors"] += 1
                return

            customFrame = self.handleCustomFrames(sniffedPacket)
            if customFrame:
                # A custom, non-802.15.4 frame was received and processed
                capture = CapturedFrame(customFrame, rssiSniff,
                                        self.__annotation)
                self.captures.append(capture)
                print(capture)
                sys.stdout.flush()

            else:
                frame = ieee.IEEE15dot4FrameFactory.parse(sniffedPacket)
                capture = CapturedFrame(frame, rssiSniff, self.__annotation)

                if capture:
                    self.captures.append(capture)
                    print(capture)
                    # hack here!
                    sys.stdout.flush()

                self.stats[ieee.FrameType.toString(frame.fcf.frametype)] += 1
                self.stats['Dissected'] += 1

        except Exception as e:
            logger.warning("Error dissecting frame.")
            logger.warning("The error was: %s" % (e.args))
            self.stats["Dissection errors"] += 1

    @staticmethod
    def checkPacket(packet):
        # used to derive other values
        fcs1, fcs2 = packet[-2:]

        # rssi is the signed value at fcs1
        rssi = (fcs1 + 2**7) % 2**8 - 2**7 - 73

        # crc ok is the 7th bit in fcs2
        crc_ok = fcs2 & (1 << 7) > 0

        # correlation value is the unsigned 0th-6th bit in fcs2
        corr = fcs2 & 0x7f

        return (rssi, corr, crc_ok)
