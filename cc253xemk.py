"""
   Copyright (c) 2014, Andrew Dodd (andrew.john.dodd@gmail.com)
"""
import errno
import logging
import struct
import threading
import time
from binascii import hexlify
from collections import namedtuple

import usb.core
import usb.util

logger = logging.getLogger(__name__)

VendorProduct = namedtuple('VendorProduct',
                           ['idVendor', 'idProduct', 'data_endpoint'])
CC2531_USB_DESCRIPTOR = VendorProduct(0x0451, 0x16ae, 0x83)
CC2530_USB_DESCRIPTOR = VendorProduct(0x11a0, 0xeb20, 0x82)


def _select_device(vendor_products):
    try:
        for vp in vendor_products:
            return usb.core.find(idVendor=vp.idVendor,
                                 idProduct=vp.idProduct), vp
    except usb.core.USBError:
        raise OSError(
            "Permission denied, you need to add an udev rule for this device",
            errno=errno.EACCES)

    return None, None


class CC253xEMK:
    """CC253xEMK is used to manage the USB device.
    """
    DEFAULT_CHANNEL = 11

    DATA_TIMEOUT = 2500

    DIR_OUT = 0x40
    DIR_IN = 0xc0

    GET_IDENT = 0xc0
    SET_POWER = 0xc5  # 11000101
    GET_POWER = 0xc6  # 11000110

    SET_START = 0xd0  # bulk in starts
    SET_STOP = 0xd1  # bulk in stops
    SET_CHAN = 0xd2  # 0x0d (idx 0) + data)0x00 (idx 1)

    COMMAND_FRAME = 0x00
    HEARTBEAT_FRAME = 0x01

    COMMAND_CHANNEL = 0x01

    def __init__(self, handler, channel=DEFAULT_CHANNEL, auto_init=True):
        """Create a new CC253xEMK manager object
        
        This constructor consumes the first sniffer available on the USB bus.
            
        Args:
            handler: Object with handler functions
            channel(int): The channel to sniff on.
        """

        self.dev = None
        self.channel = channel
        self.thread = None
        self.running = False
        self.handler = handler

        if auto_init:
            self.initialise()

    def initialise(self):
        self.dev, self.vendor_product = _select_device(
            [CC2531_USB_DESCRIPTOR, CC2530_USB_DESCRIPTOR])
        if self.dev is None:
            raise IOError("Device not found")

        # must call this to establish the USB's "Config"
        self.dev.set_configuration()
        self.name = usb.util.get_string(self.dev, self.dev.iProduct)
        # get identity from Firmware command
        self.ident = self.dev.ctrl_transfer(CC253xEMK.DIR_IN,
                                            CC253xEMK.GET_IDENT, 0, 0, 256)

        # power on radio, wIndex = 4
        self.dev.ctrl_transfer(CC253xEMK.DIR_OUT,
                               CC253xEMK.SET_POWER,
                               wIndex=4)

        while True:
            # check if powered up
            power_status = self.dev.ctrl_transfer(CC253xEMK.DIR_IN,
                                                  CC253xEMK.GET_POWER, 0, 0, 1)
            if power_status[0] == 4: break
            time.sleep(0.1)

        self.set_channel(self.channel)

    def start(self):
        # start sniffing
        self.running = True
        self.dev.ctrl_transfer(CC253xEMK.DIR_OUT, CC253xEMK.SET_START)
        self.thread = threading.Thread(target=self.__pull_messages)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        # end sniffing
        self.running = False
        self.thread.join()
        self.dev.ctrl_transfer(CC253xEMK.DIR_OUT, CC253xEMK.SET_STOP)

    def isRunning(self):
        return self.running

    def __pull_messages(self):

        # While the running flag is set, continue to read from the USB device
        while self.running:
            bytesteam = self.dev.read(self.vendor_product.data_endpoint,
                                      4096,
                                      timeout=CC253xEMK.DATA_TIMEOUT)

            if len(bytesteam) >= 3:
                (cmd, payload_len) = struct.unpack_from("<BH", bytesteam)
                payload = bytesteam[3:]
                if len(payload) == payload_len:
                    # buffer contains the correct number of bytes
                    if CC253xEMK.COMMAND_FRAME == cmd:
                        logger.info(f'Read a frame of size {payload_len}')
                        timestamp, frame_len = struct.unpack_from(
                            "<IB", payload)
                        frame = payload[5:]

                        if len(frame) == frame_len:
                            self.handler.received_valid_frame(timestamp, frame)

                        else:
                            self.handler.received_invalid_frame(
                                timestamp, frame_len, frame)
                    elif CC253xEMK.HEARTBEAT_FRAME == cmd:
                        self.handler.received_heartbeat_frame(payload[0])
                    else:
                        self.handler.received_unknown_command(
                            cmd, payload_len, payload)
                else:
                    self.handler.received_invalid_command(
                        cmd, payload_len, bytesteam)

    def set_channel(self, channel):
        was_running = self.running

        if 11 <= channel <= 26:
            if self.running:
                self.stop()

            # set channel command
            self.dev.ctrl_transfer(CC253xEMK.DIR_OUT, CC253xEMK.SET_CHAN, 0, 0,
                                   [channel])
            self.dev.ctrl_transfer(CC253xEMK.DIR_OUT, CC253xEMK.SET_CHAN, 0, 1,
                                   [0x00])

            # I don't really understand this USB stuff, so cannot figure out
            # how to read the channel from the device....just store it here
            # instead
            self.channel = channel

            if was_running:
                self.start()

        else:
            raise ValueError("Channel must be between 11 and 26")

    def get_channel(self):
        return self.channel

    def __repr__(self):
        if self.dev:
            return f"{self.name} <Channel: {self.channel}>"
        else:
            return "Not connected"
