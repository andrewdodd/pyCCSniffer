pyCCSniffer
===========

*Live Packet Sniffer for IEEE 802.15.4 networks.*

A Python module that uses a Texas Instruments CC2531emk USB dongle to sniff packets, dissect them and print them to the console.

This tool is has its roots in threee existing GitHub projects, but is significantly more useful than any of them:
 * **[ccsniffpiper](https://github.com/andrewdodd/ccsniffpiper)**: A python tool by me, based on the two below, that pipes the captured frames to wireshark.
 * **[sensniff](https://github.com/g-oikonomou/sensniff)**: A python tool by George Oikonomou to capture packets with the "sensniff" firmware for the TI CC2531 sniffer.
 * **[ccsniffer](https://github.com/christianpanton/ccsniffer)**: A python module by Christian Panton to capture packets with the original TI firmware and print them to stdout.

This tool is similar to TI's Windows-only sniffer program but allows:
 * running in your favourite OS (it has been used in Windows, OS X and Linux)
 * quick and simple access to the payloads (i.e. this is super handy you are developing directly on the 802.15.4 MAC layer instead of using something like ZigBee, as you can parse/humanify your byte stream payloads!).


Requires: pyusb >= 1.0, which can be a bit of a pain to install especially in Windows.

**pyCCSniffer** can run in interactive or 'rude' mode. In interactive mode, the user can change the radio channel while running.

How to Use
==========
Run pyCCSniffer
----------------
**pyCCSniffer**'s main role it to read from the CC2531 USB packet sniffer, parse the frames and print them to the console.

To get this default behaviour, just run the command:
`python pyCCSniffer.py`

To see further information, run the help command:
`python pyCCSniffer.py -h`

Where to start hacking
======================
This script should do most of the heavy lifting you need but at some point you will probably want to intepret the payload in a beacon or a data frame.

In the DissectorHandler's "handle()" method, there is a point marked "# hack here" that is probably the easiest place to start mucking with your own data.

