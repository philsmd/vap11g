#!/usr/bin/python
# LICENSE: GPLv2
# author: philsmd
# date: nov 2012
#
# This python script is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# vap11g.py is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this source files. If not, see
# <http://www.gnu.org/licenses/>.
#
# NO reverse engineering done or any kind of reverse engineering
# of the original software intended
# This script just "replays" the messages that the original software
# uses to communicate with the device
# The capture of the communication can be done via any OPEN SOURCE
# tool AND (as shown when this script was already in a stable state)
# the message exchange was (anyway) already available/published on
# some websites and wikis AND therefore can be considered as knowledge
# in the public domain
# If you use this script/software you can not claim any responsibility
# for ANY damage, malfunction and other problems to the author
# USE it at your OWN RISK and use it only iff you really want/need and
# trust the author
#
# Motivation: ANYONE (also me) should be allowed to use the devices he
# bought (for private use and maybe others too) w/o the necessity to buy
# over expansive operating systems (OS) or other additional priority
# software
# FREE the world!!! everyone should be FREE to use his/her devices
#
# use git(hub) to post pull request,to submit patches,to discuss issues
# PEACE!
#
# This software should be run on any *nix system with python installed,
# if you want to render it cross-plattform, submit patches for other OSes

import select
import string
import fcntl
import struct
import getpass
import hashlib
import time
from socket import socket, SOCK_RAW, AF_PACKET, htons
from optparse import OptionParser

##################################################################

# SETTINGS
debug = False
verbose = False
defaultInterface = "eth0"

##################################################################

# CONSTANTS / GLOBALS
ETH_ALL = 3
ETH_BROADCAST = "ff:ff:ff:ff:ff:ff"
ETH_TYPE = "\x88\x88"
SECURITY_OPTIONS = ("Disable", "WEP", "WPA-PSK", "WPA2-PSK")
HEX_MAX_LINE_SYMBOLS = 16
HEX_DELIMITER = ":"
HEX_MIN_NUMBER_LEN = 4
HEX_MIN_NUMBER_PADDING = 8
HEX_DEFAULT_HEX_CHAR = "."
HEX_BLOCK_SIZE = 3
HEX_SMALLEST_CHAR = 32
HEX_LARGEST_CHAR = 127

# WEP passphrase to keys conversion uses the defacto standard generation
WEP_OPTIONS = ("WEP 64bits using passphrase", "WEP 128bits using passphrase", "WEP 64bits keys",
    "WEP 128bits key")
HIDDEN_SSID = "[HiddenSSID]"
WIRELESS_NETWORK_MODE = {"":"802.11 (2Mbps)", "A":"802.11a (54Mbps)",
    "B":"802.11b (11Mbps)", "G":"802.11g (54Mbps)", "N":"802.11n (150Mbps)",
    "AC":"802.11ac (866.7Mbps)", "AD":"802.11ad (7000Mbps)"} # IEEE 802.11x (of course NOT all avail for VAP11g-abg)

# DEVICE SPECIFIC COMMANDS:
COMMAND_DEVICE_STATUS = "\x00\x01"
COMMAND_CONFIG = "\x01\x01"
COMMAND_REQUEST_RESPONSE = "\x02\x01"
DATA_END = ":\x0d\x0a"
DATA_REQUEST_CONFIG = 9100
DATA_REQUEST_SCAN = 9107
DATA_REQUEST_RESET = 9002

##################################################################

def eth_aton (mac):
    addr = ""
    temp = string.split (mac, ':')
    mac = string.join (temp, '')

    for i in range (0,len (mac),2):
        addr = "" . join ([addr, struct.pack ('B', int (mac[i:i+2], 16))],)

    return addr

def conv_octet (octet):
    res = ""
    factor = 16

    for i in range (0, 2):  # max ff = 15*16+15
        div = int (octet / factor)
        res += "%x" % div
        octet -= div * 16
        factor /= 16

    return res

def eth_rev_aton (hexstr):
    res = ""

    for i in range (0, 6):
        if res:
            res += ':'
        res += conv_octet (ord (hexstr[i]))

    return res

def hexdump_add_printable_chars (res, spaces = 0):
    res += "  "
    k = len (res) - 1
    j = k - HEX_BLOCK_SIZE * HEX_MAX_LINE_SYMBOLS
    ord_num = 0
    k -= HEX_BLOCK_SIZE * spaces

    while j < k:
        if len (str (res[j] + res[j + 1])) == 2:
            ord_num = int (res[j]+res[j+1],16)

            if ord_num > HEX_SMALLEST_CHAR and ord_num < HEX_LARGEST_CHAR:
                res += chr (ord_num)
            else:
                res += HEX_DEFAULT_HEX_CHAR
        j += 3

    res += "\n"
    return res

def hexdump (string):
    res = ""
    i = 0
    str_len = len (string)
    number_display = 0

    while i < str_len:
        if i % HEX_MAX_LINE_SYMBOLS == 0:
            if i != 0:
                res = hexdump_add_printable_chars (res)
            len_pos = len (str (number_display))
            len_leading_zeros = HEX_MIN_NUMBER_LEN - len_pos
            len_padding = HEX_MIN_NUMBER_PADDING - len_leading_zeros - len_pos

            while len_padding > 0:
                res += " "
                len_padding -= 1

            while len_leading_zeros > 0:
                res += "0"
                len_leading_zeros -= 1

            res += str (number_display) + HEX_DELIMITER
            number_display += HEX_MAX_LINE_SYMBOLS 

        res += " %02x" % ord (string[i])
        i += 1

    added_spaces = 0

    while str_len % HEX_MAX_LINE_SYMBOLS != 0:
        res += "   "
        added_spaces += 1
        str_len += 1

    res = hexdump_add_printable_chars (res, added_spaces)

    return res

def getHwAddr (s, ifname):
    global debug

    info = fcntl.ioctl (s.fileno (), 0x8927, struct.pack ("256s", ifname[:15]))
    mymac = '' . join (["%02x:" % ord (char) for char in info[18:24]])[:-1]

    if debug:
        print "[i] Your local ethernet MAC address is %s for interface %s " % (mymac, ifname)

    return mymac

def buildRequest (src, dst, c = '', p = ''):
    global debug

    dst_addr = eth_aton (dst)  # format: "01:02:03:04:05:06"
    src_addr = eth_aton (src)  # idem

    ethertype = ETH_TYPE

    if len (p) > 0:
        p = "\x00\x00\x00\x00\x00" + chr (len (p)) + '\x00' + p # all 00 since we have no packet splitting (amount = 0)

    p = c + p

    if len (p) < 50:
        p += ("\x00" * (50 - len (p)))

    packet = dst_addr + src_addr + ethertype + p

    if verbose:
        print "[i] The data:"
        print hexdump (str (packet))

    return str (packet)

def read (s, enableExit = True):
    ready = select.select ([s], [], [], 2)

    if ready[0]:
        return s.recvfrom (4096)
    elif enableExit:
        print "[-] Error: socket timed out. EXIT"
        exit (1)
    else:
        return None

def parseNetworkStr (string):
    res = {}
    if len (string) > 0:
        lines = string.split ('\n')

        for l in lines:
            try:
                spaceIndex = l.index ('\x0c')
                details = l[spaceIndex + 1:]
                name = l[0:spaceIndex]
            except:
                name = ""
                details = l

            # parse details: mac,channel,speed (802.1 'G',...),security,signal
            detailsSplit = details.split (',')
            macAddress = detailsSplit[0]
            macAddress = "" . join (macAddress[i:i+2] + ("" if i > len (macAddress) / 2 + 2 else ":") 
                for i in xrange (0, len (macAddress), 2))
            res[macAddress] = {"name":name, "channel":detailsSplit[1], "speed":detailsSplit[2],
                "security":detailsSplit[3], "signal":detailsSplit[4], "psk":""}
    return res

def parseCurrentConfig (string):
    res = {}
    bssid = ""
    resValues = {}
    lines = string.split ('\n')

    for l in lines:
        if len (l) > 0:
            search = "7000 SSID:"
            if search in l:
                resValues["name"] = l[l.index (search) + len (search):]
            else:
                search = "7002 CHANNEL:"
                if search in l:
                    resValues["channel"] = l[l.index (search) + len (search):]
                else:
                    search = "7003 SECMODE:"
                    if search in l:
                        resValues["security"] = l[l.index (search) + len (search):]
                    else:
                        search = "7019 PSKKEY:"
                        if search in l:
                            resValues["psk"] = l[l.index (search) + len (search):]
                        else:
                            search = "BSS ID = "
                            if search in l:
                                bssid = l[l.index (search) + len (search):]

    res[bssid] = resValues
    return res

def printNetworks (netList):
    count = 1

    for (mac, details) in netList.items ():
        name = details["name"]

        if not name:
            name = HIDDEN_SSID
        try:
            sec = int (details["security"])
            if not (sec >= 0 and sec < len (SECURITY_OPTIONS)):
                sec = 3
        except:
            sec = 3
        try:
            speed = WIRELESS_NETWORK_MODE[details["speed"]]
        except:
            speed = WIRELESS_NETWORK_MODE["G"]

        print str (count)+") ESSID: " + name + ", channel: " + details["channel"] + ", signal: " + \
            details["signal"] + "%, security: " + SECURITY_OPTIONS[sec] + ", speed: " + speed
        count += 1

    # ALWAYS print the following additional item
    print str (count) + ") freely add new network configuration"

def getSecmodeSelection ():
    print "[i] Available security modes:"

    count = 1 

    for name in SECURITY_OPTIONS:
        print str (count) + ") " + name
        count += 1

    num = 0

    while num < 1 or num > len (SECURITY_OPTIONS):
        try:
            num = int (raw_input ("[i] Please choose one of the options above: "))
        except KeyboardInterrupt:
            print "\n"
            exit (1)
        except:
            num = 0

    return num - 1

def inputWepKeys (strong): # means we use 26 hexadecimal characters
    print "[i] Input the keys using the hexadecimal character set [0-9A-Z] (no colons): "

    if strong:
        key = ""

        while len (key) != 26 or not all (c in string.hexdigits for c in key):
            key = raw_input ("[i] Please insert the 128bit WEP key (26 hex characters): ")

        key = key.upper ()
        key = (key, key, key, key)
    else:
        key = ()
        count = 1
        while count <= 4:
            try:
                tmpkey = raw_input ("[i] Please insert key%d (10 hex characters): " % count)
                if len (tmpkey) == 10 and all (c in string.hexdigits for c in tmpkey):
                    key = key + (tmpkey.upper (),)
                    count += 1
            except KeyboardInterrupt:
                print "\n"
                exit (1)
            except: # catch all other
                count = count

    return key

def passphrase2WepKeys (strong, passphrase = ""): # strong means 128bit
    res = ("", "", "", "")

    while len (passphrase) < 1 or len (passphrase) > 32:
        passphrase = getpass.getpass ("[i] Please input the passphrase (1-32 characters, will" + \
                " NOT be displayed): ")

    length = len (passphrase)
    key = ""

    if strong: # 128 bit using MD5
        j = 0
        buf = ""

        for i in range (0, 64):
            if j >= length:
                j = 0

            buf += passphrase[j]
            j += 1

        m = hashlib.md5 ()
        m.update (buf)
        key = m.hexdigest ()[:26]
        key = key.upper ()
        res = (key, key, key, key) 
    else: # 64 bit
        i = 0
        val = 0

        while i < length:
            shift = i & 0x3
            val ^= ord (passphrase[i]) << (shift * 8)
            i += 1

        for i in range (0, 20):
            val *= 0x343fd
            val += 0x269ec3
            key += "%0.2x" % ((val >> 16) % 256)

        if key and len (key) == 40:
            key = key.upper ()
            res = (key[:10], key[10:20], key[20:30], key[30:40]) 

    return res

def main ():
    global debug, defaultInterface, verbose

    parser = OptionParser ()
    parser.add_option ("-i", "--interface", dest = "interface", help = "destination LAN (ethernet) " + \
            "interface (e.g. eth0, eth1, p4p1)", metavar = "interface")
    parser.add_option ("-d", "--debug", action = "store_true", default = debug, dest = "debug",
            help = "debug mode switch", metavar = "debug")
    parser.add_option ("-v", "--verbose", action = "store_true", default = debug, dest = "verbose",
            help = "same as debug mode (-d)", metavar = "verbose")
    parser.add_option ("-s", "--ssid", dest = "ssid", help = "ESSID, network name", metavar = "ssid")
    parser.add_option ("-c", "--channel", type = "int", dest = "channel", help = "channel number, from" + \
            " 0 (auto) to 11, does NOT influence ssid search", metavar = "channel")
    parser.add_option ("-n", "--noauth", action = "store_true", default = False, dest = "noauth",
            help = "network authentication disabled", metavar = "noauth")
    parser.add_option ("-w", "--wep", action = "store_true", default = False, dest = "wep",
            help = "network authentication using WEP", metavar = "wep")
    parser.add_option ("-p", "--wpa", action = "store_true", default = False, dest = "wpa",
            help = "network authentication using WPA", metavar = "wpa")
    parser.add_option ("-a", "--wpa2", action = "store_true", default = False, dest = "wpa2",
            help = "network authentication using WPA2", metavar = "wpa2")
    parser.add_option ("-k", "--key", dest = "key", help = "network passphrase, password, key",
            metavar = "key")
    parser.add_option ("-t", "--strong", action = "store_true", default = False, dest = "strong",
            help = "128 bit strong encryption", metavar = "strong")

    (options, args) = parser.parse_args ()

    interface = ""

    if not options.interface is None:
        interface = options.interface

    if not interface:
        interface = defaultInterface

    if options.verbose:
        verbose = True

    if options.debug:
        debug = True
        print "[i] Interface name to use: " + interface

    if not options.channel is None:
        tmpChannel = int (options.channel)

        if tmpChannel < 0 or tmpChannel > 12:
            print "[-] Error: channel number must be 0 (auto) or between 1 and 11"
            exit (1)

    if not options.ssid is None:
        if len (options.ssid) < 1 or len (options.ssid) > 32:
            print "[-] Error: ESSID network name must be less than 32 alphanumeric characters"
            exit (1)

    # options.noauth options.wep options.wpa options.wpa2 options.key
    if options.noauth and not options.key is None:
        print "[-] Error: if noauth mode is used you can't specify a network key"
        exit (1)

    exlusiveOption = 0

    for i in (options.noauth, options.wep, options.wpa, options.wpa2):
        if i:
            exlusiveOption += 1

    if exlusiveOption > 1:
        print "[-] Error: you can only use one security protocol (e.g. WEP, WPA2) at a time" 
        exit (1)

    # START
    # our raw socket
    s = socket (AF_PACKET, SOCK_RAW, htons (ETH_ALL))
    s.bind ((interface, ETH_ALL))

    src = getHwAddr (s, interface)

    # first request: check if there are some devices connected
    s.send (buildRequest (src, ETH_BROADCAST))

    (msg, address) = read (s)

    if verbose:
        print "[i] The response:"
        print hexdump (str (msg))

    dst = eth_rev_aton (address[-1])

    if debug:
        print "[i] Got response from device on interface '%s' with MAC %s" % (address[0], dst)

    # force rescan of ssids (networks)
    s.send (buildRequest (src, dst, COMMAND_DEVICE_STATUS))
    read (s)

    s.send (buildRequest (src, dst, COMMAND_CONFIG + '\x01', str (DATA_REQUEST_SCAN) + DATA_END))
    read (s)

    s.send (buildRequest (src, dst, COMMAND_REQUEST_RESPONSE + '\x02'))
    read (s)

    time.sleep (4) # we need this, otherwise we always get an empty network list

    # get device info start:
    s.send (buildRequest (src, dst, COMMAND_CONFIG + '\x01', str (DATA_REQUEST_CONFIG) + DATA_END))

    (msg, address) = read (s)

    if verbose:
        print "[i] The response:"
        print hexdump (str (msg))

    # fetch the info:
    s.send (buildRequest (src, dst, COMMAND_REQUEST_RESPONSE + '\x02'))
    (msg,address) = read (s)

    if verbose:
        print "[i] The response:"
        print hexdump (str (msg))

    if debug:
        print "[i] Box data:"
        print msg[26:-1]

    if "VAP11G" not in  msg:
        print "[-] Box data does NOT contain the right BOX_NAME identifier. EXIT"
        exit (1)

    finalMsg = ""

    # get SURVEY (next packet)
    msg = read (s, False)

    while not msg is None:
        if verbose:
            print "[i] The response:"
            print hexdump (str (msg[0]))
        finalMsg += msg[0]
        msg = read (s, False)

    s.send (buildRequest (src, dst, COMMAND_REQUEST_RESPONSE + '\x03'))
    finalMsg = finalMsg.replace ('\x0b','\n')   # next column
    splitMsg = finalMsg.split ("7021 SURVEY:")
    configCurr = splitMsg[0][26:]

    if debug:
        print "[i] Current settings:"
        print configCurr

    config = parseCurrentConfig (configCurr)

    num = 0
    netList = ()

    if not (options.key or options.noauth or options.wep or options.wpa or options.wpa2
            or options.channel or options.ssid):
        print "[i] Networks:"

        if len (splitMsg) > 1 and splitMsg[1]:
            try:
                bandIndex = splitMsg[1].index ("7022 BAND:")
            except:
                if verbose:
                    print "[i] BAND indication NOT found:"

            if bandIndex > 0:
                networkStr = splitMsg[1][0:bandIndex].strip ()
            else:
                networkStr = splitMsg[1].strip ()

            netList = parseNetworkStr (networkStr)
            printNetworks (netList)

        while num < 1 or num > len (netList) + 1:
            try:
                num = int (raw_input ("[i] Please choose one of the options above: "))
            except KeyboardInterrupt:
                print "\n"
                exit (1)
            except:
                num = 0
    else:
        num = 1

    # initialization, default options
    essid = ""
    channel = 0
    secmode = SECURITY_OPTIONS.index ("WPA2-PSK")
    keylen = 32
    key0 = ""
    key1 = ""
    key2 = ""
    key3 = ""
    authen = 0 # first one
    psk = ""
    band = 0 # auto

    if num - 1 < len (netList):
        try:
            (macAddress, netDetails) = netList.items ()[num-1]
        except:
            print "[-] Could not read network details for configuration number %d" % num
            exit (1)
        try:
            essid = netDetails["name"]

            if not essid or len (essid) < 2:
                essid = raw_input ("[i] Please insert the hidden SSID: ")
        except:
            essid = ""
        try:
            tmpChannel = int (netDetails["channel"])

            if tmpChannel > 0 and tmpChannel < 12:
                channel = tmpChannel
        except:
            channel = 0

        secmode = int (netDetails["security"])
    else:
        if not options.ssid is None and len (options.ssid) > 0:
            essid = options.ssid
        else:
            while len (essid) < 1 or len (essid) > 32:
                essid = raw_input ("[i] Please insert the SSID: ")

        if not options.channel is None:
            channel = options.channel
        else:
            channel =- 1
            while channel < 0 or channel > 11:
                try:
                    channel = int (raw_input ("[i] Please choose the channel number from 0 (auto)" + \
                    " to 11: "))
                except KeyboardInterrupt:
                    print "\n"
                    exit (1)
                except:
                    channel = -1

        if options.noauth or options.wep or options.wpa or options.wpa2:
            if options.noauth:
                secmode = SECURITY_OPTIONS.index ("Disable")
            elif options.wep:
                secmode = SECURITY_OPTIONS.index ("WEP")
            elif options.wpa:
                secmode = SECURITY_OPTIONS.index ("WPA-PSK")
            elif options.wpa2:
                secmode = SECURITY_OPTIONS.index ("WPA2-PSK")
        else:
            secmode = getSecmodeSelection ()

    if not secmode == SECURITY_OPTIONS.index ("Disable"):  # do nothing for disabled
        if secmode == SECURITY_OPTIONS.index ("WEP"):
            passphrase = ""

            if not options.key is None and len (options.key) > 0:
                passphrase = options.key

                if options.strong:
                    num = 2
                else:
                    num = 1
            else:
                count = 1

                # print all WEP options:
                print "[i] WEP key input method:"

                for i in WEP_OPTIONS:
                    print str (count) + ") " + i
                    count += 1

                num = 0

                while num < 1 or num > len (WEP_OPTIONS):
                    try:
                        num = int (raw_input ("[i] Please choose one of the options above: "))
                    except KeyboardInterrupt:
                        print "\n"
                        exit (1)
                    except:
                        num = 0

            if num == 1 or num == 2: # WEP using passphrases
                (key0, key1, key2, key3) = passphrase2WepKeys (num == 2, passphrase)
            else:
                (key0, key1, key2, key3) = inputWepKeys (num == 4)

                if num == 3:
                    authen =- 1

                    while authen < 0 or channel > 11:
                        try:
                            authen = int (raw_input ("[i] Please choose the key index to be used 1-4:"))
                        except KeyboardInterrupt:
                            print "\n"
                            exit (1)
                        except:
                            authen =- 1
                    authen -= 1   # this is the index VAP11g uses 0-3, NOT 1-4

            # set the keylen variable
            if num == 2 or num == 4: # 128 bits
                keylen = 13
            else:   # 64 bits
                keylen = 5
        else:
            if options.key:
                psk = options.key

            length = len (psk)

            while length < 8 or length > 64:
                psk = getpass.getpass ("[i] Please insert the passphrase (min 8 chars,will NOT be " + \
                        "displayed): ")
                length = len (psk)

    if psk and not secmode == SECURITY_OPTIONS.index ('WPA-PSK'):
       pskset = 1
    else:
       pskset = 0

    payload ="7000 :" + essid + "\n7001 :16\n7002 :" + str (channel) + "\n7003 :" + \
        str (secmode) +"\n7004 :" + str (keylen) + "\n7005 :0\n7006 :" + key0 + "\n7007 :" + \
        key1 + "\n7008 :" + key2 + "\n7009 :" + key3 + "\n7012 :" + str (authen) + "\n7013 :0" + \
        "\n7018 :" + str (pskset) + "\n7019 :" + psk + "\n7022 :0\n"

    # send changes:
    # 7000: SSID                7001: domain,
    # 7002: channel (0==auto)   7003: secmode (WPA TYPE? 0,1,2,3),
    # 7004: keylen(e.g.5 or 13) 7005: defaultkey,
    # 7006: key0, (wep)         7007: key1, (wep)
    # 7008: key2, (wep)         7009: key3, (wep)
    # 7012: authen (WEP TYPE?), 7013: mode (0),
    # 7014: linkinfo (NO SET),  7017: wpamode (WPA) NO DIRECT SET,
    # 7018: pskalset,           7019: pskkey,
    # 7020: pskal (TKIT,AES),   7021: survey (NO SET),
    # 7022: band (0==auto)

    s.send (buildRequest (src, dst, COMMAND_CONFIG + '\x01', payload))
    s.send (buildRequest (src, dst, COMMAND_REQUEST_RESPONSE + '\x02'))

    # get OKAY status
    s.send (buildRequest (src, dst, COMMAND_DEVICE_STATUS))
    success = read (s);

    if verbose:
        print "[i] The response:"
        print hexdump (str (success[0]))

    if success[0][22] == '\x02':
        print "[+] Device did accept the configuration and will reboot now"
        print "[i] The device's led will become blue when the ssid was found, this does NOT\n" + \
                "    imply that the connection was indeed successful. You should test that with" + \
                ":\n    sudo dhclient3 %s\n    ping www.google.com # example\n" % interface + \
                "    while disabling all other interfaces (e.g. wlan0)"
        print "[i] Please re-execute the script to see the (new) wireless configuration"
    else:
        print "[-] It seems that the device did not accept your configuration:\n" + \
                "status code was: %02x, will reboot anyway" % ord (success[0][22])

    s.send (buildRequest (src, dst, COMMAND_CONFIG + '\x01', str (DATA_REQUEST_RESET) + DATA_END))
    s.send (buildRequest (src, dst, COMMAND_REQUEST_RESPONSE + '\x02'))

if __name__ == "__main__":
    try:
        main ()
    except KeyboardInterrupt:
        print "\n"
        exit (1)
