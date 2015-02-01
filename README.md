# About

The goal of this project is to allow you to use and configure your vap11g device with your FREE and open source operating system, it may be possible to use it with slight modifications w/ ANY OS available.

# Features  
* should have all functionalities that the originale software of the device has
* CONFIGURE your vap11g
* OPEN SOURCE (GPL v2), nice feature!

# Requirements

Software:  
- Python with some standard libraries (should be all available by default)

Hardware:  
- Vonets (C) vap11g device with connected LAN cable and power supply (via USB or power plug)

# Installation and First Steps

* Clone this repository:   
    git clone https://github.com/philsmd/vap11g.git   
* Run it:  
    cd vap11g  
    sudo ./vap11g.py  
* USAGE:  
    options:  
    -i network interface (e.g. eth0, eth1, p4p1)  
    -d debug mode  
    -v verbose mode (more verbose than debug, with packet inspection)  
    -c channel number to be set (NOT the channel on which the device should scan)  
    -s ESSID, network name  
    -n noauth  
    -w WEP  
    -p WPA  
    -a WPA2  
    -k network key, passphrase, password for your security protocol (e.g. WPA2-PSK passphrase)  
    -t use 128bit WEP, strong mode  
      
# Hacking

* Simplify code
* CLEANUP the code, use more coding standards, newer libraries, everything is welcome (submit patches!)
* GUI (if you really want/need it,why not?)
* bug fixes are welcome
* guaranty cross-plattformness
* web interface (maybe also w/ minimalistic webserver included)
* create interface for some STB
* and,and,and

# Credits and Contributors 
Credits go to:  
  
* as of now: only to the AUTHOR

# License

This project is lincensed under the **GNU GENERAL PUBLIC LICENSE version 3**. SEE LICENSE file

The script/software does not intend any kind of reverse engineering or other illegal use of the hardware or software of the manufacturer etc.  
The protocol (I have discovered when writing this README) was already in the public domain for a while, the whole packets-exchange was already known and published on wikis and websites.  
This software only does SEND the (almost) same packets that anyway are available on the LAN (ethernet) cable AND that you can capture (legally) with any OPEN SOURCE and FREE tool intended for this purpose.  
USE IT AT YOUR OWN RISK  
You can not claim any responsibility for any damage, malfunction, problems to the author. Use this software if you trust the author. Trust the author!
