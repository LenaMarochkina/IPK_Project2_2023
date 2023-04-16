# IPK Project 2 ZETA: Network sniffer
**Title**: IPK ZETA: Network sniffer\
**Author**: Elena Marochkina\
**Language**: en-US\
**Supported OS**: Linux\
**Gitea**: [xmaroc00_sniffer](https://git.fit.vutbr.cz/xmaroc00/IPK_Project2_2023)

# Table of Contents
1. [Description](#description)
    1. [Compilation](#compilation)
    2. [Usage](#usage)
    3. [Program Details](#program-details)
2. Testing
3. [License](#license)
4. [Bibliography](#bibliography)

## Description

This is a C program that uses the pcap library to capture and analyze network traffic (**a packet sniffer**). 

The program can:
- print the names of available network interfaces
- capture packets based on various criteria, such as protocol type and port number
- print information about captured packets, such as their source and destination 
IP and mac addresses, port numbers, length, time in RFC 3339 format and package contents. 

## Compilation
### Linux
Before using the **sniffer**, you need to compile the **make.c, sniffer.c, filter.c** files.

To compile the program, you can run **make build**, and to remove the ipk-sniffer executable
file, you can run **make clean**.

### Windows
The program can't be compiled for Windows.

## Usage
The client application requires  arguments to run:
- **-i eth0** (just one interface to sniff) or **--interface**. If this parameter is not specified (and any other parameters as well), or if only -i/--interface is specified without a value (and any other parameters are unspecified), a list of active interfaces is printed .
- **-t** or **--tcp** (displays TCP segments and is optionally complemented by -p functionality).
- **-u** or **--udp** (displays UDP datagrams and is optionally complemented by-p functionality).
- **-p 23** (extends previous two parameters to filter TCP/UDP based on port number; if this parameter is not present, then no filtering by port number occurs; if the parameter is given, the given port can occur in both the source and destination part of TCP/UDP headers).
- **--icmp4** (displays only ICMPv4 packets).
- **--icmp6** (displays only ICMPv6 echo request/response).
- **--arp** (display only ARP frames).
- **--ndp** (displays only ICMPv6 NDP packets).
- **--igmp** (displays only IGMP packets).
- **--mld** (displays only MLD packets).
Unless protocols are explicitly specified, all (i.e., all content, regardless of protocol) are considered for printing.
- **-n 10** (specifies the number of packets to display, i.e., the "time" the program runs; if not specified, consider displaying only one packet, i.e., as if -n 1)
All arguments can be in any order.

      Usage: ./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}

## Program Details
### Included libraries
The code uses the following libraries:

- **stdio.h**: Provides basic input/output operations such as printf and scanf.
- **string.h**: Provides functions for manipulating strings such as strcpy and strcat.
- **getopt.h**: Provides functions for parsing command-line arguments.
- **stdbool.h**: Defines the Boolean data type and its possible values.
- **stdlib.h**: Provides functions for memory allocation and manipulation such as malloc and free.
- **ctype.h**: Provides functions for character handling such as isdigit.
- **pcap.h**: Provides functions for capturing and processing network packets.
- **time.h**: Provides functions for working with date and time.
- **net/ethernet.h**: Defines Ethernet packet structures.
- **arpa/inet.h**: Provides functions for working with Internet addresses.
- **sys/socket.h**: Provides functions for working with sockets.

## Testing



## Bibliography
