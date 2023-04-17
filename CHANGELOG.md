# IPK Project 2 ZETA: Network sniffer
**Title**: IPK ZETA: Network sniffer\
**Author**: Elena Marochkina\
**Language**: en-US\
**Supported OS**: Linux\
**Gitea**: [xmaroc00_sniffer](https://git.fit.vutbr.cz/xmaroc00/IPK_Project2_2023)

# Brief Description
The program is designed to capture and analyze network traffic that is transmitted over a network interface. 

The code contains the main function and several helper functions for initializing and setting up the program's various 
options, including interface selection, filtering by protocol, and setting a capture limit. 
The code uses the libpcap library to capture network packets and apply filters based on user-defined parameters. 

The program provides a command-line  interface with options for selecting a network interface, specifying the type 
of traffic to capture, setting a packet capture limit, and filtering by protocol. 

The program prints the captured packets to the standard output in a human-readable format.

# Known Limitations
The program appears to have a few limitations, some of which are:

1. The code does not have input validation or error handling for all possible user inputs. For example, if a user 
provides an invalid interface name or filter expression, the program will terminate abruptly without providing any 
feedback on the error.
2. The code only supports a limited number of protocol filters (TCP, UDP, ARP, ICMP4, ICMP6, NDP, IGMP, MLD) and port 
filtering. It does not support filtering based on other protocol headers or packet contents.
3. The program does not have any options for output formatting, such as saving the output to a file.
4. The program does not have any options for capturing packets from a remote machine or monitoring multiple interfaces
simultaneously.