#ifndef IPK_PROJECT2_2023_SNIFFER_H
#define IPK_PROJECT2_2023_SNIFFER_H

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <pcap.h>
#include <time.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip6.h>

// Structure of an internet header, naked of options
struct ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; // Destination host address
    u_char ether_shost[ETHER_ADDR_LEN]; // Source host address
    u_short ether_type;
};

// This function takes in a timeval struct and a format string and prints out the time in the specified format
void timeval_to_string(struct timeval time, const char *format);

// This function takes in a pointer to an array of bytes (u_char) and prints out the source and destination IP addresses
void print_ip(u_char *packet);

// This function takes in a pointer to an array of bytes (uint8_t), as well as the size of the array
void print_package_data(uint8_t *data, size_t size);

// This function is called by pcap_loop for every packet that is captured
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif //IPK_PROJECT2_2023_SNIFFER_H
