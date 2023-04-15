#ifndef IPK_PROJECT2_2023_FILTER_H
#define IPK_PROJECT2_2023_FILTER_H

#include <string.h>
#include <stdbool.h>
#include <pcap.h>

// Helper function to add a protocol to the filter expression
void add_protocol(char* filter_str, const char* protocol_name, bool* empty);

// Helper function to add a port to the filter expression
void add_port(char* filter_str, int port_num, bool* empty, int tcp_flag, int udp_flag);

// This function creates a filter expression based on the given flags
void create_filter_expression(char* filter_str, int port, int tcp_flag, int udp_flag, int arp_flag, int icmp4_flag, int icmp6_flag, int ndp_flag, int igmp_flag, int mld_flag);

#endif //IPK_PROJECT2_2023_FILTER_H
