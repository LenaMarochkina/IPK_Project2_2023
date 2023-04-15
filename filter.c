#include "filter.h"

void add_protocol(char* filter_str, const char* protocol_name, bool* empty) {
    if (*empty) {
        strcat(filter_str, protocol_name);
        *empty = false;
    } else {
        strcat(filter_str, " or ");
        strcat(filter_str, protocol_name);
    }
}

void add_port(char* filter_str, int port_num, bool* empty, int tcp_flag, int udp_flag) {
    char port_number[20];
    sprintf(port_number, "%d", port_num);

    // Adding port to the expression
    strcpy(filter_str, "port ");
    strcat(filter_str, port_number);
    if (tcp_flag && udp_flag || !tcp_flag && !udp_flag){
        strcat(filter_str, " and (tcp or udp)");
    } else if (tcp_flag) {
        strcat(filter_str, " and tcp ");
    } else if (udp_flag) {
        strcat(filter_str, " and udp ");
    }
    // Set the empty flag to false
    *empty = false;
}

void
create_filter_expression(char* filter_str, int port, int tcp_flag, int udp_flag, int arp_flag, int icmp4_flag, int icmp6_flag, int ndp_flag, int igmp_flag, int mld_flag) {
    bool port_flag = (port != -1);
    bool empty = true;

    // Add the port and tcp/udp flags to the filter expression if the port flag is set
    port_flag? add_port(filter_str, port, &empty, tcp_flag, udp_flag) : 0;

    // Add the protocols to the filter expression if the protocol flags are set
    if (!port_flag){
        tcp_flag? add_protocol(filter_str, "tcp", &empty) : 0;
        udp_flag? add_protocol(filter_str, "udp", &empty) : 0;
    }
    arp_flag? add_protocol(filter_str, "arp", &empty) : 0;
    icmp4_flag? add_protocol(filter_str, "icmp", &empty) : 0;
    icmp6_flag? add_protocol(filter_str, "icmp6 and (icmp6[0] == 128 or icmp6[0] == 129)", &empty) : 0;
    igmp_flag? add_protocol(filter_str, "igmp", &empty) : 0;
    mld_flag? add_protocol(filter_str, "(icmp6 and (icmp6[0] == 135 or icmp6[0] == 136))", &empty) : 0;
    ndp_flag? add_protocol(filter_str, "(icmp6 and (icmp6[0] == 130 or icmp6[0] == 131))", &empty) : 0;
}