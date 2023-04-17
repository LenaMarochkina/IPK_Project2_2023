#include "sniffer.h"

void timeval_to_string(struct timeval time, const char *format) {
    time_t time_in_sec = time.tv_sec;
    char buffer[64];
    struct tm* timeInfo;
    time_t unix_time = (time_t) time_in_sec;
    timeInfo = localtime(&unix_time);
    strftime(buffer, 64, "%Y-%m-%dT%H:%M:%S", timeInfo);

    // Get the local time zone
    char timezone_buffer[6];
    strftime(timezone_buffer, 6, "%z", timeInfo);

    // Convert the timezone offset to ISO 8601 format
    char timezone_offset[7];
    timezone_offset[0] = timezone_buffer[0];
    timezone_offset[1] = timezone_buffer[1];
    timezone_offset[2] = timezone_buffer[2];
    timezone_offset[3] = ':';
    timezone_offset[4] = timezone_buffer[3];
    timezone_offset[5] = timezone_buffer[4];
    timezone_offset[6] = '\0';

    printf("%s.%03ld%s\n", buffer, time.tv_usec / 1000, timezone_offset);
}

void print_ip_and_ports(u_char *packet) {
    // Print out the source IP address for v4 and v6
    const struct ethernet *ethernet = (struct ethernet*)(packet);

// Check if the Ethernet type is IPv4
    if (ntohs(ethernet->ether_type) == ETHERTYPE_IP) {
        // Define char arrays to store the source and destination IP addresses
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        // Extract the source IP address from the packet using inet_ntop and store it in src_ip
        inet_ntop(AF_INET, packet + 26, src_ip, INET_ADDRSTRLEN);
        // Extract the destination IP address from the packet using inet_ntop and store it in dst_ip
        inet_ntop(AF_INET, packet + 30, dst_ip, INET_ADDRSTRLEN);
        // Print out the source and destination IP addresses
        printf("src IP: %s\n", src_ip);
        printf("dst IP: %s\n", dst_ip);

        // Print out the source and destination ports for TCP and UDP
        // Check if the protocol is TCP
        if (packet[23] == 6 || packet[23] == 17) {
            // Extract the source port from the packet
            uint16_t src_port = (packet[34] << 8) | packet[35];
            // Extract the destination port from the packet
            uint16_t dst_port = (packet[36] << 8) | packet[37];
            // Print out the source and destination ports
            printf("src port: %d\n", src_port);
            printf("dst port: %d\n", dst_port);
        }
    }
// Check if the Ethernet type is IPv6
    else if (ntohs(ethernet->ether_type) == ETHERTYPE_IPV6) {
        // Define a pointer to an IPv6 header and set it to the start of the IPv6 packet
        struct ip6_hdr *ip6 = (struct ip6_hdr*)(packet + sizeof (struct ethernet));
        // Define char arrays to store the source and destination IPv6 addresses
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        // Extract the source IPv6 address from the packet using inet_ntop and store it in src_ip
        inet_ntop(AF_INET6, &ip6->ip6_src, src_ip, INET6_ADDRSTRLEN);
        // Extract the destination IPv6 address from the packet using inet_ntop and store it in dst_ip
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst_ip, INET6_ADDRSTRLEN);
        // Print out the source and destination IPv6 addresses
        printf("src IP: %s\n", src_ip);
        printf("dst IP: %s\n", dst_ip);

        // Print out the source and destination ports for TCP and UDP
        // Check if the protocol is TCP
        if (packet[20] == 6 || packet[20] == 17) {
            // Extract the source port from the packet
            uint16_t src_port = (packet[54] << 8) | packet[55];
            // Extract the destination port from the packet
            uint16_t dst_port = (packet[56] << 8) | packet[57];
            // Print out the source and destination ports
            printf("src port: %d\n", src_port);
            printf("dst port: %d\n", dst_port);
        }
    }
    else if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP) {
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, packet + 28, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, packet + 38, dst_ip, INET_ADDRSTRLEN);
        printf("src IP: %s\n", src_ip);
        printf("dst IP: %s\n", dst_ip);
    }


}


void print_package_data(uint8_t *data, size_t size) {
    // Initialize two size_t variables, i and j
    size_t i, j;
    // Loop through the array in increments of 16 (i.e. print 16 bytes at a time)
    for (i = 0; i < size; i += 16) {
        // Print the current index in the array (in hexadecimal format)
        printf("0x%04x: ", (unsigned int)i);
        for (j = i; j < i + 16 && j < size; j++) {
            printf("%02x ", data[j]);
        }
        // If there are less than 16 bytes left to print, fill the remaining space with blank spaces (for formatting purposes).
        for (; j < i + 16; j++) {
            printf("   ");
        }
        // Print a space before printing the ASCII representation of the bytes.
        // Loop through the next 16 bytes, or until the end of the array (whichever comes first).
        for (j = i; j < i + 16 && j < size; j++) {
            if (data[j] >= 32 && data[j] <= 126) {
                printf("%c", data[j]);
            } else {
                printf(".");
            }
        }
        // Print a newline character at the end of each 16-byte row.
        printf("\n");
    }
    printf("\n\n");
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // print the timestamp of the packet
    printf("timestamp: ");
    timeval_to_string(header->ts, "%Y-%m-%d %H:%M:%S");

    // print mac addresses
    printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);

    // print the length of the packet
    printf("frame length: %d bytes\n", header->len);

    // print IP address and port

    print_ip_and_ports((u_char*) packet);

    // print the package data
    printf("\n");
    print_package_data((uint8_t*) packet, header->len);
}