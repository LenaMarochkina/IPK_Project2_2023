#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <pcap.h>
#include <time.h>

#define MAX 101
char err_buf[PCAP_ERRBUF_SIZE];

// This function prints the names of all available network interfaces
void print_interfaces() {
    pcap_if_t *interfaces;
    // pcap_findalldevs returns a linked list of available interfaces
    if (pcap_findalldevs(&interfaces, err_buf) == 0) {
        // loop through all interfaces and print their names
        for (pcap_if_t *interface = interfaces; interface != NULL; interface = interface->next) {
            printf("%s\n", interface->name);
        }
        // free the memory allocated by pcap_findalldevs
        pcap_freealldevs(interfaces);
    } else {
        // if pcap_findalldevs fails, print an error message
        fprintf(stderr, "Error in pcap_findall_devs(): %s\n", err_buf);
    }
};

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

    printf("%s.%03ld%s\n", buffer, time_in_sec % 1000, timezone_offset);
}

void print_ip_and_port(char* src_ip, char* dst_ip, u_char *packet) {
    // Convert the source IP address from binary to string format
    char src_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_ip, src_ip_str, INET_ADDRSTRLEN);

    // Convert the destination IP address from binary to string format
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dst_ip, dst_ip_str, INET_ADDRSTRLEN);

    // Print out the source IP address and port number
    printf("src IP: %s\n", src_ip_str);
    printf("dst IP: %s\n", dst_ip_str);

    // Print out the destination IP address and port number
    uint16_t src_port = ntohs(*(uint16_t*)(packet + 34));
    uint16_t dst_port = ntohs(*(uint16_t*)(packet + 36));

    printf("src port: %d\n", src_port);
    printf("dst port: %d\n", dst_port);
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

    print_ip_and_port((char*) packet + 26, (char*) packet + 30, (u_char*) packet);

}

int main(int argc, char *argv[]) {
    // initialize variables with default values
    char interface[MAX] = "";
    int port = -1;
    bool tcp_flag = 0;
    bool udp_flag = 0;
    bool icmp4_flag = 0;
    bool icmp6_flag = 0;
    bool arp_flag = 0;
    bool ndp_flag = 0;
    bool igmp_flag = 0;
    bool mld_flag = 0;
    int count = -1;

    pcap_t *handle;

    // define the program's command line options and their corresponding parameters
    static struct option long_options[] =
            {
                    {"interface", optional_argument, 0, 'i'},
                    {"tcp",       no_argument,       0, 't'},
                    {"udp",       no_argument,       0, 'u'},
                    {"arp",       no_argument,       0, 1},
                    {"icmp4",     no_argument,       0, 2},
                    {"icmp6",     no_argument,       0, 3},
                    {"ndp",       no_argument,       0, 4},
                    {"igmp",      no_argument,       0, 5},
                    {"mld",       no_argument,       0, 6},
                    {0,           0,                 0, 0}
            };

    int option_index = 0;
    int option;

    // loop through all the command line options and their parameters using getopt_long
    while ((option = getopt_long(argc, argv, "i::p:tun:", long_options, &option_index)) != -1) {
        switch (option) {
            case 0:
                break;
            case 'i':
                // Check if interface name is provided
                if (argv[optind] == NULL)
                    break;
                strncpy(interface, argv[optind], MAX - 1);
                break;
            case 'p':
                // Check if port value is a number
                for (size_t i = 0; i < optarg[i] != '\0'; i++)
                    if (!isdigit(optarg[i])) {
                        fprintf(stderr, "Error: port value is not digit\n");
                        exit(1);
                    }
                // convert the port value to an integer
                port = atoi(optarg);
                break;
            case 't':
                tcp_flag = 1;
                break;
            case 'u':
                udp_flag = 1;
                break;
            case 'n':
                // Check if count value is a number
                for (size_t i = 0; i < optarg[i] != '\0'; i++) {
                    if (!isdigit(optarg[i])) {
                        fprintf(stderr, "Error: number of packets is not digit\n");
                        exit(1);
                    }
                }
                // Convert the count value to an integer
                count = atoi(optarg);
                break;
            case 1:
                arp_flag = 1;
                break;
            case 2:
                icmp4_flag = 1;
                break;
            case 3:
                icmp6_flag = 1;
                break;
            case 4:
                ndp_flag = 1;
                break;
            case 5:
                igmp_flag = 1;
                break;
            case 6:
                mld_flag = 1;
                break;
            case '?':
                // Print an error message for unknown arguments and exit the program
                fprintf(stderr, "Unknown argument %s\n", argv[optind - 1]);
                exit(1);
            default:
                // Print the correct usage for the program and exit
                fprintf(stderr,
                        "Usage: %s [-i interface | --interface interface] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n",
                        argv[0]);
                exit(1);
        }
    }

    // Set flags for all protocols if no specific protocol flags are set
    if (!tcp_flag && !udp_flag && !icmp4_flag && !icmp6_flag && !arp_flag && !ndp_flag && !igmp_flag && !mld_flag) {
        tcp_flag = icmp4_flag = icmp6_flag = arp_flag = ndp_flag = igmp_flag = mld_flag = 1;
    }

    // If no interface is provided, print a list of available interfaces and exit
    if (strcmp(interface, "") == 0) {
        print_interfaces();
        exit(0);
    }

    // If the number of packets to capture is not provided, set it to 1
    if (count == -1) {
        count = 1;
    }

    // Check if the interface is valid
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, err_buf);
    if (handle == NULL) {
        fprintf(stderr, "Error: %s\n", err_buf);
        exit(2);
    }

    // Check if the interface provides Ethernet headers
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", interface);
        return (2);
    }

    pcap_loop(handle, count, packet_handler, NULL);
    pcap_close(handle);

    return 0;
}