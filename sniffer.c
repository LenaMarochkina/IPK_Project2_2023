#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>

#define MAX 101

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
    int count = 0;

    // define the program's command line options and their corresponding parameters
    static struct option long_options[] =
            {
                    {"interface", optional_argument, 0, 'i'},
                    {"tcp", no_argument, 0, 't'},
                    {"udp", no_argument, 0, 'u'},
                    {"arp", no_argument, 0, 1},
                    {"icmp4", no_argument, 0, 2},
                    {"icmp6", no_argument, 0, 3},
                    {"ndp", no_argument, 0, 4},
                    {"igmp", no_argument, 0, 5},
                    {"mld", no_argument, 0, 6},
                    {0, 0, 0, 0}
            };

    int option_index = 0;
    int option;

    // loop through all the command line options and their parameters using getopt_long
    while((option = getopt_long (argc, argv, "i::p:tun:", long_options, &option_index)) != -1) {
        switch (option) {
            case 0:
                break;
            case 'i':
                // Check if interface name is provided
                if(argv[optind] == NULL)
                    break;
                strncpy(interface, argv[optind], MAX - 1);
                break;
            case 'p':
                // Check if port value is a number
                for(size_t i = 0; i < optarg[i] != '\0'; i++)
                    if(!isdigit(optarg[i])){
                        fprintf(stderr,"Error: port value is not digit\n");
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
                for(size_t i = 0; i < optarg[i] != '\0'; i++) {
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
                fprintf(stderr,"Unknown argument %s\n", argv[optind - 1]);
                exit(1);
            default:
                // Print the correct usage for the program and exit
                fprintf(stderr, "Usage: %s [-i interface | --interface interface] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n", argv[0]);
                exit(1);
        }
    }

    // Set flags for all protocols if no specific protocol flags are set
    if (!tcp_flag && !udp_flag && !icmp4_flag && !icmp6_flag && !arp_flag && !ndp_flag && !igmp_flag && !mld_flag) {
        tcp_flag = 1;
        icmp4_flag = 1;
        icmp6_flag = 1;
        arp_flag = 1;
        ndp_flag = 1;
        igmp_flag = 1;
        mld_flag = 1;
    }

    return 0;
}