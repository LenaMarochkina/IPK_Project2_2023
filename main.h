#ifndef IPK_PROJECT2_2023_MAIN_H
#define IPK_PROJECT2_2023_MAIN_H

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pcap.h>

char err_buf[PCAP_ERRBUF_SIZE];

// This function prints the names of all available network interfaces
void print_interfaces();

#endif //IPK_PROJECT2_2023_MAIN_H
