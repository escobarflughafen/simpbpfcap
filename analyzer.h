#ifndef NETWORKSNIFFER_ANALYZER_H
#define NETWORKSNIFFER_ANALYZER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>

#include <sys/errno.h>
#include <sys/types.h>

#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "display.h"

#define BPF_HEADER_LENGTH 18
#define ETH_HEADER_LENGTH 14
#define IP_HEADER_LENGTH 20


struct brief_t{
    uint32_t serial_no;
    time_t timestamp;
    uint8_t src_haddr[6];
    uint8_t dst_haddr[6];
    uint8_t ttl;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    uint16_t src_port;
    uint16_t dst_port;
    char* protocol;
    uint32_t len;
    char* info;
    char* verbose_info;
};


struct brief_t create_brief(char* packet, size_t len, int counter);
#endif //NETWORKSNIFFER_ANALYZER_H
