#ifndef NETWORKSNIFFER_SNIFFER_H
#define NETWORKSNIFFER_SNIFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <string.h>
#include <sysexits.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <sys/uio.h>

#include <net/if.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/bpf.h>

#define DEVICE_PENDING  ""

struct sniffer_t{
    int fd;                             // file descriptor of designated bpf device
    char device[11];                    // BSD packet filter device
    unsigned int buf_len;               // max buffer length of packet contents
    char *buffer;
    unsigned int last_read_len;         //
    unsigned int read_bytes_consumed;
};

struct captureinfo_t{
    char *data;
    struct bpf_hdr *bpf_hdr;
};

int create_sniffer(struct sniffer_t *sniffer, char* device, char* interface, unsigned int buf_len);
int close_sniffer(struct sniffer_t *sniffer);
int read_packets(struct sniffer_t *sniffer);
int parse_packets(struct sniffer_t *sniffer, struct captureinfo_t *info);
#endif  //NETWORKSNIFFER_SNIFFER_H

