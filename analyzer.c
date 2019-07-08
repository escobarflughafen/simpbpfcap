#include "analyzer.h"

int is_h_broadcast(const char* daddr) {
    if(!strcmp(haddr_s(daddr), "ff:ff:ff:ff:ff:ff"))
        return 1;
    return 0;
}

//in x86 devices, numbers are stored with little-endian style
void int32_char4(unsigned char* dst, int src) {
    for (int i = 0; i < 4; i++) {
        *(dst + i) = (src >> 8 * i) & 0xFF;
    }
}

int int16_endian_swap(int16_t num){
    int16_t a0, a1;
    a0 = (num & 0x00ff) << 8u;
    a1 = (num & 0xff00) >> 8u;
    return (a0 | a1);
}

int int32_endian_swap(int32_t num){
    int32_t a0, a1, a2, a3;
    a0 = (num & 0x000000ff) << 24u;
    a1 = (num & 0x0000ff00) << 8u;
    a2 = (num & 0x00ff0000) >> 8u;
    a3 = (num & 0xff000000) >> 24u;
    return (a0 | a1 | a2 | a3);
}


void parse_eth_frame(struct ether_header *e_hdr, struct brief_t* brief){
    memcpy(brief->src_haddr, e_hdr->ether_shost, 6);
    memcpy(brief->dst_haddr, e_hdr->ether_dhost, 6);
}

void parse_arp_packet(struct ether_arp *e_arp, struct brief_t* brief) {
    strcpy(brief->protocol, "ARP");
    memcpy(brief->src_ip, e_arp->arp_spa, 4);
    memcpy(brief->dst_ip, e_arp->arp_tpa, 4);
    brief->src_port = -1;
    brief->dst_port = -1;
    if (is_h_broadcast(brief->dst_haddr)) {
        sprintf(brief->info,
                "[ARP]:\t<request> - %s (%s) is looking for %s",
                ipaddr_s(e_arp->arp_spa),
                haddr_s(e_arp->arp_sha),
                ipaddr_s(e_arp->arp_tpa));
    } else {
        sprintf(brief->info,
                "[ARP]:\t<reply> - (To %s) %s is located at %s",
                ipaddr_s(e_arp->arp_tpa),
                ipaddr_s(e_arp->arp_spa),
                haddr_s(e_arp->arp_sha));
    }
    sprintf(brief->verbose_info,
            "%s\n%s",
            brief->verbose_info,
            brief->info);
}

void parse_ip_header(struct ip*ipv4_hdr, struct brief_t* brief) {
    int32_char4(brief->src_ip, ipv4_hdr->ip_src.s_addr);
    int32_char4(brief->dst_ip, ipv4_hdr->ip_dst.s_addr);
    brief->ttl = ipv4_hdr->ip_ttl;
    char fragment_mark[32] = {0};
    if (ipv4_hdr->ip_off & IP_DF) strcat(fragment_mark, "<DF>, ");
    if (ipv4_hdr->ip_off & IP_MF) {
        sprintf(fragment_mark, "<MF> - offset=%u, ", (uint16_t) int16_endian_swap(ipv4_hdr->ip_off & IP_OFFMASK));
    }
    sprintf(brief->verbose_info,
            "%s\n[IPv4]:\ttos=%u, id=%u, %schksum=%u",
            brief->verbose_info,
            ipv4_hdr->ip_tos,
            (uint16_t) int16_endian_swap(ipv4_hdr->ip_id),
            fragment_mark,
            (uint16_t) int16_endian_swap(ipv4_hdr->ip_sum));
}

void parse_icmp_packet(struct icmp *icmp_hdr, struct brief_t* brief) {
    char *type[] = {
            "echo reply",
            "undefined",
            "undefined",
            "destination unreachable",
            "source quench",
            "redirect",
            "undefined",
            "undefined",
            "echo request",
            "router advertisement",
            "rounter selection",
            "time exceeded for datagram",
            "parameter problem on datagram",
            "timestamp request",
            "timestamp reply",
            "information request",
            "information reply",
            "address mask request",
            "address mask reply"
    };

    strcpy(brief->protocol, "ICMP");
    brief->src_port = -1;
    brief->dst_port = -1;

    switch (icmp_hdr->icmp_type) {
        default:
            strcpy(brief->info, "[ICMP]: cannot resolve this ICMP packet.");
            break;
        case 0:
            sprintf(brief->info,
                    "[ICMP]:\t<%s>\t - id=%u, seq=%u",
                    type[icmp_hdr->icmp_type],
                    (uint16_t) int16_endian_swap(icmp_hdr->icmp_hun.ih_idseq.icd_id),
                    (uint16_t) int16_endian_swap(icmp_hdr->icmp_hun.ih_idseq.icd_seq));
            break;
        case 3:
            if (icmp_hdr->icmp_code == 4) {
                sprintf(brief->info,
                        "[ICMP]:\t<%s>\t - icmp_pmvoid=%u, icmp_nextmtu=%u",
                        type[icmp_hdr->icmp_type],
                        (uint16_t) int16_endian_swap(icmp_hdr->icmp_hun.ih_pmtu.ipm_void),
                        (uint16_t) int16_endian_swap(icmp_hdr->icmp_hun.ih_pmtu.ipm_nextmtu));

            } else {
                sprintf(brief->info,
                        "[ICMP]:\t<%s>\t - icmp_void=%u",
                        type[icmp_hdr->icmp_type],
                        (uint32_t) int32_endian_swap(icmp_hdr->icmp_hun.ih_void));
            }
            break;
        case 5:
            sprintf(brief->info,
                    "[ICMP]:\t<%s>\t - icmp_gwaddr=%s",
                    type[icmp_hdr->icmp_type],
                    ipaddr_s(icmp_hdr->icmp_hun.ih_gwaddr.s_addr));
            break;
        case 8:
            sprintf(brief->info,
                    "[ICMP]:\t<%s>\t - id=%u, seq=%u",
                    type[icmp_hdr->icmp_type],
                    (uint16_t) int16_endian_swap(icmp_hdr->icmp_hun.ih_idseq.icd_id),
                    (uint16_t) int16_endian_swap(icmp_hdr->icmp_hun.ih_idseq.icd_seq));
            break;
        case 11:
            sprintf(brief->info,
                    "[ICMP]:\t<%s>\t - icmp_void=%u",
                    type[icmp_hdr->icmp_type],
                    (uint32_t) int32_endian_swap(icmp_hdr->icmp_hun.ih_void));
            break;
    }

    sprintf(brief->verbose_info,
            "%s",
            brief->info);
}

void parse_tcp_packet(struct tcphdr* tcp_hdr, struct brief_t* brief) {
    char flags[64] = {0};
    brief->src_port = int16_endian_swap(tcp_hdr->th_sport);
    brief->dst_port = int16_endian_swap(tcp_hdr->th_dport);
    strcpy(brief->protocol, "TCP");
    if (tcp_hdr->th_flags & TH_FIN) strcat(flags, "FIN, ");
    if (tcp_hdr->th_flags & TH_SYN) strcat(flags, "SYN, ");
    if (tcp_hdr->th_flags & TH_RST) strcat(flags, "RST, ");
    if (tcp_hdr->th_flags & TH_PUSH) strcat(flags, "PSH, ");
    if (tcp_hdr->th_flags & TH_ACK) strcat(flags, "ACK, ");
    if (tcp_hdr->th_flags & TH_URG) strcat(flags, "URG, ");
    sprintf(brief->info,
            "[TCP]:\t%u -> %u, [%s], seq=%u, ack=%u, win=%u, offset=%u",
            brief->src_port,
            brief->dst_port,
            flags,
            (uint32_t) int32_endian_swap(tcp_hdr->th_seq),
            (uint32_t) int32_endian_swap(tcp_hdr->th_ack),
            (uint16_t) int16_endian_swap(tcp_hdr->th_win),
            (uint16_t) int16_endian_swap(tcp_hdr->th_off));

    sprintf(brief->verbose_info,
            "%s\n%s, chksum=%u",
            brief->verbose_info,
            brief->info,
            (uint16_t) int16_endian_swap(tcp_hdr->th_sum));
    //urgent pointer
    if (tcp_hdr->th_flags & TH_URG)
        sprintf(brief->verbose_info,
                "%s, urp=%u",
                (uint16_t) int16_endian_swap(tcp_hdr->th_urp));
}

void parse_udp_packet(struct udphdr* udp_hdr, struct brief_t* brief) {
    brief->src_port = int16_endian_swap(udp_hdr->uh_sport);
    brief->dst_port = int16_endian_swap(udp_hdr->uh_dport);
    strcpy(brief->protocol, "UDP");
    sprintf(brief->info,
            "[UDP]:\t%u -> %u, length: %u",
            brief->src_port,
            brief->dst_port,
            (uint16_t) int16_endian_swap(udp_hdr->uh_ulen));

    sprintf(brief->verbose_info,
            "%s\n%s, chksum=%u",
            brief->verbose_info,
            brief->info,
            (uint16_t) int16_endian_swap(udp_hdr->uh_sum));
}

struct brief_t create_brief(char* packet, size_t len, int counter) { struct brief_t brief;
    struct ether_header e_hdr;
    struct ether_arp e_arp;
    struct ip ipv4_hdr;
    struct tcphdr tcp_hdr;
    struct udphdr udp_hdr;
    struct icmp icmp_hdr;
    char *ptr = packet + BPF_HEADER_LENGTH;

    memset(&brief, 0, sizeof(struct brief_t));
    brief.serial_no = counter;
    brief.protocol = (char *) malloc(16 * sizeof(char));
    brief.info = (char *) malloc(512 * sizeof(char));
    brief.verbose_info = (char *) malloc(1024 * sizeof(char));
    memset(brief.verbose_info, 0, 1024);
    brief.ttl = MAXTTL;
    time(&brief.timestamp);
    memcpy(&e_hdr, ptr, sizeof(struct ether_header));
    parse_eth_frame(&e_hdr, &brief);
    ptr += sizeof(struct ether_header);
    len -= sizeof(struct ether_header);
    if (ntohs(e_hdr.ether_type) == ETHERTYPE_ARP || ntohs(e_hdr.ether_type) == ETHERTYPE_REVARP) {
        memcpy(&e_arp, ptr, sizeof(struct ether_arp));
        brief.len = len;
        parse_arp_packet(&e_arp, &brief);
    } else if (ntohs(e_hdr.ether_type) == ETHERTYPE_IP) {
        memcpy(&ipv4_hdr, ptr, sizeof(struct ip));
        parse_ip_header(&ipv4_hdr, &brief);
        ptr += sizeof(struct ip);
        len -= sizeof(struct ip);
        if (ipv4_hdr.ip_p == IPPROTO_TCP) {
            memcpy(&tcp_hdr, ptr, sizeof(struct tcphdr));
            ptr += sizeof(struct tcphdr);
            len -= sizeof(struct tcphdr);
            brief.len = len;
            parse_tcp_packet(&tcp_hdr, &brief);
        } else if (ipv4_hdr.ip_p == IPPROTO_UDP) {
            memcpy(&udp_hdr, ptr, sizeof(struct udphdr));
            ptr += sizeof(struct udphdr);
            len -= sizeof(struct udphdr);
            brief.len = len;
            parse_udp_packet(&udp_hdr, &brief);
        } else if (ipv4_hdr.ip_p == IPPROTO_ICMP) {
            memcpy(&icmp_hdr, ptr, sizeof(struct icmp));
            brief.len = len;
            ptr += sizeof(struct icmp);
            len -= sizeof(struct icmp);
            parse_icmp_packet(&icmp_hdr, &brief);
        }
    } else {
        printf("unresolvable packet.\n");
    }
    return brief;
}
