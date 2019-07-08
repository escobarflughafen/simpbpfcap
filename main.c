#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>

#include "display.h"
#include "sniffer.h"
#include "analyzer.h"


void INThandler(int);
static volatile sig_atomic_t cutoff = 0;

void run(int argc, char** argv) {
    //parsing arguments
    char args[] = "i::vn::r:s::";

    int verbose = 0, to_archive = 0;
    int max_num_of_packages = -1;
    char save_path[256] = "";
    int step = HEX_BASE_N * 2;
    char interface[16] = "";
    FILE *r_file;
    int opt;
    while ((opt = getopt(argc, argv, args)) != -1) {
        switch (opt) {
            case 'v':
                verbose = 1;
                break;
            case 'i':
                strcpy(interface, optarg);
                break;
            case 'n':
                max_num_of_packages = atoi(optarg);
                break;
            case 'r':
                if (strlen(optarg) <= 0)
                    strcpy(save_path, "capture.out");
                else
                    strcpy(save_path, optarg);
                to_archive = 1;
                break;
            case 's':
                step = atoi(optarg) * HEX_BASE_N;
            default:
                break;
        }
    }
    if (to_archive) {
        if ((r_file = fopen(save_path, "w")) == NULL) {
            perror("fopen() wb");
            return;
        }
    }
    signal(SIGINT, INThandler);

    struct sniffer_t sniffer;
    struct brief_t brief;
    time_t epoch_time, now_time;
    time(&epoch_time);

    if (create_sniffer(&sniffer, DEVICE_PENDING, interface, 0) != -1) {
        int counter = 0;
        int flag = 1;
        while (flag) {
            if (cutoff || (max_num_of_packages > 0 && counter >= max_num_of_packages)) break;
            read_packets(&sniffer);
            if (to_archive) {
                fwrite(sniffer.buffer, sniffer.last_read_len, 1, r_file);
                fwrite(save_path, strlen(save_path), 1, r_file);
            }
            brief = create_brief(sniffer.buffer, sniffer.last_read_len, counter + 1);
            if (verbose) {
                char timestr[256] = {0};
                time(&now_time);
                strftime(timestr, 256, "%H:%M:%S, %x", localtime(&now_time));
                printf("%u (%s).\n%s -> %s, %s -> %s, ttl=%u, length=%u\n%s\n",
                       brief.serial_no,
                       timestr,
                       haddr_s(brief.src_haddr),
                       haddr_s(brief.dst_haddr),
                       ipaddr_s(brief.src_ip),
                       ipaddr_s(brief.dst_ip),
                       (unsigned char) brief.ttl,
                       brief.len,
                       brief.verbose_info);
                //printf("\nRAW PACKET DATA\n");
                printf("%s\n", paddings(5 * step, '-'));
                display_HEX_RAW(sniffer.buffer, sniffer.last_read_len, 0, sniffer.last_read_len,
                                step, '.', "\t|\t");
                printf("%s\n\n", paddings(5 * step, '-'));
            } else {
                printf("%u (%lu). %s -> %s, length=%-12u%s\n",
                       brief.serial_no,
                       brief.timestamp - epoch_time,
                       ipaddr_s(brief.src_ip),
                       ipaddr_s(brief.dst_ip),
                       brief.len,
                       brief.info);
            }
            counter++;

        }

        close_sniffer(&sniffer);
        time(&now_time);
        printf("\n%d packets captured.\n", counter);
        printf("%lu seconds elapsed.\n", (now_time - epoch_time));
        if (to_archive) {
            if (fclose(r_file) == EOF) {
                perror("close()");
                return;
            }
        }
    } else {
        printf("run(): failed to create a sniffer\n");
        return;
    }

}

int main(int argc, char** argv) {
    run(argc, argv);
    return 0;
}

void INThandler(int sig){
    signal(sig, SIG_IGN);
    cutoff = 1;
}