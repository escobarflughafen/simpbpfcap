#ifndef NETWORKSNIFFER_DISPLAY_H
#define NETWORKSNIFFER_DISPLAY_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#define HEX_BASE_N 16
#define MAX_BUFFER_LEN 65536
#define DISP_HEX 0x00
#define DISP_DEC 0x01
#define DISP_RAW 0x02
#define DEFAULT_REPLACEMENT_CHAR '.'
#define DEFAULT_SEPERATOR "\t|\t"
int display_HEX(char* buffer, int buffer_len, int offset, int step);
int display_DEC(char* buffer, int buffer_len, int offset, int step);
int display_RAW(char* buffer, int buffer_len, int offset, int step, char replacement);

char* paddings(unsigned int n, char c);
unsigned int display_HEX_RAW   (char* buffer,
                                unsigned int buffer_len,
                                unsigned int offset,
                                unsigned int length,
                                unsigned int step,
                                char replacement,
                                char* separator);
char* haddr_s(char* haddr);
char* ipaddr_s(char* ipaddr);
#endif //NETWORKSNIFFER_DISPLAY_H
