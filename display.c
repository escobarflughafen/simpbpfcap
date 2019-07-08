#include "display.h"

void _display_raw_char(char c, char replacement) {
    printf("%c", (c >= 32 && c < 127) ? c : replacement);
}

int _display(char* buffer, int buffer_len, int offset, int step, int displaymode, char replacement) {
    if (NULL == buffer)
        return -1;
    step = (step < 0) ? (0 - step) : step;
    int row_s = offset / step;
    int row_e = (buffer_len % step > 0) ? buffer_len / step + 1 : buffer_len / step;
    int i, j, padding, pointer;

    padding = offset - row_s * step;
    //padding
    if (padding > 0) {
        switch (displaymode) {
            default:
            case DISP_HEX:
                printf("%04x\t", row_s * step);
                for (int i = 0; i < padding; i++) {
                    printf("   ");
                }
                for (int i = padding; i < ((step < buffer_len) ? step : buffer_len); i++) {
                    printf("%02x ", (unsigned char) *(buffer + i));
                }
                break;
            case DISP_RAW:
                printf("%04x\t", row_s * step);
                for (int i = 0; i < padding; i++) {
                    printf(" ");
                }
                for (int i = padding; i < ((step < buffer_len) ? step : buffer_len); i++) {
                    _display_raw_char(*(buffer + i), replacement);
                }
                break;
            case DISP_DEC:
                printf("%05d\t", row_s * step);
                for (int i = 0; i < padding; i++) {
                    printf("    ");
                }
                for (int i = padding; i < ((step < buffer_len) ? step : buffer_len); i++) {
                    printf("%03u ", (unsigned char) *(buffer + i));
                }
                break;
        }
        printf("\n");
    }
    for (i = (padding > 0) ? row_s + 1 : row_s, pointer = (padding > 0) ? (row_s + 1) * step : offset;
         i < row_e; i++, pointer += step) {
        switch (displaymode) {
            default:
            case DISP_HEX:
            case DISP_RAW:
                printf("%04x\t", i * step);
                break;
            case DISP_DEC:
                printf("%05d\t", i * step);
                break;
        }

        for (j = 0; j < step; j++) {
            if (pointer + j >= buffer_len) break;
            switch (displaymode) {
                default:
                case DISP_HEX:
                    printf("%02x ", (unsigned char) *(buffer + pointer + j));
                    break;
                case DISP_DEC:
                    printf("%03u ", (unsigned char) *(buffer + pointer + j));
                    break;
                case DISP_RAW:
                    _display_raw_char(*(buffer + pointer + j), replacement);

            }
        }
        printf("\n");
    }
    return row_e;
}

int display_HEX(char* buffer, int buffer_len, int offset, int step) {
    return _display(buffer, buffer_len, offset, step, DISP_HEX, DEFAULT_REPLACEMENT_CHAR);
}

int display_DEC(char* buffer, int buffer_len, int offset, int step) {
    return _display(buffer, buffer_len, offset, step, DISP_DEC, DEFAULT_REPLACEMENT_CHAR);
}

int display_RAW(char* buffer, int buffer_len, int offset, int step, char replacement) {
    return _display(buffer, buffer_len, offset, step, DISP_RAW, replacement);
}
char* paddings(unsigned int n, char c) {
    char *s;
    s = (char *) malloc(n + 1 * sizeof(char));
    memset(s, c, n);
    *(s + n) = 0;
    return s;
}

unsigned int display_HEX_RAW(char* buffer, unsigned int buffer_len, unsigned  int offset, unsigned int length, unsigned int step, char replacement, char* separator) {

    if (NULL == buffer || offset > buffer_len)
        return -1;

    if (offset + length > buffer_len) {
        length -= buffer_len - offset;
    }
    int row_s, row_e, first_line_padding, last_line_complement;
    int i, j;
    first_line_padding = offset % step;
    last_line_complement = step - ((offset + length) % step);
    row_s = offset / step;  //row number of starting
    row_e = (offset + length) / step + (((offset + length) % step > 0) ? 1 : 0);  //row number of ending
    if (first_line_padding > 0) {
        printf("%04x\t", row_s);
        printf("%s", paddings(first_line_padding * 3, ' '));
        for (i = 0; i < step - first_line_padding; i++) {
            printf("%02x ", (unsigned char) *(buffer + i + offset));
        }
        if (offset + length < step && last_line_complement > 0) {
            printf("%s", paddings(3 * last_line_complement, ' '));
        }
        printf("%s", separator);
        printf("%s", paddings(first_line_padding * 1, ' '));
        for (i = 0; i < step - first_line_padding; i++) {
            _display_raw_char(*(buffer + i + offset), replacement);
        }
        printf("\n");
        row_s++;
    }

    if (row_s < row_e) {
        for (i = row_s; i < row_e - ((last_line_complement > 0) ? 1 : 0); i++) {
            printf("%04x\t", i);
            for (j = 0; j < step; j++) {
                printf("%02x ", (unsigned char) *(buffer + j + i * step));
            }
            printf("%s", separator);
            for (j = 0; j < step; j++) {
                _display_raw_char(*(buffer + j + i * step), replacement);
            }
            printf("\n");
        }

        if (last_line_complement > 0) {
            printf("%04x\t", i);
            for (i = 0; i < step - last_line_complement; i++) {
                printf("%02x ", (unsigned char) *(buffer + i + (row_e - 1) * step));
            }
            printf("%s", paddings(3 * last_line_complement, ' '));
            printf("%s", separator);
            for (i = 0; i < step - last_line_complement; i++) {
                _display_raw_char(*(buffer + i + (row_e - 1) * step), replacement);
            }
            printf("\n");
        }
        row_s--;
    }
    return row_e - row_s;
}

char* haddr_s(char* haddr) {
    char *str_haddr = (char *) malloc(18 * sizeof(char));
    sprintf(str_haddr,
            "%02x:%02x:%02x:%02x:%02x:%02x",
            (unsigned char)haddr[0],
            (unsigned char)haddr[1],
            (unsigned char)haddr[2],
            (unsigned char)haddr[3],
            (unsigned char)haddr[4],
            (unsigned char)haddr[5]);
    return str_haddr;
}

char* ipaddr_s(char* ipaddr){
    char* str_ipaddr = (char*)malloc(16*sizeof(char));
    sprintf(str_ipaddr,
            "%u.%u.%u.%u",
            (unsigned char)ipaddr[0],
            (unsigned char)ipaddr[1],
            (unsigned char)ipaddr[2],
            (unsigned char)ipaddr[3]);
    return str_ipaddr;
}