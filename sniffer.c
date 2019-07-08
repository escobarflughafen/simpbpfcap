#include "sniffer.h"

/*
 * Search for an available BSD package filter pseudo-device,
 * which provides a raw interface to data link layers in a protocol
 * independence fashion.
 */
int select_bpf_device(struct sniffer_t *sniffer){
    char dev[11] = {0};
    for (int i=0; i<99; i++){
        sprintf(dev, "/dev/bpf%i", i);
        sniffer->fd = open(dev, O_RDWR);
        if(sniffer->fd != -1){
            strcpy(sniffer->device, dev);
            return i;
        }
    }
    return -1;
}

/*
 * Configure bpf device for creating a sniffer on data link layers.
 */
int configure_bpf_device(struct sniffer_t *sniffer, char* device, char* interface, unsigned int buf_len) {
    if (strlen(device) == 0 || NULL == device) {
        if (select_bpf_device(sniffer) == -1) {
            perror("select_bpf_device()");
            return -1;
        }
    } else {
        sniffer->fd = open(device, O_RDWR);
        if (sniffer->fd == -1) {
            perror("open() O_RDWR");
            return -1;
        }
    }

    if (buf_len == 0) {
        if (ioctl(sniffer->fd, BIOCGBLEN, &sniffer->buf_len) == -1) {
            perror("ioctl() BIOCGBLEN");
            return -1;
        }
    } else {
        if (ioctl(sniffer->fd, BIOCSBLEN, buf_len) == 1) {
            perror("ioctl() BIOCSBLEN");
            return -1;
        }
        sniffer->buf_len = buf_len;
    }

    struct ifreq if_req;
    strcpy(if_req.ifr_name, interface);
    if (ioctl(sniffer->fd, BIOCSETIF, &if_req) > 0) {
        perror("ioctl() BIOCSETIF");
        return -1;
    }

    unsigned int enable = 1;
    if (ioctl(sniffer->fd, BIOCIMMEDIATE, &enable) == -1) {
        perror("ioctl() BIOCIMMEDIATE");
        return -1;
    }

    if (ioctl(sniffer->fd, BIOCPROMISC, NULL) == -1) {
        perror("ioctl() BIOCPROMISC");
        return -1;
    }

    sniffer->read_bytes_consumed = 0;
    sniffer->last_read_len = 0;
    sniffer->buffer = (char *) malloc(sniffer->buf_len * sizeof(char));
    return 0;
}

int create_sniffer(struct sniffer_t *sniffer, char* device, char* interface, unsigned int buf_len){
    return configure_bpf_device(sniffer, device, interface, buf_len);
}

/*
 * Capture incoming raw packets in promiscuous mode.
 */
int read_packets(struct sniffer_t *sniffer) {
    memset(sniffer->buffer, 0, sniffer->buf_len);
    ssize_t len;

    sniffer->read_bytes_consumed = 0;
    if ((len = read(sniffer->fd, sniffer->buffer, sniffer->buf_len)) == -1) {
        sniffer->last_read_len = 0;
        perror("read:");
        return -1;
    }
    sniffer->last_read_len = (unsigned int) len;

    return (int) len;
}

int parse_packets(struct sniffer_t *sniffer, struct captureinfo_t *info) {
    if (sniffer->read_bytes_consumed + sizeof(sniffer->buffer) >= sniffer->last_read_len) {
        return 0;
    }

    info->bpf_hdr = (struct bpf_hdr *) ((long) sniffer->buffer + (long) sniffer->read_bytes_consumed);
    info->data = sniffer->buffer + (long) sniffer->read_bytes_consumed + info->bpf_hdr->bh_hdrlen;
    sniffer->read_bytes_consumed += BPF_WORDALIGN(info->bpf_hdr->bh_hdrlen + info->bpf_hdr->bh_caplen);

    return info->bpf_hdr->bh_datalen;
}

int close_sniffer(struct sniffer_t *sniffer) {
    free(sniffer->buffer);
    if (close(sniffer->fd) == -1)
        return -1;
    return 0;
}
