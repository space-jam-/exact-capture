/*
 * Copyright (c) 2017,2018,2019 All rights reserved.
 * See LICENSE.txt for full details.
 *
 *  Created:     28 Jul 2017
 *  Author:      Matthew P. Grosvenor
 *  Description: A tool for parsing pcaps and expcaps and outputting in ASCII
 *               for debugging and inspection.
 *
 */


#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <netinet/if_ether.h>
#include <endian.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stddef.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <chaste/types/types.h>
#include <chaste/data_structs/vector/vector_std.h>
#include <chaste/options/options.h>
#include <chaste/log/log.h>
#include <chaste/parsing/numeric_parser.h>

#include "data_structs/pthread_vec.h"
#include "data_structs/eiostream_vec.h"
#include "data_structs/pcap-structures.h"

#include "data_structs/expcap.h"
#include "checksum.h"

USE_CH_LOGGER_DEFAULT;
USE_CH_OPTIONS;

#define WRITE_BUFF_SIZE (128 * 1024 * 1024) /* 128MB */
#define ETH_CRC_LEN 4
#define VLAN_HLEN 4

struct {
    char*  input;
    char*  write;
    char*  write_filtered;
    bool verbose;
    char* format;
    ch_word offset;
    ch_word timens;
    ch_word max;
    ch_word num;
    char* dst_mac;
    char* src_mac;
    char* vlan;
    ch_word add_vlan;
    ch_word del_vlan;
    char* src_ip;
    char* dst_ip;
    char* src_port;
    char* dst_port;
} options;

typedef struct {
    char* filename;
    char* data;
    pcap_pkthdr_t* pkt;
    bool eof;
    int fd;
    uint64_t filesize;
    uint64_t offset;
    uint64_t pkt_idx;
} buff_t;

struct vlan_ethhdr {
    unsigned char	h_dest[ETH_ALEN];
    unsigned char	h_source[ETH_ALEN];
    __be16		h_vlan_proto;
    __be16		h_vlan_TCI;
    __be16		h_vlan_encapsulated_proto;
};

struct port_hdr {
    uint16_t src;
    uint16_t dst;
};

struct pseudo_iphdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
} __attribute__((packed));

typedef union {
    u64 sum;
    struct {
        u64 dst_mac : 1;
        u64 src_mac : 1;
        u64 vlan : 1;
        u64 src_ip : 1;
        u64 dst_ip : 1;
        u64 src_port : 1;
        u64 dst_port : 1;
    } bits ;
} pkt_filter_t;

static volatile bool stop = false;
void signal_handler(int signum)
{
    ch_log_warn("Caught signal %li, shutting down\n", signum);
    if(stop == 1){
        ch_log_fatal("Hard exit\n");
    }
    stop = 1;
}

/* Open a new file for output, as a buff_t */
void new_file(buff_t* wr_buff, int file_num)
{
    char full_filename[1024] = {0};
    snprintf(full_filename, 1024, "%s_%i.pcap", wr_buff->filename, file_num);

    ch_log_info("Opening output \"%s\"...\n",full_filename );
    wr_buff->fd = open(full_filename, O_CREAT | O_TRUNC | O_WRONLY, 0666 );
    if(wr_buff->fd < 0)
    {
        ch_log_fatal("Could not open output file %s: \"%s\"",
                     full_filename, strerror(errno));
    }

    /* TODO: Currently assumes PCAP output only, would be nice at add ERF */
    /* Generate the output file header */
    pcap_file_header_t hdr;
    hdr.magic = NSEC_TCPDUMP_MAGIC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = 0;
    hdr.sigfigs = 0; /* 9? libpcap always writes 0 */
    hdr.snaplen = 1518 + (ch_word)sizeof(expcap_pktftr_t);
    hdr.linktype = DLT_EN10MB;
    ch_log_info("Writing PCAP header to fd=%i\n", wr_buff->fd);
    if(write(wr_buff->fd,&hdr,sizeof(hdr)) != sizeof(hdr))
    {
        ch_log_fatal("Could not write PCAP header");
        /*TDOD: handle this failure more gracefully */
    }

}

void flush_to_disk(buff_t* wr_buff, int64_t packets_written)
{
    (void)packets_written;

    //ch_log_info("Flushing %liB to fd=%i total=(%liMB) packets=%li\n", wr_buff->offset, wr_buff->fd, *file_bytes_written / 1024/ 1024, packets_written);
    /* Not enough space in the buffer, time to flush it */
    const uint64_t written = write(wr_buff->fd,wr_buff->data,wr_buff->offset);
    if(written < wr_buff->offset)
    {
        ch_log_fatal("Couldn't write all bytes, fix this some time\n");
    }

    wr_buff->offset = 0;
}


void dprint_packet(int fd, bool expcap, pcap_pkthdr_t* pkt_hdr, char* packet,
                   int total_out, int64_t timedelta_ns)
{
    char fmtd[4096] = {0};
    char out[4096] = {0};
    int off = 0;

    if(options.num != 0){
        int n = 0;

        if(options.num < 0){
            options.num = INT64_MAX;
        }

        for(int64_t i = 0; i < MIN((int64_t)pkt_hdr->caplen,options.num); i++){
            n += sprintf(fmtd + n, "%02x", *((uint8_t*)packet +i));
        }
    }
    off += sprintf(out + off, "%04i,%lins,%i.%09i,%i,%i,",
            total_out, timedelta_ns,
            pkt_hdr->ts.ns.ts_sec, pkt_hdr->ts.ns.ts_nsec,
            pkt_hdr->caplen, pkt_hdr->len);


    if(expcap && packet){
        expcap_pktftr_t* pkt_ftr = (expcap_pktftr_t*)((char*)(packet)
                + pkt_hdr->caplen - sizeof(expcap_pktftr_t));

        off += sprintf(out + off, "%i,%i,%li.%012li,",
                pkt_ftr->dev_id,
                pkt_ftr->port_id,
                (int64_t)pkt_ftr->ts_secs, (int64_t)pkt_ftr->ts_psecs);
    }

    off += sprintf(out + off, "%s",fmtd);

    dprintf(fd, "%s\n", out);

}

int read_packet(char* data, int64_t* offset, int64_t snaplen, pcap_pkthdr_t** pkt_hdro, char** pbufo )
{
    pcap_pkthdr_t* pkt_hdr = (pcap_pkthdr_t*)(data + *offset);
    *offset += sizeof(pcap_pkthdr_t);

    bool error = false;
    snaplen = 4096;
    if(pkt_hdr->caplen > snaplen){
        ch_log_error("Error, packet length out of range [0,%li] %u at offset=%li\n", snaplen, pkt_hdr->len, offset);
        error = true;
    }

    if(options.verbose && (pkt_hdr->len != 0 && pkt_hdr->len + sizeof(expcap_pktftr_t) < pkt_hdr->caplen)){
        ch_log_warn("Warning: packet len %li < capture len %li\n", pkt_hdr->len, pkt_hdr->caplen);
    }


    if(error){
        char* pbuf = data + *offset;
        hexdump(pkt_hdr, sizeof(pkt_hdr));
        hexdump(pbuf, 4096);
        exit(0);
    }

    char* pbuf = data + *offset;
    *offset += pkt_hdr->caplen;

    *pbufo = pbuf;
    *pkt_hdro = pkt_hdr;

    return 0;

}

static int str_to_mac(char* str, unsigned char** mac_out)
{
    if(strlen(str) == ((sizeof(unsigned char) * ETH_ALEN) * 2) + 2){
        u64 mac = htobe64(parse_number(str, 0).val_uint) >> 16;
        *mac_out = (unsigned char *)mac;
        return 0;
    }
    return -1;
}

static int parse_mac_opt(char* str, unsigned char** old_mac, unsigned char** new_mac)
{
    char* tok_old = strtok(str, ",");
    char* tok_new = strtok(NULL, ",");

    /* If there is no new MAC specified */
    if(!tok_new && str){
        return str_to_mac(str, old_mac);
    }

    if(str_to_mac(tok_old, old_mac) == 0 && str_to_mac(tok_new, new_mac) == 0){
        return 0;
    }

    return -1;
}

static int parse_vlan_opt(char* str, u16* old_vlan, u16* new_vlan)
{
    char* tok_old = strtok(str, ",");
    char* tok_new = strtok(NULL, ",");
    u16 old_tag, new_tag;

    old_tag = htobe16(parse_number(tok_old, 0).val_uint);
    *old_vlan = old_tag;

    if(tok_new){
        new_tag = htobe16(parse_number(tok_new, 0).val_uint);
        *new_vlan = new_tag;
    }

    return 0;
}

static int parse_ip_opt(char* str, u32* old_ip, u32* new_ip)
{
    struct in_addr old_addr, new_addr;
    char *tok_old = strtok(str, ",");
    char *tok_new = strtok(NULL, ",");

    if(str){
        if(!inet_aton(tok_old, &old_addr)){
            return -1;
        }

        *old_ip = old_addr.s_addr;
    }

    if(tok_new){
        if(!inet_aton(tok_new, &new_addr)){
            return -1;
        }

        *new_ip = new_addr.s_addr;
    }

    return 0;
}

static int parse_port_opt(char *str, u16* old_port, u16* new_port)
{
    char *tok_old = strtok(str, ",");
    char *tok_new = strtok(NULL, ",");
    u16 old_p, new_p;

    if(!tok_new && str){
        old_p = htobe16(parse_number(tok_old, 0).val_uint);
        *old_port = old_p;
        return 0;
    }

    if(tok_new){
        new_p = htobe16(parse_number(tok_new, 0).val_uint);
        *new_port = new_p;
        return 0;
    }
    return -1;
}

static inline int compare_mac(unsigned char* lhs, unsigned char* rhs)
{
    return memcmp(lhs, rhs, sizeof(unsigned char) * ETH_ALEN) == 0;
}

static inline void copy_mac(unsigned char* dst, unsigned char* src)
{
    memcpy(dst, src, sizeof(unsigned char) * ETH_ALEN);
}

static inline int is_mac_valid(unsigned char* mac_addr)
{
    u64* mac = (u64*)mac_addr;
    return (*mac << 16) != 0;
}

static inline int compare_vlan(struct vlan_ethhdr* lhs, struct vlan_ethhdr* rhs)
{
    return lhs->h_vlan_proto == rhs->h_vlan_proto && lhs->h_vlan_TCI == rhs->h_vlan_TCI;
}

static inline void get_pseudo_iphdr(struct iphdr* ip_hdr, uint16_t hdr_len, struct pseudo_iphdr* hdro)
{
    hdro->saddr = ip_hdr->saddr;
    hdro->daddr = ip_hdr->daddr;
    hdro->zero = 0;
    hdro->protocol = ip_hdr->protocol;
    hdro->len = hdr_len;
}

int main(int argc, char** argv)
{
    ch_word result = -1;
    int64_t offset = 0;

    signal(SIGHUP, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGPIPE, signal_handler);
    signal(SIGALRM, signal_handler);
    signal(SIGTERM, signal_handler);

    ch_opt_addsu(CH_OPTION_REQUIRED,'i',"input","PCAP file to read", &options.input);
    ch_opt_addsi(CH_OPTION_REQUIRED,'w',"write","Destination to write modified packets to ", &options.write, NULL);

    /* Packets which are unmodified/unfiltered will be written here. */
    ch_opt_addsi(CH_OPTION_OPTIONAL,'W',"write-filtered","Destination to write filtered packets to ", &options.write_filtered, NULL);
    ch_opt_addbi(CH_OPTION_FLAG,'v',"verbose","Printout verbose output", &options.verbose, false);
    ch_opt_addsu(CH_OPTION_REQUIRED,'f',"format","Input format [pcap | expcap]", &options.format);
    ch_opt_addii(CH_OPTION_OPTIONAL,'o',"offset","Offset into the file to start ", &options.offset, 0);
    ch_opt_addii(CH_OPTION_OPTIONAL,'t',"time","Time into the file to start ", &options.timens, 0);
    ch_opt_addii(CH_OPTION_OPTIONAL,'m',"max","Max packets to output (<0 means all)", &options.max, -1);
    ch_opt_addii(CH_OPTION_OPTIONAL,'n',"num-chars","Number of characters to output (<=0 means all)", &options.num, 64);

    /* For modify options that support the OLD,NEW syntax, omitting NEW will produce a 'filtering' behavior */
    /* E.g, the option '-e 0x643F5F010203' would cause packets only with DST MAC 64:3F:5F:01:02:03 to be present in the destination pcap */
    /* If multiple options are specified, packets must match ALL options in order to be written to the destination pcap */
    ch_opt_addsi(CH_OPTION_OPTIONAL,'e',"dst-mac","Edit DST MAC with syntax 'OLD,NEW' (eg. 0x643F5F010203,0xFFFFFFFFFFFF)", &options.dst_mac, NULL);
    ch_opt_addsi(CH_OPTION_OPTIONAL,'E',"src-mac","Edit SRC MAC with syntax 'OLD,NEW' (eg. 0x643F5F010203,0xFFFFFFFFFFFF)", &options.src_mac, NULL);

    /* Modify VLAN tags, with the syntax OLD,NEW */
    /* To add a VLAN tag (e.g 100), specify 0,100 */
    /* To delete a VLAN tag (e.g 100) specify 100,0 */
    /* To change VLAN tags, (e.g 100 to 200) specify 100,200 */
    /* As with other options supporting the OLD,NEW syntax, passing in '-l 100' would cause only packets with VLAN tag 100  */
    /* to be present in the destination capture  */
    ch_opt_addsi(CH_OPTION_OPTIONAL,'l',"vlan","Edit a VLAN tag with syntax 'OLD,NEW' (eg. 100,200)", &options.vlan, 0);
    ch_opt_addsi(CH_OPTION_OPTIONAL,'a',"src-ip","Edit SRC IP with syntax 'OLD,NEW' (eg. 192.168.0.1,172.16.0.1)", &options.src_ip, NULL);
    ch_opt_addsi(CH_OPTION_OPTIONAL,'A',"dst-ip","Edit DST IP with syntax 'OLD,NEW' (eg. 192.168.0.1,172.16.0.1)", &options.dst_ip, NULL);
    ch_opt_addsi(CH_OPTION_OPTIONAL,'p',"src-port","Edit SRC port with syntax 'OLD,NEW' (eg. 5000, 51000)", &options.src_port, NULL);
    ch_opt_addsi(CH_OPTION_OPTIONAL,'P',"dst-port","Edit DST port with syntax 'OLD,NEW' (eg. 5000, 51000)", &options.dst_port, NULL);

    ch_opt_parse(argc,argv);

    ch_log_settings.log_level = CH_LOG_LVL_INFO;

    bool expcap = false;
    if(strncmp(options.format, "pcap", strlen("pcap")) == 0){
        expcap = false;
    }
    else if(strncmp(options.format, "expcap", strlen("expcap")) == 0){
        expcap = true;
    }
    else{
        ch_log_fatal("Unknown format type =\"%s\". Must be \"pcap\" or \"expcap\"\n", options.format);
    }

    if(options.max < 0){
        options.max = INT64_MAX;
    }

    ch_log_info("Starting PCAP modifier...\n");

    int fd = open(options.input,O_RDONLY);
    if(fd < 0){
        ch_log_fatal("Could not open PCAP %s (%s)\n", options.input, strerror(errno));
    }

    struct stat st = {0};
    if(stat(options.input, &st)){
        ch_log_fatal("Could not stat file %s: \"%s\"\n", options.input, strerror(errno));
    }
    const ssize_t filesize = st.st_size;

    /* Which parts of a given packet must match */
    pkt_filter_t filter = {0};
    struct ethhdr old_eth_hdr = {0};
    struct ethhdr new_eth_hdr = {0};
    if(options.dst_mac){
        if(parse_mac_opt(options.dst_mac, (unsigned char**)&old_eth_hdr.h_dest, (unsigned char**)&new_eth_hdr.h_dest) == -1){
            ch_log_fatal("Failed to parse MAC address pair: %s\n", options.dst_mac);
        }
        filter.bits.dst_mac = 1;
    }

    if(options.src_mac){
        if(parse_mac_opt(options.src_mac, (unsigned char**)&old_eth_hdr.h_source, (unsigned char**)&new_eth_hdr.h_source) == -1){
            ch_log_fatal("Failed to parse MAC address pair: %s\n", options.src_mac);
        }
        filter.bits.src_mac = 1;
    }

    struct vlan_ethhdr old_vlan_hdr = {0};
    struct vlan_ethhdr new_vlan_hdr = {0};
    if(options.vlan){
        parse_vlan_opt(options.vlan, &old_vlan_hdr.h_vlan_TCI, &new_vlan_hdr.h_vlan_TCI);
        filter.bits.vlan = 1;

        /* if an old vlan tag was specified, proto is 8021q */
        old_vlan_hdr.h_vlan_proto = old_vlan_hdr.h_vlan_TCI ? htobe16(ETH_P_8021Q) : htobe16(ETH_P_IP);

        /* if a new vlan tag was specified, proto is 8021q, encapsulate IP */
        new_vlan_hdr.h_vlan_proto = new_vlan_hdr.h_vlan_TCI ? htobe16(ETH_P_8021Q) : htobe16(ETH_P_IP);
        new_vlan_hdr.h_vlan_encapsulated_proto = htobe16(ETH_P_IP);
    }

    struct iphdr old_ip_hdr = {0};
    struct iphdr new_ip_hdr = {0};
    if(options.src_ip){
        printf("parse src: %s\n", options.src_ip);
        if(parse_ip_opt(options.src_ip, &old_ip_hdr.saddr, &new_ip_hdr.saddr) == -1){
            ch_log_fatal("Failed to parse IP address: %s\n", options.src_ip);
        }
        filter.bits.src_ip = 1;
    }
    if(options.dst_ip){
        if(parse_ip_opt(options.dst_ip, &old_ip_hdr.daddr, &new_ip_hdr.daddr) == -1){
            ch_log_fatal("Failed to parse IP address: %s\n", options.dst_ip);
        }
        filter.bits.dst_ip = 1;
    }

    struct port_hdr old_port_hdr = {0};
    struct port_hdr new_port_hdr = {0};
    if(options.src_port){
        if(parse_port_opt(options.src_port, &old_port_hdr.src, &new_port_hdr.src) == -1){
            ch_log_fatal("Failed to parse SRC port: %s\n", options.src_port);
        }
        filter.bits.src_port = 1;
    }
    if(options.dst_port){
        if(parse_port_opt(options.dst_port, &old_port_hdr.dst, &new_port_hdr.dst) == -1){
            ch_log_fatal("Failed to parse DST port: %s\n", options.dst_port);
        }
        filter.bits.dst_port = 1;
    }

    char* data = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE , fd, 0);
    if(data == MAP_FAILED){
        ch_log_fatal("Could not map input file %s: \"%s\"\n", options.input, strerror(errno));
    }

    pcap_file_header_t* fhdr = (pcap_file_header_t*)(data + offset);
    offset += sizeof(pcap_file_header_t);
    char* magic_str = fhdr->magic == NSEC_TCPDUMP_MAGIC ? "Nansec TCP Dump" :  "UNKNOWN";
    magic_str = fhdr->magic == TCPDUMP_MAGIC ? "TCP Dump" :  magic_str;
    if(options.verbose){
        printf("Magic    0x%08x (%i) (%s)\n", fhdr->magic, fhdr->magic, magic_str);
        printf("Ver Maj  0x%04x     (%i)\n", fhdr->version_major, fhdr->version_major);
        printf("Ver Min  0x%04x     (%i)\n", fhdr->version_minor, fhdr->version_minor);
        printf("Thiszone 0x%08x (%i)\n", fhdr->thiszone, fhdr->thiszone);
        printf("SigFigs  0x%08x (%i)\n", fhdr->sigfigs, fhdr->sigfigs);
        printf("Snap Len 0x%08x (%i)\n", fhdr->snaplen, fhdr->snaplen);
        printf("Link typ 0x%08x (%i)\n", fhdr->linktype, fhdr->linktype);
    }

    pcap_pkthdr_t* pkt_hdr = NULL;
    char* pbuf = NULL;

    /* Write buffer for packets which match a filter */
    buff_t match_wr_buff = {0};
    match_wr_buff.data = calloc(1, WRITE_BUFF_SIZE);
    if(!match_wr_buff.data){
        ch_log_fatal("Could not allocate memory for write buffer\n");
    }
    match_wr_buff.filename = options.write;
    int64_t match_file_seg = 0;
    new_file(&match_wr_buff, match_file_seg);

    /* Write buffer for packets do not match a filter */
    buff_t filter_wr_buff = {0};
    int64_t filter_file_seg = 0;
    if(options.write_filtered){
        filter_wr_buff.data = calloc(1, WRITE_BUFF_SIZE);
        if(!filter_wr_buff.data){
            ch_log_fatal("Could not allocate memory for write buffer\n");
        }
        filter_wr_buff.filename = options.write_filtered;
        new_file(&filter_wr_buff, filter_file_seg);
    }

    /* Packets are written here as they are processed */
    buff_t tmp_wr_buff = {0};
    /* We probably don't need 100M just for a temp buffer... make it 9KB? (ip mtu) */
    tmp_wr_buff.data = calloc(1, WRITE_BUFF_SIZE);
    if(!tmp_wr_buff.data){
        ch_log_fatal("Could not allocate memory for temp buffer\n");
    }

    int64_t timenowns = 0;
    int64_t timeprevns = 0;
    int64_t matched_out = 0;
    int64_t filtered_out = 0;
    for(int pkt_num = 0; (!stop) && (pkt_num < options.offset + options.max) && offset < filesize; pkt_num++,
    timeprevns = timenowns ){
        bool recalc_eth_crc = false;
        bool recalc_ip_csum = false;
        bool recalc_prot_csum = false;
        pkt_filter_t matched = {0};
        if(pkt_num && pkt_num % (1000 * 1000) == 0){
            ch_log_info("Loaded %li,000,000 packets\n", pkt_num/1000/1000);
        }

        if(read_packet(data, &offset, fhdr->snaplen, &pkt_hdr, &pbuf)){
            break;
        }

        timenowns = pkt_hdr->ts.ns.ts_sec * 1000ULL * 1000 * 1000 + pkt_hdr->ts.ns.ts_nsec;

        if(timeprevns == 0){
            timeprevns = timenowns;
        }

        const int64_t time_delta = timenowns - timeprevns;

        if(pkt_num < options.offset || timenowns < options.timens){
            continue;
        }

        if(options.verbose){
            dprint_packet(STDOUT_FILENO, expcap, pkt_hdr, pbuf, pkt_num, time_delta );
        }

        char *pkt_start = pbuf;
        const int64_t vlan_bytes = options.add_vlan > 0 && !options.del_vlan ? VLAN_HLEN : 0;
        int64_t pcap_copy_bytes = sizeof(pcap_pkthdr_t) + pkt_hdr->caplen + vlan_bytes;

        if(match_wr_buff.offset + pcap_copy_bytes > WRITE_BUFF_SIZE){
            flush_to_disk(&match_wr_buff, matched_out);
        }
        if(filter_wr_buff.offset + pcap_copy_bytes > WRITE_BUFF_SIZE){
            flush_to_disk(&filter_wr_buff, filtered_out);
        }

        /* Copy pcap header to new packet */
        pcap_pkthdr_t* wr_hdr = (pcap_pkthdr_t*)(tmp_wr_buff.data + tmp_wr_buff.offset);
        memcpy(wr_hdr, pkt_hdr, sizeof(pcap_pkthdr_t));
        tmp_wr_buff.offset += sizeof(pcap_pkthdr_t);

        /* Copy ethernet header to new packet */
        struct ethhdr* rd_eth_hdr = (struct ethhdr*)pbuf;
        struct ethhdr* wr_eth_hdr = (struct ethhdr*)(tmp_wr_buff.data + tmp_wr_buff.offset);
        memcpy(wr_eth_hdr, rd_eth_hdr, sizeof(struct ethhdr));
        tmp_wr_buff.offset += sizeof(struct ethhdr);
        pbuf += sizeof(struct ethhdr);

        /* Update Ethernet headers */
        if(options.dst_mac){
            if(compare_mac(wr_eth_hdr->h_dest, old_eth_hdr.h_dest)){
                matched.bits.dst_mac = 1;
                if(is_mac_valid(new_eth_hdr.h_dest)){
                    copy_mac(wr_eth_hdr->h_dest, new_eth_hdr.h_dest);
                    recalc_eth_crc = true;
                }
            }
        }
        if(options.src_mac){
            if(compare_mac(wr_eth_hdr->h_source, old_eth_hdr.h_source)){
                matched.bits.src_mac = 1;
                if(is_mac_valid(new_eth_hdr.h_source)){
                    copy_mac(wr_eth_hdr->h_source, new_eth_hdr.h_source);
                    recalc_eth_crc = true;
                }
            }
        }

        struct vlan_ethhdr* rd_vlan_hdr = (struct vlan_ethhdr*)rd_eth_hdr;
        struct vlan_ethhdr* wr_vlan_hdr = (struct vlan_ethhdr*)wr_eth_hdr;
        if(options.vlan){
            /* Are we looking for a tagged packet */
            if(old_vlan_hdr.h_vlan_TCI){
                /* Is this the VLAN tag we're looking for */
                if(compare_vlan(rd_vlan_hdr, &old_vlan_hdr)){
                    matched.bits.vlan = 1;
                    /* Do we want to change the vlan tag */
                    if(new_vlan_hdr.h_vlan_TCI){
                        /* Update with new VLAN tag */
                        wr_vlan_hdr->h_vlan_TCI = new_vlan_hdr.h_vlan_TCI;
                        /* Need to set the encapsulated proto, as we've only copied the eth header at this point */
                        wr_vlan_hdr->h_vlan_encapsulated_proto = rd_vlan_hdr->h_vlan_encapsulated_proto;
                        pbuf += VLAN_HLEN;
                        tmp_wr_buff.offset += VLAN_HLEN;
                        recalc_eth_crc = true;
                    }
                    /* Do we want to delete the vlan tag */
                    else if(new_vlan_hdr.h_vlan_proto == htobe16(ETH_P_IP)){
                        wr_vlan_hdr->h_vlan_proto = new_vlan_hdr.h_vlan_proto;
                        wr_hdr->len -= VLAN_HLEN;
                        wr_hdr->caplen -= VLAN_HLEN;
                        pbuf += VLAN_HLEN;
                        pcap_copy_bytes -= VLAN_HLEN;
                        recalc_eth_crc = true;
                    }
                }
            }
            /* We are filtering for an untagged packet */
            else{
                /* Is this an untagged packet */
                if(!compare_vlan(rd_vlan_hdr, &old_vlan_hdr)){
                    matched.bits.vlan = 1;
                    if(new_vlan_hdr.h_vlan_TCI){
                        /* Do we want to add a new vlan tag */
                        wr_vlan_hdr->h_vlan_proto = new_vlan_hdr.h_vlan_proto;
                        wr_vlan_hdr->h_vlan_TCI = new_vlan_hdr.h_vlan_TCI;
                        wr_vlan_hdr->h_vlan_encapsulated_proto = new_vlan_hdr.h_vlan_encapsulated_proto;
                        wr_hdr->len += VLAN_HLEN;
                        wr_hdr->caplen += VLAN_HLEN;
                        tmp_wr_buff.offset += VLAN_HLEN;
                        pcap_copy_bytes += VLAN_HLEN;
                        recalc_eth_crc = true;
                    }
                }
            }
        }
        else{
            if(rd_vlan_hdr->h_vlan_proto == htobe16(ETH_P_8021Q)){
                memcpy(tmp_wr_buff.data + tmp_wr_buff.offset, pbuf, VLAN_HLEN);
                pbuf += VLAN_HLEN;
                tmp_wr_buff.offset += VLAN_HLEN;
            }
        }


        /* Modify IP header, recalc csum as needed */
        struct iphdr* rd_ip_hdr = (struct iphdr*)pbuf;
        struct iphdr* wr_ip_hdr = (struct iphdr*)(tmp_wr_buff.data + tmp_wr_buff.offset);
        uint16_t rd_ip_hdr_len = rd_ip_hdr->ihl << 2;
        memcpy(tmp_wr_buff.data + tmp_wr_buff.offset, rd_ip_hdr, rd_ip_hdr_len);
        tmp_wr_buff.offset += rd_ip_hdr_len;
        pbuf += rd_ip_hdr_len;
        if(options.src_ip){
            if(rd_ip_hdr->saddr == old_ip_hdr.saddr){
                matched.bits.src_ip = 1;
                if(new_ip_hdr.saddr){
                    wr_ip_hdr->saddr = new_ip_hdr.saddr;
                    recalc_ip_csum = true;
                }
            }
        }
        if(options.dst_ip){
            if(rd_ip_hdr->daddr == old_ip_hdr.daddr){
                matched.bits.dst_ip = 1;
                if(new_ip_hdr.daddr){
                    wr_ip_hdr->daddr = new_ip_hdr.daddr;
                    recalc_ip_csum = true;
                }
            }
        }
        if(recalc_ip_csum){
            wr_ip_hdr->check = 0;
            wr_ip_hdr->check = csum((unsigned char*)wr_ip_hdr, wr_ip_hdr->ihl<<2, wr_ip_hdr->check);
        }

        /* Modify protocol ports, recalc csums */
        switch(wr_ip_hdr->protocol){
            case IPPROTO_UDP:{
                struct udphdr* rd_udp_hdr = (struct udphdr*)pbuf;
                struct udphdr* wr_udp_hdr = (struct udphdr*)(tmp_wr_buff.data + tmp_wr_buff.offset);
                const uint16_t udp_len = be16toh(rd_udp_hdr->len);
                const uint64_t bytes_remaining = pkt_hdr->len - (pbuf - pkt_start);

                /* copy the remaining packet bytes, minus the CRC. The frame may be padded out, which
                   isn't detectable from IP/L4 headers */
                memcpy(wr_udp_hdr, rd_udp_hdr, bytes_remaining);
                pbuf += bytes_remaining;
                tmp_wr_buff.offset += bytes_remaining;

                if(options.src_port){
                    if(rd_udp_hdr->source == old_port_hdr.src){
                        matched.bits.src_port = 1;
                        if(new_port_hdr.src){
                            wr_udp_hdr->source = new_port_hdr.src;
                            recalc_prot_csum = true;
                        }
                    }
                }
                if(options.dst_port){
                    if(rd_udp_hdr->dest == old_port_hdr.dst){
                        matched.bits.dst_port = 1;
                        if(new_port_hdr.dst){
                            wr_udp_hdr->dest = new_port_hdr.dst;
                            recalc_prot_csum = true;
                        }
                    }
                }
                if(recalc_prot_csum || recalc_ip_csum){
                    struct pseudo_iphdr p_hdr;
                    wr_udp_hdr->check = 0;
                    get_pseudo_iphdr(wr_ip_hdr, wr_udp_hdr->len, &p_hdr);
                    uint16_t pseudo_csum = csum((unsigned char*)&p_hdr, sizeof(struct pseudo_iphdr), 0);
                    wr_udp_hdr->check = csum((unsigned char*)wr_udp_hdr, udp_len, ~pseudo_csum);
                }
                break;
            }
            case IPPROTO_TCP:{
                struct tcphdr* rd_tcp_hdr = (struct tcphdr*)pbuf;
                struct tcphdr* wr_tcp_hdr = (struct tcphdr*)(tmp_wr_buff.data + tmp_wr_buff.offset);
                const uint16_t tcp_len = be16toh(wr_ip_hdr->tot_len) - (wr_ip_hdr->ihl<<2);
                const uint64_t bytes_remaining = pkt_hdr->len - (pbuf - pkt_start);
                memcpy(wr_tcp_hdr, rd_tcp_hdr, bytes_remaining);
                pbuf += bytes_remaining;
                tmp_wr_buff.offset += bytes_remaining;

                if(options.src_port){
                    if(rd_tcp_hdr->source == old_port_hdr.src){
                        matched.bits.src_port = 1;
                        if(new_port_hdr.src){
                            wr_tcp_hdr->source = new_port_hdr.src;
                            recalc_prot_csum = true;
                        }
                    }
                }
                if(options.dst_port){
                    if(rd_tcp_hdr->source == new_port_hdr.dst){
                        matched.bits.dst_port = 1;
                        if(new_port_hdr.dst){
                            wr_tcp_hdr->dest = new_port_hdr.dst;
                            recalc_prot_csum = true;
                        }
                    }
                }
                if(recalc_prot_csum){
                    struct pseudo_iphdr p_hdr;
                    wr_tcp_hdr->check = 0;
                    get_pseudo_iphdr(wr_ip_hdr, htobe16(tcp_len), &p_hdr);
                    uint16_t pseudo_csum = csum((unsigned char*)&p_hdr, sizeof(struct pseudo_iphdr), 0);
                    wr_tcp_hdr->check = csum((unsigned char*)wr_tcp_hdr, tcp_len, ~pseudo_csum);
                }
                break;
            }
        }

        if(recalc_eth_crc || recalc_ip_csum || recalc_prot_csum){
            uint32_t* wr_crc = (uint32_t*)(tmp_wr_buff.data + tmp_wr_buff.offset - ETH_CRC_LEN);
            *wr_crc = 0;
            *wr_crc = crc32(((char *)wr_hdr + sizeof(pcap_pkthdr_t)), (wr_hdr->len - ETH_CRC_LEN));
        }

        /* If expcap trailer present, copy over */
        if(expcap){
            expcap_pktftr_t* rd_pkt_ftr = (expcap_pktftr_t*)pbuf;
            expcap_pktftr_t* wr_pkt_ftr = (expcap_pktftr_t*)(tmp_wr_buff.data + tmp_wr_buff.offset);
            memcpy(wr_pkt_ftr, rd_pkt_ftr, sizeof(expcap_pktftr_t));
            tmp_wr_buff.offset += sizeof(expcap_pktftr_t);
        }

        /* If our filter matches, write to matched buffer */
        if(matched.sum == filter.sum){
            memcpy(match_wr_buff.data + match_wr_buff.offset, tmp_wr_buff.data, pcap_copy_bytes);
            match_wr_buff.offset += pcap_copy_bytes;
            matched_out++;
        }
        /* Otherwise, write the original packet out */
        else if (options.write_filtered){
            memcpy(filter_wr_buff.data + filter_wr_buff.offset, pkt_hdr, sizeof(pcap_pkthdr_t) + pkt_hdr->caplen);
            filter_wr_buff.offset += sizeof(pcap_pkthdr_t) + pkt_hdr->caplen;
            filtered_out++;
        }

        /* Wipe the temp buffer */
        memset(tmp_wr_buff.data, 0, pcap_copy_bytes);
        tmp_wr_buff.offset = 0;
    }

    munmap(data, filesize);
    close(fd);
    flush_to_disk(&match_wr_buff, matched_out);
    close(match_wr_buff.fd);

    if(options.write_filtered){
        flush_to_disk(&filter_wr_buff, filtered_out);
        close(filter_wr_buff.fd);
    }

    ch_log_info("Modified %li packets\n", matched_out);
    ch_log_info("Filtered %li packets\n", filtered_out);
    ch_log_info("PCAP modifier, finished\n");
    result = 0;
    return result;

}
