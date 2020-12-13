#include "data_structs/pcap-structures.h"

typedef struct {
    char* filename;
    char* data;
    pcap_pkthdr_t* pkt;
    bool eof;
    int fd;
    uint64_t filesize;
    uint64_t offset;
    uint64_t pkt_idx;
    int file_seg;
    uint64_t file_offset;
} buff_t;

void read_file(buff_t* buff, char* filename);
void new_file(buff_t* buff, int snaplen, bool usec);
void next_packet(buff_t* buff);
void flush_to_disk(buff_t* wr_buff);
