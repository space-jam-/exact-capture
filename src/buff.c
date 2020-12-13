#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

#include <chaste/types/types.h>
#include <chaste/log/log.h>

#include "buff.h"
#include "data_structs/expcap.h"

/* Open a new file for output, as a buff_t */
void new_file(buff_t* buff, int snaplen, bool usec)
{
    char full_filename[1024] = {0};
    snprintf(full_filename, 1024, "%s_%i.pcap", buff->filename, buff->file_seg);

    ch_log_info("Opening output \"%s\"...\n",full_filename );
    buff->fd = open(full_filename, O_CREAT | O_TRUNC | O_WRONLY, 0666 );
    if(buff->fd < 0)
    {
        ch_log_fatal("Could not open output file %s: \"%s\"",
                     full_filename, strerror(errno));
    }

    /* TODO: Currently assumes PCAP output only, would be nice at add ERF */
    /* Generate the output file header */
    pcap_file_header_t hdr;
    hdr.magic = usec ? TCPDUMP_MAGIC: NSEC_TCPDUMP_MAGIC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = 0;
    hdr.sigfigs = 0; /* 9? libpcap always writes 0 */
    hdr.snaplen = snaplen + (ch_word)sizeof(expcap_pktftr_t);
    hdr.linktype = DLT_EN10MB;
    ch_log_info("Writing PCAP header to fd=%i\n", buff->fd);
    if(write(buff->fd,&hdr,sizeof(hdr)) != sizeof(hdr))
    {
        ch_log_fatal("Could not write PCAP header");
        /*TDOD: handle this failure more gracefully */
    }
    close(buff->fd);
}

void read_file(buff_t* buff, char* filename)
{
    buff->filename = filename;
    ch_log_debug1("Opening input %s...\n",buff->filename );
    buff->fd = open(buff->filename,O_RDONLY);
    if(!buff->fd){
        ch_log_fatal("Could not open input file %s: \"%s\"",
                     buff->filename, strerror(errno));
        }

    struct stat st = {0};
    if(stat(buff->filename, &st)){
        ch_log_fatal("Could not stat file %s: \"%s\"\n",
                     buff->filename, strerror(errno));
    }
    buff->filesize = st.st_size;


    buff->data = mmap(NULL, buff->filesize,
                            PROT_READ,
                            MAP_PRIVATE , //| MAP_POPULATE ,
                            buff->fd, 0);
    if(buff->data == MAP_FAILED){
        ch_log_fatal("Could not map input file %s: \"%s\"\n",
                     buff->filename, strerror(errno));
    }
    ch_log_debug1("File mapped at %p\n", buff->data);
}
/* Flush a buff_t to disk */
void flush_to_disk(buff_t* buff)
{

    //ch_log_info("Flushing %liB to fd=%i total=(%liMB) packets=%li\n", buff->offset, buff->fd, *file_bytes_written / 1024/ 1024, packets_written);
    /* open fd */
    char full_filename[1024] = {0};
    snprintf(full_filename, 1024, "%s_%i.pcap", buff->filename, buff->file_seg);
    buff->fd = open(full_filename, O_APPEND | O_WRONLY, 0666 );
    if (buff->fd == -1) {
        ch_log_fatal("Failed to append to output: %s\n", strerror(errno));
    }

    const uint64_t written = write(buff->fd,buff->data,buff->offset);
    if(written != buff->offset)
    {
        ch_log_fatal("Couldn't write all bytes: %s \n", strerror(errno));
    }

    buff->offset = 0;
    close(buff->fd);
}


void next_packet(buff_t* buff)
{
    pcap_pkthdr_t* curr_pkt    = buff->pkt;
    const int64_t curr_cap_len = curr_pkt->caplen;
    ch_log_debug1("Skipping %li bytes ahead\n", curr_cap_len);
    pcap_pkthdr_t* next_pkt    = (pcap_pkthdr_t*)((char*)(curr_pkt+1) + curr_cap_len);

    buff->pkt = next_pkt;
    buff->pkt_idx++;

    /*Check if we've overflowed */
    const uint64_t offset = (char*)next_pkt - buff->data;
    buff->eof = offset >= buff->filesize;
    if(buff->eof){
        ch_log_warn("End of file \"%s\"\n", buff->filename);
    }
}
