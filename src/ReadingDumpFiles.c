#include "ReadingDumpFiles.h"
#include <stdio.h>
#include <pcap.h>

#define LINE_LEN 16

void run_reading_dump_files(const char* filename)
{
    pcap_t* fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    u_int i = 0;
    int res;

    if (pcap_createsrcstr(source,
        PCAP_SRC_FILE,
        NULL,
        NULL,
        filename,
        errbuf) != 0)
    {
        fprintf(stderr, "\nError creating a source string\n");
        return;
    }

    if ((fp = pcap_open(source, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
    {
        fprintf(stderr, "\nUnable to open the file %s.\n", source);
        return;
    }

    while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
    {
        printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

        for (i = 1; i < header->caplen + 1; i++)
        {
            printf("%.2x ", pkt_data[i - 1]);
            if ((i % LINE_LEN) == 0)
                printf("\n");
        }

        printf("\n\n");
    }

    if (res == -1)
    {
        printf("Error reading the packets: %s\n", pcap_geterr(fp));
    }

    // pcap_close(fp); // Dilersen aktif edebilirsin
}
