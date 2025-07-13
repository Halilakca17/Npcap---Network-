#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "SavingDumpFiles.h"

void packet_handler(u_char* param,
    const struct pcap_pkthdr* header,
    const u_char* pkt_data);

void run_saving_dump_files(const char* filename)
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_dumper_t* dumpfile;

    if (filename == NULL)
    {
        printf("usage: %s filename\n", filename);
        return;
    }

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return;
    }

    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf_s("%d", &inum);

    if (inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs);
        return;
    }

    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);

    if (adhandle == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
        pcap_freealldevs(alldevs);
        return;
    }

    dumpfile = pcap_dump_open(adhandle, filename);
    if (dumpfile == NULL)
    {
        fprintf(stderr, "\nError opening output file\n");
        return;
    }

    printf("\nlistening on %s... Press Ctrl+C to stop...\n", d->description);

    pcap_freealldevs(alldevs);

    pcap_loop(adhandle, 0, packet_handler, (unsigned char*)dumpfile);
}

static void packet_handler(u_char* dumpfile,
    const struct pcap_pkthdr* header,
    const u_char* pkt_data)
{
    pcap_dump(dumpfile, header, pkt_data);
}
