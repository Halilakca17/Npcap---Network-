#include "Filtering.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

void run_filtering()
{
    pcap_if_t* alldevs, * d;
    pcap_t* adhandle;
    int i = 0, inum, res;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;
    struct bpf_program fcode;
    bpf_u_int32 netmask;

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
        return;
    }

    for (d = alldevs; d != NULL; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0) {
        printf("No interfaces found! Make sure Npcap is installed.\n");
        return;
    }

    printf("Enter the interface number (1-%d): ", i);
    scanf_s("%d", &inum);

    if (inum < 1 || inum > i) {
        printf("Invalid interface number.\n");
        pcap_freealldevs(alldevs);
        return;
    }

    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (adhandle == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
        pcap_freealldevs(alldevs);
        return;
    }

    printf("\nListening on %s...\n", d->description ? d->description : d->name);

    if (d->addresses != NULL)
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        netmask = 0xffffff;

    pcap_freealldevs(alldevs);

    if (pcap_compile(adhandle, &fcode, "tcp port 80", 1, netmask) < 0) {
        fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
        return;
    }

    if (pcap_setfilter(adhandle, &fcode) < 0) {
        fprintf(stderr, "\nError setting the filter.\n");
        return;
    }

    while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
    {
        if (res == 0)
            continue;

        local_tv_sec = header->ts.tv_sec;
        localtime_s(&ltime, &local_tv_sec);
        strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);
        printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
    }

    if (res == -1) {
        printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
        return;
    }
}
