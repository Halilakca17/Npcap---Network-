#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <winsock2.h>
#include <windows.h>

typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ip_address;

typedef struct ip_header {
    u_char  ver_ihl;
    u_char  tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char  ttl;
    u_char  proto;
    u_short crc;
    ip_address  saddr;
    ip_address  daddr;
    u_int  op_pad;
} ip_header;

typedef struct udp_header {
    u_short sport;
    u_short dport;
    u_short len;
    u_short crc;
} udp_header;

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    struct tm ltime;
    char timestr[16];
    ip_header* ih;
    udp_header* uh;
    u_int ip_len;
    u_short sport, dport;
    time_t local_tv_sec;

    (void)(param);

    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

    printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

    ih = (ip_header*)(pkt_data + 14); // Ethernet header uzunluðu

    ip_len = (ih->ver_ihl & 0x0f) * 4;
    uh = (udp_header*)((u_char*)ih + ip_len);

    sport = ntohs(uh->sport);
    dport = ntohs(uh->dport);

    printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
        ih->saddr.byte1,
        ih->saddr.byte2,
        ih->saddr.byte3,
        ih->saddr.byte4,
        sport,
        ih->daddr.byte1,
        ih->daddr.byte2,
        ih->daddr.byte3,
        ih->daddr.byte4,
        dport);
}

void run_inter_packets()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask;
    char packet_filter[] = "ip and udp";
    struct bpf_program fcode;

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
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
        pcap_freealldevs(alldevs);
        return;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf_s("%d", &inum);
    getchar();

    if (inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs);
        return;
    }

    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
        pcap_freealldevs(alldevs);
        return;
    }

    if (pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
        pcap_freealldevs(alldevs);
        return;
    }

    if (d->addresses != NULL)
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        netmask = 0xffffff;

    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    {
        fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
        pcap_freealldevs(alldevs);
        return;
    }

    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr, "\nError setting the filter.\n");
        pcap_freealldevs(alldevs);
        return;
    }

    printf("\nlistening on %s...\n", d->description);

    pcap_freealldevs(alldevs);

    pcap_loop(adhandle, 0, packet_handler, NULL);
}
