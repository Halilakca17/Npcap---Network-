#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <tchar.h>

#include "GatheringStatistic.h"

void usage();
void dispatcher_handler(u_char*, const struct pcap_pkthdr*, const u_char*);

void run_gathering_statistic(const char* adapter_name)
{
    pcap_t* fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct timeval st_ts;
    u_int netmask;
    struct bpf_program fcode;

    if (adapter_name == NULL)
    {
        usage();
        return;
    }

    fp = pcap_open(adapter_name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (fp == NULL)
    {
        fprintf(stderr, "\nUnable to open adapter %s.\n", errbuf);
        return;
    }

    netmask = 0xffffff;

    if (pcap_compile(fp, &fcode, "tcp", 1, netmask) < 0)
    {
        fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
        pcap_close(fp);
        return;
    }

    if (pcap_setfilter(fp, &fcode) < 0)
    {
        fprintf(stderr, "\nError setting the filter.\n");
        pcap_close(fp);
        return;
    }

    if (pcap_setmode(fp, MODE_STAT) < 0)
    {
        fprintf(stderr, "\nError setting the mode.\n");
        pcap_close(fp);
        return;
    }

    printf("TCP traffic summary:\n");

    pcap_loop(fp, 0, dispatcher_handler, (PUCHAR)&st_ts);

    pcap_close(fp);
}

void dispatcher_handler(u_char* state, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    struct timeval* old_ts = (struct timeval*)state;
    u_int delay;
    LARGE_INTEGER Bps, Pps;
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;

    delay = (header->ts.tv_sec - old_ts->tv_sec) * 1000000 - old_ts->tv_usec + header->ts.tv_usec;

    Bps.QuadPart = (((*(LONGLONG*)(pkt_data + 8)) * 8 * 1000000) / (delay));
    Pps.QuadPart = (((*(LONGLONG*)(pkt_data)) * 1000000) / (delay));

    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

    printf("%s ", timestr);
    printf("BPS=%I64u ", Bps.QuadPart);
    printf("PPS=%I64u\n", Pps.QuadPart);

    old_ts->tv_sec = header->ts.tv_sec;
    old_ts->tv_usec = header->ts.tv_usec;
}

static void usage()
{
    printf("\nShows the TCP traffic load, in bits per second and packets per second."
           "\nCopyright (C) 2002 Loris Degioanni.\n");
    printf("\nUsage:\n");
    printf("\t tcptop adapter\n");
    printf("\t You can use \"WinDump -D\" if you don't know the name of your adapters.\n");

    exit(0);
}
