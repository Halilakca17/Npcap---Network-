#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include "SendingQueue.h"

#ifdef _WIN32
#include <tchar.h>
#include <windows.h>

BOOL LoadNpcapDlls()
{
    TCHAR npcap_dir[512];
    UINT len = GetSystemDirectory(npcap_dir, 480);
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, TEXT("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    return TRUE;
}
#endif

void usage()
{
    printf("\nSendcap - Send a .pcap file's contents to a network adapter\n");
    printf("Usage:\n");
    printf("\tsendcap <file_name> <adapter> [s]\n");
    printf("Parameters:\n");
    printf("\tfile_name: path to the .pcap file\n");
    printf("\tadapter: name of the network adapter (use WinDump -D or pcap_findalldevs)\n");
    printf("\ts: optional, send packets respecting their timestamps (synchronized)\n");
    exit(0);
}

void run_sending_queue(const char* file_name, const char* adapter, int sync)
{
#ifdef _WIN32
    if (!LoadNpcapDlls()) {
        fprintf(stderr, "Couldn't load Npcap DLLs.\n");
        return;
    }
#endif

    FILE* capfile = NULL;
    if (fopen_s(&capfile, file_name, "rb") != 0) {
        fprintf(stderr, "Error opening capture file.\n");
        return;
    }

    fseek(capfile, 0, SEEK_END);
    int caplen = ftell(capfile) - sizeof(struct pcap_file_header);
    fclose(capfile);

    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
    pcap_t* indesc;
    pcap_t* outdesc;
    pcap_send_queue* squeue;
    struct pcap_pkthdr* pktheader;
    const u_char* pktdata;
    u_int res;
    int npacks = 0;

    if (pcap_createsrcstr(source, PCAP_SRC_FILE, NULL, NULL, file_name, errbuf) != 0) {
        fprintf(stderr, "Error creating source string: %s\n", errbuf);
        return;
    }

    indesc = pcap_open(source, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (indesc == NULL) {
        fprintf(stderr, "Error opening input file: %s\n", errbuf);
        return;
    }

    outdesc = pcap_open(adapter, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (outdesc == NULL) {
        fprintf(stderr, "Error opening adapter: %s\n", errbuf);
        pcap_close(indesc);
        return;
    }

    if (pcap_datalink(indesc) != pcap_datalink(outdesc)) {
        printf("Warning: Link-layer types don't match.\n");
        printf("Press Enter to continue, Ctrl+C to abort.\n");
        getchar();
    }

    squeue = pcap_sendqueue_alloc(caplen);

    while ((res = pcap_next_ex(indesc, &pktheader, &pktdata)) == 1) {
        if (pcap_sendqueue_queue(squeue, pktheader, pktdata) == -1) {
            printf("Warning: Queue too small, not all packets will be sent.\n");
            break;
        }
        npacks++;
    }

    if (res == -1) {
        printf("Corrupted input file.\n");
        pcap_sendqueue_destroy(squeue);
        pcap_close(indesc);
        pcap_close(outdesc);
        return;
    }

    clock_t start_time = clock();

    res = pcap_sendqueue_transmit(outdesc, squeue, sync);

    clock_t end_time = clock();
    double elapsed = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    if (res < squeue->len) {
        printf("Error sending packets: %s. Only %d bytes sent.\n", pcap_geterr(outdesc), res);
    }

    printf("\nTotal packets sent = %d\n", npacks);
    printf("Elapsed time = %.3f seconds\n", elapsed);
    printf("Packets per second = %.1f\n", npacks / elapsed);

    pcap_sendqueue_destroy(squeue);
    pcap_close(indesc);
    pcap_close(outdesc);
}
