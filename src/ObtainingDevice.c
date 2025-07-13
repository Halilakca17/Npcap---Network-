#include "pcap.h"
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

#include "ObtainingDevice.h"
#include "PacketSender.h"

const char* iptos(u_long in)
{
    static char addr_str[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = in;
    if (inet_ntop(AF_INET, &addr, addr_str, sizeof(addr_str)) == NULL)
        return "Invalid IP";
    return addr_str;
}

const char* ip6tos(const struct sockaddr* sockaddr, char* addr_str, size_t addr_str_len)
{
    if (sockaddr == NULL)
        return NULL;

    if (sockaddr->sa_family == AF_INET6)
    {
        void* addr_ptr = &(((struct sockaddr_in6*)sockaddr)->sin6_addr);
        inet_ntop(AF_INET6, addr_ptr, addr_str, (socklen_t)addr_str_len);
        return addr_str;
    }
    return NULL;
}

void ifprint(pcap_if_t* d)
{
    pcap_addr_t* a;
    char ip6str[128];

    printf("%s\n", d->name);

    if (d->description)
        printf("\tDescription: %s\n", d->description);

    printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

    for (a = d->addresses; a; a = a->next) {
        printf("\tAddress Family: #%d\n", a->addr->sa_family);

        switch (a->addr->sa_family)
        {
        case AF_INET:
            printf("\tAddress Family Name: AF_INET\n");
            if (a->addr)
                printf("\tAddress: %s\n", iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
            if (a->netmask)
                printf("\tNetmask: %s\n", iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr));
            if (a->broadaddr)
                printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr));
            if (a->dstaddr)
                printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in*)a->dstaddr)->sin_addr.s_addr));
            break;

        case AF_INET6:
            printf("\tAddress Family Name: AF_INET6\n");
            if (a->addr)
                printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
            break;

        default:
            printf("\tAddress Family Name: Unknown\n");
            break;
        }
    }
    printf("\n");
}

void run_obtaining_device()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
        return;
    }

    if (alldevs == NULL)
    {
        printf("No interfaces found! Make sure Npcap is installed.\n");
        return;
    }

    for (d = alldevs; d != NULL; d = d->next)
    {
        printf("%d. ", ++i);
        ifprint(d);
    }

    pcap_freealldevs(alldevs);
}
