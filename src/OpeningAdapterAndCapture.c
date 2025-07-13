#include "OpeningAdapterAndCapture.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>

int GetIPString(uint32_t ip, char* buffer, size_t buflen)
{
    if (inet_ntop(AF_INET, &ip, buffer, (socklen_t)buflen) == NULL) {
        return -1;
    }
    return 0;
}

void run_opening_adapter_and_capture()
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

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
        return;
    }

    printf("=== Available Network Interfaces ===\n");
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

    printf("\nEnter the interface number (1-%d): ", i);
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

    printf("\n=== Listening on %s ===\n", d->description ? d->description : d->name);
    printf("Press Ctrl+C to stop...\n\n");

    pcap_freealldevs(alldevs);

    while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
    {
        if (res == 0)
            continue;

        local_tv_sec = header->ts.tv_sec;
        localtime_s(&ltime, &local_tv_sec);
        strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);

        printf("=== PACKET CAPTURED ===\n");
        printf("Timestamp: %s.%06d\n", timestr, header->ts.tv_usec);
        printf("Packet Length: %d bytes\n", header->len);

        printf("Destination MAC: ");
        for (int i = 0; i < 6; i++) {
            printf("%02X", pkt_data[i]);
            if (i != 5) printf(":");
        }
        printf("\n");

        printf("Source MAC: ");
        for (int i = 6; i < 12; i++) {
            printf("%02X", pkt_data[i]);
            if (i != 11) printf(":");
        }
        printf("\n");

        const u_char* data = pkt_data + 12;

        unsigned short ethernet_type = (data[0] << 8) | data[1];
        data += 2;

        printf("EtherType: 0x%04X ", ethernet_type);
        if (ethernet_type == 0x0800)
            printf("(IPv4)\n");
        else if (ethernet_type == 0x0806)
            printf("(ARP)\n");
        else if (ethernet_type == 0x86DD)
            printf("(IPv6)\n");
        else
            printf("(Unknown Protocol)\n");

        if (ethernet_type == 0x0800)
        {
            unsigned char protocol = data[9];
            unsigned short total_length = (data[2] << 8) | data[3];
            unsigned short identification = (data[4] << 8) | data[5];
            unsigned char ip_header_len = (data[0] & 0x0F) * 4;

            uint32_t ip_src = *(uint32_t*)(data + 12);
            uint32_t ip_dst = *(uint32_t*)(data + 16);

            char ipstr_src[INET_ADDRSTRLEN];
            char ipstr_dst[INET_ADDRSTRLEN];

            if (GetIPString(ip_src, ipstr_src, sizeof(ipstr_src)) != 0)
                snprintf(ipstr_src, sizeof(ipstr_src), "Invalid IP");

            if (GetIPString(ip_dst, ipstr_dst, sizeof(ipstr_dst)) != 0)
                snprintf(ipstr_dst, sizeof(ipstr_dst), "Invalid IP");

            printf("--- IPv4 Header ---\n");
            printf("Total Length: %u bytes\n", total_length);
            printf("Identification: %u\n", identification);
            printf("Source IP: %s\n", ipstr_src);
            printf("Destination IP: %s\n", ipstr_dst);
            printf("Protocol: %u ", protocol);

            switch (protocol) {
            case 1: printf("(ICMP)\n"); break;
            case 6: printf("(TCP)\n"); break;
            case 17: printf("(UDP)\n"); break;
            default: printf("(Other)\n"); break;
            }

            if (protocol == 6 || protocol == 17)
            {
                const u_char* l4_data = data + ip_header_len;

                unsigned short src_port = (l4_data[0] << 8) | l4_data[1];
                unsigned short dst_port = (l4_data[2] << 8) | l4_data[3];

                printf("--- Layer 4 Transport Header ---\n");
                printf("Protocol: %s\n", protocol == 6 ? "TCP" : "UDP");
                printf("Source Port: %u\n", src_port);
                printf("Destination Port: %u\n", dst_port);

                const char* application = "UNKNOWN";

                if (src_port == 53 || dst_port == 53) {
                    application = "DNS";
                }
                else if (protocol == 6 && (src_port == 80 || dst_port == 80 || src_port == 8080 || dst_port == 8080)) {
                    application = "HTTP";
                }
                else if (protocol == 6 && (src_port == 443 || dst_port == 443)) {
                    application = "HTTPS/SSL";
                }
                else if (protocol == 6 && (src_port == 25 || dst_port == 25 || src_port == 587 || dst_port == 587)) {
                    application = "SMTP";
                }
                else if (protocol == 6 && (src_port == 110 || dst_port == 110 || src_port == 995 || dst_port == 995)) {
                    application = "POP3";
                }
                else if (protocol == 17 && (src_port == 123 || dst_port == 123)) {
                    application = "NTP";
                }
                else if (src_port >= 1024 && dst_port >= 1024) {
                    application = "PRIVATE/DYNAMIC";
                }

                printf("Application Protocol: %s\n", application);

                if (protocol == 6) {
                    unsigned char tcp_flags = l4_data[13];

                    printf("--- TCP Flags ---\n");
                    printf("Flags: 0x%02X (", tcp_flags);

                    if (tcp_flags & 0x01) printf("FIN ");
                    if (tcp_flags & 0x02) printf("SYN ");
                    if (tcp_flags & 0x04) printf("RST ");
                    if (tcp_flags & 0x08) printf("PSH ");
                    if (tcp_flags & 0x10) printf("ACK ");
                    if (tcp_flags & 0x20) printf("URG ");
                    if (tcp_flags & 0x40) printf("ECE ");
                    if (tcp_flags & 0x80) printf("CWR ");

                    printf(")\n");
                }

                if (protocol == 6 && (src_port == 80 || dst_port == 80 || src_port == 8080 || dst_port == 8080)) {
                    const u_char* http_data = l4_data + 20;
                    int http_data_len = total_length - ip_header_len - 20;

                    if (http_data_len > 0) {
                        printf("--- HTTP Payload (First 100 bytes) ---\n");
                        for (int i = 0; i < http_data_len && i < 100; i++) {
                            if (http_data[i] >= 32 && http_data[i] <= 126) {
                                printf("%c", http_data[i]);
                            }
                            else {
                                printf(".");
                            }
                        }
                        printf("\n");
                    }
                }

                if ((protocol == 17 || protocol == 6) && (src_port == 53 || dst_port == 53)) {
                    const u_char* dns_data = l4_data + (protocol == 17 ? 8 : 20);

                    unsigned short transaction_id = (dns_data[0] << 8) | dns_data[1];
                    unsigned short flags = (dns_data[2] << 8) | dns_data[3];
                    unsigned short questions = (dns_data[4] << 8) | dns_data[5];
                    unsigned short answer_rrs = (dns_data[6] << 8) | dns_data[7];
                    unsigned short authority_rrs = (dns_data[8] << 8) | dns_data[9];
                    unsigned short additional_rrs = (dns_data[10] << 8) | dns_data[11];

                    printf("--- DNS Header ---\n");
                    printf("Transaction ID: 0x%04X\n", transaction_id);
                    printf("Flags: 0x%04X\n", flags);
                    printf("Questions: %u\n", questions);
                    printf("Answer RRs: %u\n", answer_rrs);
                    printf("Authority RRs: %u\n", authority_rrs);
                    printf("Additional RRs: %u\n", additional_rrs);
                }
            }
            else if (protocol == 1) {
                const u_char* icmp_data = data + ip_header_len;

                unsigned char icmp_type = icmp_data[0];
                unsigned char icmp_code = icmp_data[1];
                unsigned short icmp_checksum = (icmp_data[2] << 8) | icmp_data[3];

                printf("--- ICMP Header ---\n");
                printf("Type: %u ", icmp_type);

                switch (icmp_type) {
                case 0: printf("(Echo Reply)\n"); break;
                case 3: printf("(Destination Unreachable)\n"); break;
                case 8: printf("(Echo Request)\n"); break;
                case 11: printf("(Time Exceeded)\n"); break;
                default: printf("(Other)\n"); break;
                }

                printf("Code: %u\n", icmp_code);
                printf("Checksum: 0x%04X\n", icmp_checksum);
            }
            else {
                printf("--- Other IP Protocol ---\n");
                printf("Protocol Number: %u\n", protocol);
                printf("(Not TCP/UDP/ICMP - detailed analysis not implemented)\n");
            }
        }
        else if (ethernet_type == 0x0806)
        {
            printf("--- ARP Packet ---\n");
            const u_char* arp_data = data;

            unsigned short hardware_type = (arp_data[0] << 8) | arp_data[1];
            unsigned short protocol_type = (arp_data[2] << 8) | arp_data[3];
            unsigned char hardware_size = arp_data[4];
            unsigned char protocol_size = arp_data[5];
            unsigned short opcode = (arp_data[6] << 8) | arp_data[7];

            printf("Hardware Type: %u ", hardware_type);
            printf("%s\n", (hardware_type == 1) ? "(Ethernet)" : "(Other)");

            printf("Protocol Type: 0x%04X ", protocol_type);
            printf("%s\n", (protocol_type == 0x0800) ? "(IPv4)" : "(Other)");

            printf("Hardware Size: %u bytes\n", hardware_size);
            printf("Protocol Size: %u bytes\n", protocol_size);

            printf("Opcode: %u ", opcode);
            if (opcode == 1)
                printf("(ARP Request - Who has this IP?)\n");
            else if (opcode == 2)
                printf("(ARP Reply - I have this IP)\n");
            else
                printf("(Other ARP operation)\n");

            char sender_mac[18];
            sprintf_s(sender_mac, sizeof(sender_mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                arp_data[8], arp_data[9], arp_data[10], arp_data[11], arp_data[12], arp_data[13]);

            char sender_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp_data + 14, sender_ip, sizeof(sender_ip));

            char target_mac[18];
            sprintf_s(target_mac, sizeof(target_mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                arp_data[18], arp_data[19], arp_data[20], arp_data[21], arp_data[22], arp_data[23]);

            char target_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp_data + 24, target_ip, sizeof(target_ip));

            printf("--- ARP Addresses ---\n");
            printf("Sender MAC: %s\n", sender_mac);
            printf("Sender IP: %s\n", sender_ip);
            printf("Target MAC: %s\n", target_mac);
            printf("Target IP: %s\n", target_ip);

            if (opcode == 1) {
                printf("--- ARP Request Explanation ---\n");
                printf("'%s' is asking: 'Who has IP %s? Tell %s'\n",
                    sender_ip, target_ip, sender_ip);
            }
            else if (opcode == 2) {
                printf("--- ARP Reply Explanation ---\n");
                printf("'%s' is saying: 'I have IP %s, my MAC is %s'\n",
                    sender_ip, sender_ip, sender_mac);
            }
        }
        else if (ethernet_type == 0x86DD)
        {
            printf("--- IPv6 Packet ---\n");
            printf("IPv6 detailed analysis not implemented in this version\n");
            printf("Packet contains IPv6 data (128-bit addresses)\n");

            printf("IPv6 Header (first 8 bytes): ");
            for (int i = 0; i < 8 && i < header->len - 14; i++) {
                printf("%02X ", data[i]);
            }
            printf("\n");
        }
        else {
            printf("--- Unknown Protocol ---\n");
            printf("EtherType: 0x%04X\n", ethernet_type);
            printf("This protocol is not analyzed in detail\n");

            printf("Raw Data (first 16 bytes): ");
            for (int i = 0; i < 16 && i < header->len - 14; i++) {
                printf("%02X ", data[i]);
            }
            printf("\n");
        }

        printf("\n");
        printf("========================================\n");
        printf("\n");
    }

    if (res == -1) {
        printf("=== ERROR ===\n");
        printf("Error reading packets: %s\n", pcap_geterr(adhandle));
        printf("Possible causes:\n");
        printf("- Network interface went down\n");
        printf("- Permission denied\n");
        printf("- Driver issues\n");
        return;
    }

    printf("=== CAPTURE ENDED ===\n");
    printf("End of capture reached\n");

    pcap_close(adhandle);
}
