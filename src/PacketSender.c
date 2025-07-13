#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

void run_packet_sender(const char* iface) {
    printf("run_packet_sender başladı. Interface: %s\n", iface);

    pcap_t* fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char packet[128];
    int packet_len = 0;

    fp = pcap_open(
        iface,
        128,
        PCAP_OPENFLAG_PROMISCUOUS,
        1000,
        NULL,
        errbuf
    );

    if (fp == NULL) {
        fprintf(stderr, "\nArayüz açılamadı: %s\n", errbuf);
        return;
    }

    packet[0] = 0x01; packet[1] = 0x01; packet[2] = 0x01;
    packet[3] = 0x01; packet[4] = 0x01; packet[5] = 0x01;

    packet[6] = 0x02; packet[7] = 0x02; packet[8] = 0x02;
    packet[9] = 0x02; packet[10] = 0x02; packet[11] = 0x02;

    packet[12] = 0x08;
    packet[13] = 0x00;

    packet_len = 14;

    packet[14] = 0x45;
    packet[15] = 0x00;
    packet[16] = 0x00;
    packet[17] = 0x3C;
    packet[18] = 0x00; packet[19] = 0x00;
    packet[20] = 0x40;
    packet[21] = 0x00;
    packet[22] = 0x40;
    packet[23] = 0x11;
    packet[24] = 0x00; packet[25] = 0x00;

    packet[26] = 192;
    packet[27] = 168;
    packet[28] = 1;
    packet[29] = 10;

    packet[30] = 192;
    packet[31] = 168;
    packet[32] = 1;
    packet[33] = 10;

    packet_len += 20;

    packet[34] = 0x04; packet[35] = 0x00;
    packet[36] = 0x08; packet[37] = 0x00;
    packet[38] = 0x00; packet[39] = 0x28;
    packet[40] = 0x00; packet[41] = 0x00;

    packet_len += 8;

    for (int i = 0; i < 32; i++) {
        packet[42 + i] = (u_char)i;
    }

    packet_len += 32;

    if (pcap_sendpacket(fp, packet, packet_len) != 0) {
        fprintf(stderr, "\nPaket gönderilirken hata oluştu: %s\n", pcap_geterr(fp));
    }
    else {
        printf("Paket başarıyla gönderildi!\n");
    }

    pcap_close(fp);
}
