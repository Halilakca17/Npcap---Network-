#include <stdio.h>
#include <string.h>
#include "Filtering.h"
#include "GatheringStatistic.h"
#include "InterPackets.h"
#include "ObtainingDevice.h"
#include "OpeningAdapterAndCapture.h"
#include "ReadingDumpFiles.h"
#include "SavingDumpFiles.h"
#include "SendingQueue.h"
#include "PacketSender.h"

int main() {
    int secim;
    char param1[256], param2[256];
    int sync;
    while (1) {
        printf("\nModül Seçin:\n");
        printf("1. Filtering\n");
        printf("2. Gathering Statistic\n");
        printf("3. Inter Packets\n");
        printf("4. Obtaining Device\n");
        printf("5. Opening Adapter and Capture\n");
        printf("6. Reading Dump Files\n");
        printf("7. Saving Dump Files\n");
        printf("8. Sending Packet\n");
        printf("9. Sending Queue\n");
        printf("0. Exit\n");
        printf("Seçiminiz: ");
        scanf_s("%d", &secim);
        getchar(); 
        switch (secim) {
            case 1:
                run_filtering();
                break;
            case 2:
                printf("Adapter adı girin: ");
                fgets(param1, sizeof(param1), stdin);
                param1[strcspn(param1, "\n")] = 0;
                run_gathering_statistic(param1);
                break;
            case 3:
                run_inter_packets();
                break;
            case 4:
                run_obtaining_device();
                break;
            case 5:
                run_opening_adapter_and_capture();
                break;
            case 6:
                printf("Dump dosya adı girin: ");
                fgets(param1, sizeof(param1), stdin);
                param1[strcspn(param1, "\n")] = 0;
                run_reading_dump_files(param1);
                break;
            case 7:
                printf("Kaydedilecek dump dosya adı girin: ");
                fgets(param1, sizeof(param1), stdin);
                param1[strcspn(param1, "\n")] = 0;
                run_saving_dump_files(param1);
                break;
            case 8:
                printf("Interface adı girin: ");
                fgets(param1, sizeof(param1), stdin);
                param1[strcspn(param1, "\n")] = 0;
                run_packet_sender(param1);
                break;
            case 9:
                printf("Pcap dosya adı girin: ");
                fgets(param1, sizeof(param1), stdin);
                param1[strcspn(param1, "\n")] = 0;
                printf("Adapter adı girin: ");
                fgets(param2, sizeof(param2), stdin);
                param2[strcspn(param2, "\n")] = 0;
                printf("Senkronize gönderim? (1=Evet, 0=Hayır): ");
                scanf_s("%d", &sync);
                getchar();
                run_sending_queue(param1, param2, sync);
                break;
            case 0:
                return 0;
            default:
                printf("Geçersiz seçim!\n");
        }
    }
    return 0;
}
