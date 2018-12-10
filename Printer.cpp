#include "Printer.h"

void print_data_hex(const uint8_t* data, int size)
{
    int offset = 0;
    int nlines = size / PRINT_BYTES_PER_LINE;
    if(nlines * PRINT_BYTES_PER_LINE < size)
        nlines++;

    printf("        ");

    for(int i = 0; i < PRINT_BYTES_PER_LINE; i++)
        printf("%02X ", i);

    printf("\n\n");

    for(int line = 0; line < nlines; line++)
    {
        printf("%04X    ", offset);
        for(int j = 0; j < PRINT_BYTES_PER_LINE; j++)
        {
            if(offset + j >= size)
                printf("   ");
            else
                printf("%02X ", data[offset + j]);
        }

        printf("   ");

        for(int j = 0; j < PRINT_BYTES_PER_LINE; j++)
        {
            if(offset + j >= size)
                printf(" ");
            else if(data[offset + j] > 31 && data[offset + j] < 127)
                printf("%c", data[offset + j]);
            else
                printf(".");
        }

        offset += PRINT_BYTES_PER_LINE;
        printf("\n");
    }
}

void list_devs() {
    int errcode;
    pcap_if_t *alldevs, *currdev;
    char errbuff[PCAP_ERRBUF_SIZE];

    errcode = pcap_findalldevs(&alldevs, errbuff);
    /* Each element of the list is of type pcap_if_t, and has the following members:
next
if not NULL, a pointer to the next element in the list; NULL for the last element of the list
name
a pointer to a string giving a name for the device to pass to pcap_open_live()
description
if not NULL, a pointer to a string giving a human-readable description of the device
addresses
a pointer to the first element of a list of network addresses for the device, or NULL if the device has no addresses
flags
     */
    if (errcode != 0) {
        fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuff);
        return;
    }

    currdev = alldevs;

    while (currdev) {
        printf("%s\t%s\n", currdev->name,
               currdev->description ? currdev->description :
               "(no description)"
        );
        currdev = currdev->next;
    }

    if (alldevs)
        pcap_freealldevs(alldevs);
    //! free the pointer
}