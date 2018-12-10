#pragma once

#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "net_headers.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <iostream>

//#define UNUSED(x) ((void)(x));

void handle_packet(uint8_t* user, const struct pcap_pkthdr *hdr, const uint8_t* bytes);

/*
 * pcap_pkthdr, which includes the following members:
ts
a struct timeval containing the time when the packet was captured
caplen
a bpf_u_int32 giving the number of bytes of the packet that are available from the capture
len
a bpf_u_int32 giving the length of the packet, in bytes (which might be more than the number
 of bytes available from the capture, if the length of the packet is larger than the maximum number of bytes to capture).
 *
 */


