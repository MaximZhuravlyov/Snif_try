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

using namespace std;
#define PRINT_BYTES_PER_LINE 16

 void print_data_hex(const uint8_t* data, int size);

void list_devs();
