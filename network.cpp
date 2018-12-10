

#include "network.h"
#include "Printer.h"


void handle_packet(uint8_t* user, const struct pcap_pkthdr *hdr,
                          const uint8_t* bytes)
{
//    UNUSED(user);

    auto * ip_header = (struct iphdr*)(bytes + sizeof(struct ethhdr));



    sockaddr_in  source, dest;

//    memset(&source, 0, sizeof(source));
//    memset(&dest, 0, sizeof(dest));
//    source.sin_addr.s_addr = ip_header->saddr;
//    dest.sin_addr.s_addr = ip_header->daddr;

    char source_ip[128];
    char dest_ip[128];
    strncpy(source_ip, inet_ntoa(source.sin_addr), sizeof(source_ip));
    strncpy(dest_ip, inet_ntoa(dest.sin_addr), sizeof(dest_ip));

    int source_port = 0;
    int dest_port = 0;
    int data_size = 0;
    int ip_header_size = ip_header->ihl * 4;
    char* next_header = (char*)ip_header + ip_header_size;

    if(ip_header->protocol == IP_HEADER_PROTOCOL_TCP)
    {
         tcphdr* tcp_header = (struct tcphdr*)next_header;
        source_port = ntohs(tcp_header->source);
        dest_port = ntohs(tcp_header->dest);
        int tcp_header_size = tcp_header->doff * 4;
        data_size = hdr->len - sizeof(struct ethhdr) -
                    ip_header_size - tcp_header_size;
    }
    else if(ip_header->protocol == IP_HEADER_PROTOCOL_UDP)
    {
         udphdr* udp_header = (struct udphdr*)next_header;
        source_port = ntohs(udp_header->source);
        dest_port = ntohs(udp_header->dest);
        data_size = hdr->len - sizeof(struct ethhdr) -
                    ip_header_size - sizeof(struct udphdr);
    }

    printf("\n%s:%d -> %s:%d, %d (0x%x) bytes\n\n",
           source_ip,
           source_port,
           dest_ip,
           dest_port,
           data_size,
           data_size);
    char saddr[INET_ADDRSTRLEN];
    char daddr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->saddr), saddr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), daddr, INET_ADDRSTRLEN);
    cout<<"ip saddr: \n"<<saddr<<endl<<"ip daddr:"<<daddr<<endl;
    cout<<

    if(data_size > 0)
    {
        int headers_size = hdr->len - data_size;
        print_data_hex(bytes + headers_size, data_size);
    }
}
