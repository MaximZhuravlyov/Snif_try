#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <iostream>

#include "net_headers.h"
#include "network.h"
#include "Printer.h"

using namespace std;

//#define UNUSED(x) ((void)(x))


int main(int argc, char *argv[]) {
    int res;

    if ((argc < 3) && !((argc == 2) &&
                        (strcmp(argv[1], "--list-devs") == 0))) {
        cout << "Usage: " << argv[0] << "\t" << "device filter\n";
        cout << "Use " << argv[0] << "\"--list-devs\" to watch the list of devices\n";

        char errbuff[PCAP_ERRBUF_SIZE];
        string dev_name = "wlp3s0";

        char *string1 = pcap_lookupdev(errbuff); // find one device from the list of devices
        if (string1 != nullptr) {
            dev_name = string1;
        }


        cout << "Example: " << argv[0] << " " << dev_name << " udp src or dst port 80\n";
        cout << pcap_lib_version() << endl;
        return 1;
    }

    if (argc == 2) {
        list_devs(); //! write the list of devs, if we enter ./execute_name + '--list-devs'
        return 0;
    }

    const char *device = argv[1];
    const char *filter = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE]; //! 256 bytes

    pcap_t *pcap = pcap_open_live(device, 65535, 1, 100, errbuf);
    if (pcap == nullptr) {
        cerr << "pcap_open_live failed: " << errbuf << endl;
        return 1;
    }

    bpf_program filterprog;
    res = pcap_compile(pcap, &filterprog, filter, 0,
                       PCAP_NETMASK_UNKNOWN);
    /*
     * If the netmask of the network on which packets are being captured isn't known to the program,
     * or if packets are being captured on the Linux "any"
     * pseudo-interface that can capture on more than one network,
     * a value of PCAP_NETMASK_UNKNOWN can be supplied;*/
    if (res != 0) {
        cerr << "pcap_compile failed: " << pcap_geterr(pcap) << endl;
        pcap_close(pcap);
        return 1;
    }

    res = pcap_setfilter(pcap, &filterprog);
    if (res != 0) {
        cerr << "pcap_setfilter failed: " << pcap_geterr(pcap) << endl;

        pcap_close(pcap);
        return 1;
    }

    // do we need it now to free up allocated memory pointed to by a bpf_program struct generated
    // pcap_freecode(&filterprog);

    cout << "Listening , filter: " << device << filter << endl;

    res = pcap_loop(pcap, -1, handle_packet, nullptr);

    cout << "pcap_loop returned " << res << "\n";

    pcap_close(pcap);
    return 0;
}