#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "net_headers.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>

#include <iostream>
#define UNUSED(x) ((void)(x))

#define PRINT_BYTES_PER_LINE 16




int main(int argc, char* argv[])
{
	int res;

	if ((argc < 3) && !((argc == 2) &&
		(strcmp(argv[1], "--list-devs") == 0)))
	{


		/*printf("Usage: %s device filter\n"
			"       %s --list-devs\n",
			argv[0], argv[0]);*/
		std::cout << "Usage:" << argv[0] << " device filter\n" << argv[0]
			<< " --list-devs";
		//printf("Example: %s eth0 'udp src or dst port 53'\n", argv[0]);
		//printf("%s\n", pcap_lib_version());
		std::cout << "Example: " << argv[0] << " eth0 'udp src or dst port 53'\n";
		std::cout << argv[0] << "]n";
		return 1;
	}

	if (argc == 2)
	{
		list_devs(); //! write the list of devs, if we enter ./execute_name + '--list-devs'
		return 0;
	}

	const char* device = argv[1];
	const char* filter = argv[2];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* pcap = pcap_open_live(device, 65535, 1, 100, errbuf);
	if (pcap == NULL)
	{
		//fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
		std::cerr << "pcap_open_live failed: " << errbuf << "\n";
		return 1;
	}

	struct bpf_program filterprog;
	res = pcap_compile(pcap, &filterprog, filter, 0,
		PCAP_NETMASK_UNKNOWN);
	if (res != 0)
	{
		/*fprintf(stderr, "pcap_compile failed: %s\n",
			pcap_geterr(pcap));*/
		std::cerr << "pcap_compile failed: " << pcap_geterr(pcap) << "\n";
		pcap_close(pcap);
		return 1;
	}

	res = pcap_setfilter(pcap, &filterprog);
	if (res != 0)
	{
		/*fprintf(stderr, "pcap_setfilter failed: %s\n",
			pcap_geterr(pcap));*/
		std::cerr << "pcap_setfilter failed: " << pcap_geterr(pcap) << "\n";
		pcap_close(pcap);
		return 1;
	}

	//printf("Listening %s, filter: %s...\n", device, filter);
	std::cout << "Listening " << device << ", filter: " << filter << "...\n";

	res = pcap_loop(pcap, -1, handle_packet, NULL);
	//printf("pcap_loop returned %d\n", res);
	std::cout << "pcap_loop returned " << res << "\n";

	pcap_close(pcap);
	return 0;
}
