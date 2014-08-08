#include "agent.h"

extern void do_debug(char *msg, ...);
extern void my_err(char *msg, ...);

int debug = 0;

void usage()
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "vap-agent -i <ifacename>\n");
	fprintf(stderr, "-d: outputs debug infomation while running\n");
	fprintf(stderr, "-h: output this usage\n");
	exit(1);
}

void process_packet(u_char *argc, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	do_debug("Received packet size: %d\n", pkthdr->len);
}

int main(int argc, char *argv[])
{
	int opt;
	char dev[DEVSIZE] = "";
	pcap_t *ppcap = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (argc <= 1) {
		my_err("Too few options\n");
		usage();
	}

	while ((opt = getopt(argc, argv, "hi:d")) > 0) {
		switch(opt) {
			case 'h':
				usage();
				break;
			case 'i':
				strncpy(dev, optarg, DEVSIZE - 1);
				break;
			case 'd':
				debug = 1;
				break;
			default:
				my_err("Unknown option %c\n", opt);
				usage();
		}
	}
	
	argv += optind;
	argc -= optind;

	if (argc > 0) {
		my_err("Too many options\n");
		usage();
	}

	if (*dev == '\0') {
		usage();
	}

	do_debug("Creating socket at %s \n", dev);

	// open interface in pcap
	ppcap = pcap_open_live(dev, 800, 1, 20, errbuf);
    if (ppcap == NULL) {
        my_err("Unable to open interface %s in pcap: %s\n", dev, errbuf);
        return -1;
    }   

	// check data link type
	if (pcap_datalink(ppcap) != DLT_IEEE802_11_RADIO) {
		my_err("Device %s doesn't provide 802.11 Radiotap haders\n", dev);
		return -1;
	}

	// set nonblock mode
	if (pcap_setnonblock(ppcap, 1, errbuf) == -1) {
		my_err("Device %s doesn't set non-blocking mode\n", dev);
		return -1;
	}
	
	// fall into pcap loop
	pcap_loop(ppcap, -1, process_packet,NULL);

	pcap_close(ppcap);
	
	return 0;
}
