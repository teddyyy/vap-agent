#include "agent.h"

extern void my_err(char *msg, ...);

extern pcap_t* create_recv_dev(char *dev)
{
	pcap_t *ppcap = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	// open interface in pcap
	ppcap = pcap_open_live(dev, 800, 1, 20, errbuf);
    if (ppcap == NULL) {
        my_err("Unable to open interface %s in pcap: %s\n", dev, errbuf);
        exit (-1);
    }    

	// check data link type
    if (pcap_datalink(ppcap) != DLT_IEEE802_11_RADIO) {
        my_err("Device %s doesn't provide 802.11 Radiotap haders\n", dev);
        exit (-1);
    }

	// set nonblock mode
    if (pcap_setnonblock(ppcap, 1, errbuf) == -1) {
        my_err("Device %s doesn't set non-blocking mode\n", dev);
        exit (-1);
    }

	return ppcap;
}

extern pcap_t* create_send_dev(char *dev)
{
	pcap_t *ppcap = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	ppcap = pcap_open_live(dev, 800, 1, 20, errbuf);
    if (ppcap == NULL) {
        my_err("Unable to open interface %s in pcap: %s\n", dev, errbuf);
        exit (-1);
    }    

	return ppcap;
}
