#include "agent.h"
#include "radiotap.h"

extern void do_debug(char *msg, ...);
extern void my_err(char *msg, ...);

typedef struct  {
    int m_nChannel;
    int m_nChannelFlags;
    int m_nRate;
    int m_nRadiotapFlags;
	int8_t m_ndBmsignal;
	int8_t m_ndBmnoise;
} __attribute__((packed)) PENUMBRA_RADIOTAP_DATA;

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
	u16 hlen;
	u_int8_t nlen;
	int n80211HeaderLength = 0x18;
	int bytes, n;
	PENUMBRA_RADIOTAP_DATA prd;
	struct ieee80211_radiotap_iterator rti;

	hlen = pkt[2] + (pkt[3] << 8);
	nlen = hlen;

	if (pkthdr->len >= 24) {

		switch (pkt[nlen]) {
			case 0x00:
				do_debug("Recdived frame type is association request\n");	
				break;
			case 0x10:
				do_debug("Recdived frame type is association response\n");	
				break;
			case 0x40:
				do_debug("Recdived frame type is probe request\n");	
				break;
			case 0x50:
				do_debug("Recdived frame type is probe response\n");	
				break;
			case 0x80:
				do_debug("Recdived frame type is beacon\n");	
				break;
			case 0xB0:
				do_debug("Recdived frame type is authentication\n");	
				break;
			default:
				do_debug("Unknown frame type\n");
				break;
		}
	}

	bytes = pkthdr->len - (hlen + n80211HeaderLength);

	ieee80211_radiotap_iterator_init(&rti, (struct ieee80211_radiotap_header *)pkt, bytes);

	while ((n = ieee80211_radiotap_iterator_next(&rti)) == 0) {

            switch (rti.this_arg_index) {
            case IEEE80211_RADIOTAP_RATE:
                prd.m_nRate = (*rti.this_arg);
                break;

            case IEEE80211_RADIOTAP_CHANNEL:
                prd.m_nChannel = le16_to_cpu(*((u16 *)rti.this_arg));
                prd.m_nChannelFlags = le16_to_cpu(*((u16 *)(rti.this_arg + 2)));
                break;

            case IEEE80211_RADIOTAP_FLAGS:
                prd.m_nRadiotapFlags = (*rti.this_arg);
                break;

			case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
				prd.m_ndBmsignal = (*rti.this_arg);
				break;

			case IEEE80211_RADIOTAP_DBM_ANTNOISE:
				prd.m_ndBmnoise = (*rti.this_arg);
				break;

            }
	}

	printf("RX: Rate: %2d.%dMbps, Freq: %dMHz, Flags: 0x%X	",
            prd.m_nRate / 2, 5 * (prd.m_nRate & 1),
            prd.m_nChannel,
            prd.m_nRadiotapFlags);
	printf("signal: %ddBm	noise:  %ddBm\n", prd.m_ndBmsignal, prd.m_ndBmnoise);

/*	
	if (pkthdr->len >= 24) {
		hlen = pkt[2] + (pkt[3] << 8);
*/
		
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
