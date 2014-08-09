#include "agent.h"
#include "radiotap.h"

extern void do_debug(char *msg, ...);
extern void my_err(char *msg, ...);

typedef struct  {
    int m_nChannel;
    int m_nRate;
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

void bssid_found(const u_char *bssid)
{
    printf("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx ",
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
}

void print_mgmt_header(const u_char *pkt, 
            u_int8_t pos1, u_int8_t pos2, u_int8_t pos3)
{
    printf("DA:");
    bssid_found(pkt + pos1);
    printf("SA:");
    bssid_found(pkt + pos2);
    printf("BSSID:");
    bssid_found(pkt + pos3);
}


void process_packet(u_char *argc, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	u16 hlen, pos1, pos2, pos3;
	u_int8_t nlen;
	int n80211HeaderLength = 0x18;
	int bytes, n;
	PENUMBRA_RADIOTAP_DATA prd;
	struct ieee80211_radiotap_iterator rti;
	const u_char *rtpkt = pkt;

	// extract radiotap headder
	// based on packetspammer by andy green
	hlen = rtpkt[2] + (rtpkt[3] << 8);
	
	bytes = pkthdr->len - (hlen + n80211HeaderLength);

	ieee80211_radiotap_iterator_init(&rti, (struct ieee80211_radiotap_header *)rtpkt, bytes);

	while ((n = ieee80211_radiotap_iterator_next(&rti)) == 0) {

            switch (rti.this_arg_index) {
            case IEEE80211_RADIOTAP_RATE:
                prd.m_nRate = (*rti.this_arg);
                break;

            case IEEE80211_RADIOTAP_CHANNEL:
                prd.m_nChannel = le16_to_cpu(*((u16 *)rti.this_arg));
                break;
	
			case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
				prd.m_ndBmsignal = (*rti.this_arg);
				break;

			case IEEE80211_RADIOTAP_DBM_ANTNOISE:
				prd.m_ndBmnoise = (*rti.this_arg);
				break;

            }
	}

	do_debug("RX: Rate: %2d.%dMbps, Freq: %dMHz, Signal:% ddBm, Noise: %ddBm	",
            prd.m_nRate / 2, 5 * (prd.m_nRate & 1), prd.m_nChannel,prd.m_ndBmsignal, prd.m_ndBmnoise);

	// extract 802.11 header
	if (pkthdr->len >= 24) {
		nlen = pkt[2] + (pkt[3] << 8);

		pos1 = hlen + 4;
        pos2 = hlen + 10; 
        pos3 = hlen + 16; 

		switch (pkt[nlen]) {
		case 0x00:
			do_debug("Recdived frame type is association request ");
			print_mgmt_header(pkt, pos1, pos2 ,pos3);
			do_debug("\n");
			break;
		case 0x10:
			do_debug("Recdived frame type is association response ");	
			print_mgmt_header(pkt, pos1, pos2 ,pos3);
			do_debug("\n");
			break;
		case 0x40:
			do_debug("Recdived frame type is probe request ");	
			print_mgmt_header(pkt, pos1, pos2 ,pos3);
			do_debug("\n");
			break;
		case 0x50:
			do_debug("Recdived frame type is probe response ");	
			print_mgmt_header(pkt, pos1, pos2 ,pos3);
			do_debug("\n");
			break;
		case 0x80:
			do_debug("Recdived frame type is beacon ");	
			print_mgmt_header(pkt, pos1, pos2 ,pos3);
			do_debug("\n");
			break;
		case 0xB0:
			do_debug("Recdived frame type is authentication ");	
			print_mgmt_header(pkt, pos1, pos2 ,pos3);
			do_debug("\n");
			break;
		case 0xD4:
			do_debug("Recdived frame type is ack\n");	
			break;
		case 0x08:
			do_debug("Recdived frame type is data\n");	
			break;
		case 0x48:
			do_debug("Recdived frame type is null\n");	
			break;
		default:
			do_debug("Unknown frame type is %x\n", pkt[nlen]);
			break;
		}
	}
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
