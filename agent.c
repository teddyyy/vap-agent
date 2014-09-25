#include "agent.h"
#include "radiotap.h"
#include "frame.h"

int debug = 0;

static void usage()
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "vap-agent -i <ifacename>\n");
	fprintf(stderr, "-v: outputs debug infomation while running\n");
	fprintf(stderr, "-h: output this usage\n");
	exit(1);
}

static void handle_packet(u_char *argc, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	u16 hlen, pos1, pos2, pos3, b_pos;
	u_int8_t nlen;
	int n80211HeaderLength = HEADERLENGTH;
	int bytes, n, ssid = 0;
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

	// extract subtype from 802.11 header
	if (pkthdr->len >= 24) {
		nlen = pkt[2] + (pkt[3] << 8);

		pos1 = nlen + 4; // frame control + Duration ID
        pos2 = nlen + 10; // frame control + Duration ID + Address 1
        pos3 = nlen + 16; // frame control + Duration ID + Address 1 + Address 2

		switch (pkt[nlen]) {
		case 0x00:
			do_debug("Recdived frame type is association request ");
			print_mgmt_header(pkt, pos1, pos2 ,pos3);
			do_debug("\n");
			break;
		case 0x10:
			do_debug("Recdived frame type is association response ");	
			print_mgmt_header(pkt, pos1, pos2 ,pos3);
			b_pos = nlen + 30;
			ssid = 1;
			break;
		case 0x40:
			do_debug("Recdived frame type is probe request ");	
			print_mgmt_header(pkt, pos1, pos2 ,pos3);
			b_pos = nlen + 24;
			ssid = 1;
			break;
		case 0x50:
			do_debug("Recdived frame type is probe response ");	
			print_mgmt_header(pkt, pos1, pos2 ,pos3);
			b_pos = nlen + 36;
			ssid = 1;
			break;
		case 0x80:
			do_debug("Recdived frame type is beacon ");	
			print_mgmt_header(pkt, pos1, pos2 ,pos3);
			b_pos = nlen + 36;
			ssid = 1;
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

	// extract ssid from 802.11 frame body
	if (ssid)
		essid_print(pkt + b_pos);
}

void* frame_monitor(void* dev)
{
	pcap_t *rpcap = NULL;
	rpcap = create_recv_dev(dev);

	do_debug("Creating frame monitor\n");
	pcap_loop(rpcap, -1, handle_packet, NULL);

	pcap_close(rpcap);

	return 0;
}

void* frame_inject(void* dev)
{
	int total;
	u_char *p;
	u_char buf[sizeof(struct radiotapHeader) 
				+ sizeof(struct ieee80211Header) 
				+ sizeof(struct beaconBody)];

	struct radiotapHeader rth = {
		.version = RTAP_VERSION,
		.hlen = RTAP_HLEN,
		.bitmap = RTAP_BITMAP,
		.timestamp = RTAP_TIMESTAMP,
		.flags = RTAP_FLAGS,
		.rate = RTAP_RATE,
		.channel = RTAP_CHANNEL,
		.signal = RTAP_SIGNAL,
		.noise = RTAP_NOISE,
		.ant = RTAP_ANT,
	};

	struct ieee80211Header i80211h = {
		.fc = 0x8000,
		.duration = IEEEHEADER_DURATION,
		.da[0] = 0x00,
		.da[1] = 0x1f,
		.da[2] = 0x5b,
		.da[3] = 0xcb,
		.da[4] = 0xe8,
		.da[5] = 0xbe,
		.sa[0] = 0x4c,
		.sa[1] = 0xe6,
		.sa[2] = 0x76,
		.sa[3] = 0xf9,
		.sa[4] = 0xa0,
		.sa[5] = 0x51,
		.bssid[0] = 0x4c,
		.bssid[1] = 0xe6,
		.bssid[2] = 0x76,
		.bssid[3] = 0xf9,
		.bssid[4] = 0xa0,
		.bssid[5] = 0x51,
		.seq = IEEEHEADER_SEQ,
	};

	struct beaconBody bbody = {
		.timestamp = BEACON_TIMESTAMP,
		.interval = BEACON_INTERVAL,
		.capinfo = BEACON_CAPINFO,
		.ssid_parm = BEACON_SSID_PARM,
		.ssid_len = 0x04,
		.ssid[0] = 0x68,
		.ssid[1] = 0x6f,
		.ssid[2] = 0x67,
		.ssid[3] = 0x65,
		.rate_parm = BEACON_RATE_PARM,
		.rate_len = BEACON_RATE_LEN,
		.rate = BEACON_RATE,
	};

	pcap_t *spcap = NULL;
	spcap = create_send_dev(dev);

	memset(buf, 0, sizeof(buf));

	p = buf;

	memcpy(p, &rth, sizeof(struct radiotapHeader));
	p += sizeof(struct radiotapHeader);
	memcpy(p, &i80211h, sizeof(struct ieee80211Header));
	p += sizeof(struct ieee80211Header);
	memcpy(p, &bbody, sizeof(struct beaconBody));
	p += sizeof(struct beaconBody);

	total = p - buf;

	while (1) {
 		pcap_inject(spcap, buf, total);
		sleep(0.1);
	}

	pcap_close(spcap);

	return 0;
}

int main(int argc, char *argv[])
{
	int opt;
	char dev[DEVSIZE] = "";
	pthread_t th1, th2;
	
	if (argc <= 1) {
		my_err("Too few options\n");
		usage();
	}

	while ((opt = getopt(argc, argv, "hi:v")) > 0) {
		switch(opt) {
			case 'h':
				usage();
				break;
			case 'i':
				strncpy(dev, optarg, DEVSIZE - 1);
				break;
			case 'v':
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

	// fall into pthread 
	pthread_create(&th1, NULL, frame_monitor, (void*)&dev);
	pthread_create(&th2, NULL, frame_inject, (void*)&dev);

	pthread_join(th1, NULL);
	pthread_join(th2, NULL);
	
	return 0;
}
