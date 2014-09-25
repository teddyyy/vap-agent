#define	IEEE802_11_TSTAMP_LEN	8 
#define SSID_MAXLEN				4

#define RTAP_VERSION			0x0000
#define RTAP_HLEN				0x1900
#define RTAP_BITMAP				0x00000000
#define RTAP_TIMESTAMP			0x0000000000000000
#define RTAP_FLAGS				0x00
#define RTAP_RATE				0x00
#define RTAP_CHANNEL			0x00000000
#define RTAP_SIGNAL				0x00
#define RTAP_NOISE				0x00
#define RTAP_ANT				0x00

#define IEEEHEADER_DURATION		0x0000
#define IEEEHEADER_SEQ			0x1086

#define BEACON_TIMESTAMP		0x0000000000000000
#define BEACON_INTERVAL			0x6600
#define BEACON_CAPINFO			0x2100
#define BEACON_SSID_PARM		0x0000
#define BEACON_RATE_PARM		0x0001
#define BEACON_RATE_LEN			0x0008
#define BEACON_RATE				0x8c129824b048606c

struct radiotapHeader {
    uint16_t version;
    uint16_t hlen;
    uint32_t bitmap;
    uint64_t timestamp;
    uint8_t flags;
    uint8_t rate;
    uint32_t channel;
    uint8_t signal;
    uint8_t noise;
    uint8_t ant;
} __attribute__((packed));

struct ieee80211Header {
    uint16_t fc; 
    uint16_t duration;
    uint8_t da[6];
    uint8_t sa[6];
    uint8_t bssid[6];
    uint16_t seq;
} __attribute__((packed));

struct beaconBody {
	uint64_t timestamp;	
	uint16_t interval;
	uint16_t capinfo;
	uint8_t ssid_parm;
	uint8_t ssid_len;
	u_char ssid[SSID_MAXLEN];
	uint8_t rate_parm;
	uint8_t rate_len;
	uint64_t rate;
}__attribute__((packed));
