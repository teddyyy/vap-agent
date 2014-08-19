#define	IEEE802_11_TSTAMP_LEN		8  /* Timestamp */
#define SSID_MAXLEN 				32

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
	uint8_t timestamp[IEEE802_11_TSTAMP_LEN];	
	uint16_t interval;
	uint16_t capinfo;
	uint8_t ssid_parm;
	uint8_t ssid_len;
	u_char ssid[SSID_MAXLEN + 1];
	uint8_t rate_parm;
	uint8_t rate_len;
	uint8_t rate[16];
};
