#define SSID_MAXLEN 			32  
#define	IEEE802_11_TSTAMP_LEN	8
#define IEEE802_11_AP_LEN       6  /* Current AP Address */

typedef enum {
	NOT_PRESENT,
	PRESENT,
	TRUNCATED
} elem_status_t;

struct ssid_t {
	u_int8_t	element_id;
	u_int8_t	length;
	u_char		ssid[SSID_MAXLEN+1];  /* +1 for null terminator */
};

struct rates_t {
	u_int8_t	element_id;
	u_int8_t	length;
	u_int8_t	rate[16];
};

struct challenge_t {
	u_int8_t	element_id;
	u_int8_t	length;
	u_int8_t	text[254]; /* 1-253 + 1 for null */
};

struct fh_t {
	u_int8_t	element_id;
	u_int8_t	length;
	u_int16_t	dwell_time;
	u_int8_t	hop_set;
	u_int8_t 	hop_pattern;
	u_int8_t	hop_index;
};

struct ds_t {
	u_int8_t	element_id;
	u_int8_t	length;
	u_int8_t	channel;
};

struct cf_t {
	u_int8_t	element_id;
	u_int8_t	length;
	u_int8_t	count;
	u_int8_t	period;
	u_int16_t	max_duration;
	u_int16_t	dur_remaing;
};

struct tim_t {
	u_int8_t	element_id;
	u_int8_t	length;
	u_int8_t	count;
	u_int8_t	period;
	u_int8_t	bitmap_control;
	u_int8_t	bitmap[251];
};

struct mgmt_body_t {
	u_int8_t   	timestamp[IEEE802_11_TSTAMP_LEN];
	u_int16_t  	beacon_interval;
	u_int16_t 	listen_interval;
	u_int16_t 	status_code;
	u_int16_t 	aid;
	u_char		ap[IEEE802_11_AP_LEN];
	u_int16_t	reason_code;
	u_int16_t	auth_alg;
	u_int16_t	auth_trans_seq_num;
	elem_status_t	challenge_status;
	struct challenge_t  challenge;
	u_int16_t	capability_info;
	elem_status_t	ssid_status;
	struct ssid_t	ssid;
	elem_status_t	rates_status;
	struct rates_t 	rates;
	elem_status_t	ds_status;
	struct ds_t	ds;
	elem_status_t	cf_status;
	struct cf_t	cf;
	elem_status_t	fh_status;
	struct fh_t	fh;
	elem_status_t	tim_status;
	struct tim_t	tim;
};

