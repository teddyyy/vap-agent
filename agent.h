#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <pcap.h>
#include <endian.h>
#include <stdint.h>

#define DEVSIZE 16
#define HEADERLENGTH 0x18
extern int debug;

typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef u32 __le32;

typedef struct  {
    int m_nChannel;
    int m_nRate;
    int8_t m_ndBmsignal;
    int8_t m_ndBmnoise;
} __attribute__((packed)) PENUMBRA_RADIOTAP_DATA;

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#else
#define le16_to_cpu(x) ((((x)&0xff)<<8)|(((x)&0xff00)>>8))
#define le32_to_cpu(x) \
((((x)&0xff)<<24)|(((x)&0xff00)<<8)|(((x)&0xff0000)>>8)|(((x)&0xff000000)>>24))
#endif
#define unlikely(x) (x)
