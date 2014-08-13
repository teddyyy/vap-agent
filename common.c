#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include "agent.h"

#define SSIDPARAM 0x00
#define SSIDLENGTH 0x01

void essid_print(const u_char *d)
{
	int len, i = 2;

	if (d[0] == SSIDPARAM && d[1] != SSIDLENGTH) {
		printf("length:%d ", d[1]);
		len = d[1];		
		for (i = 2; i <= len + 1; i++) {
			printf("%c", d[i]);
		}
		printf("\n");
	}
}

static void ether_ntoa_r(const u_char *bssid)
{
    printf("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx ",                                                                                  
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
}

extern void print_mgmt_header(const u_char *pkt, 
            u_int8_t pos1, u_int8_t pos2, u_int8_t pos3)
{
    printf("DA:");
    ether_ntoa_r(pkt + pos1);
    printf("SA:");
    ether_ntoa_r(pkt + pos2);
    printf("BSSID:");
    ether_ntoa_r(pkt + pos3);
}

extern void do_debug(char *msg, ...)
{
    va_list args;

    if (debug) {
        va_start(args, msg);
        vfprintf(stdout, msg, args);
        va_end(args);
    }
}

extern void do_perror(char *msg)
{
    if (debug) {
        fprintf(stderr, "%s : %s\n", msg, strerror(errno));
    }
}

extern void my_err(char *msg, ...)                                                                          
{
    va_list args;
    
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);
}
