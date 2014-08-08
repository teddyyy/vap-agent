#include "agent.h"

extern void do_debug(char *msg, ...);
extern void my_err(char *msg, ...);

int debug = 0;

void usage()
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "vap-agent -i <ifacename>\n");
	fprintf(stderr, "-d: outputs debug infomation while running\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	int opt;
	char dev[DEVSIZE] = "";

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

	do_debug("%s \n", dev);

	return 0;
}
