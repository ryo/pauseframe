#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/bpf.h>

static int opt_v;

static unsigned char pauseframe[] = {
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x01,	/* dst mac */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* src mac */
	0x88, 0x08,				/* ethernet type */
	0x00, 0x01,				/* opcode */
	0x00, 0x01,				/* duration */
	/* 42byte padding */
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00
};

static void
usage()
{
	fprintf(stderr, "usage: pauseframe [option]\n");
	fprintf(stderr, "	-i <interface>	output interface\n");
	fprintf(stderr, "	-d <duration>	duration. default is 1\n");
	fprintf(stderr, "	-v		verbose\n");
	exit(1);
}

int
bpf_open(const char *ifname)
{
	struct bpf_version bv;
	struct ifreq ifr;
	int fd, n;
	char devbpf[sizeof "/dev/bpf0000000000000"];

	n = 0;
	do {
		(void)snprintf(devbpf, sizeof devbpf, "/dev/bpf%d", n++);
		fd = open(devbpf, O_WRONLY);
	} while (fd < 0 && errno == EBUSY);

	if (fd < 0) { 
		warn("open");
		goto failure;
	}

	if (ioctl(fd, BIOCVERSION, (caddr_t)&bv) < 0) {
		warn("ioctl: BIOCVERSION");
		goto failure;
	}

	if (bv.bv_major != BPF_MAJOR_VERSION ||
	    bv.bv_minor < BPF_MINOR_VERSION) {
		warnx("kernel bpf filter out of date");
		goto failure;
	}

	(void)strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, BIOCSETIF, (caddr_t)&ifr) < 0) {
		warn("ioctl: BIOCSETIF: %s", ifname);
		goto failure;
	}

	return fd;

 failure:
	if (fd >= 0)
		(void)close(fd);
	return -1;
}

int
main(int argc, char *argv[])
{
	ssize_t r;
	int bpf_fd, ch;
	uint16_t duration = 1;
	char *ifname = NULL;

	while ((ch = getopt(argc, argv, "d:i:v")) != -1) {
		switch (ch) {
		case 'd':
			duration = strtol(optarg, NULL, 10);
		case 'i':
			ifname = optarg;
			break;
		case 'v':
			opt_v++;
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	bpf_fd = bpf_open(ifname);
	if (bpf_fd < 0)
		exit(2);

	/* set duration */
	pauseframe[16] = duration >> 8;
	pauseframe[17] = duration & 0xff;

	r = write(bpf_fd, pauseframe, sizeof(pauseframe));
	if (r < 0)
		err(3, "write");
	if (opt_v)
		printf("writing %llu bytes\n", (unsigned long long)r);

	exit(0);
}
