/*
  $Id: dns_replay3.c,v 1.4 2013/03/12 18:51:29 fujiwara Exp $

  Copyright (C) 1998-2006 Kazunori Fujiwara <fujiwara@wide.ad.jp>.
  All rights reserved.

  You can redistribute it and/or modify it
  under either the terms of the GPL version 2.
  GPL is shown in <http://www.gnu.org/licenses/gpl.html>.

  How to complile:
Solaris 10:	gcc -O -o dns_replay2 -DNO_ERR dns_replay2.c -lsocket -lresolv -lnsl
BSD:		cc -O -o dns_replay2 dns_replay.c
 */

/*
#define USE_KQUEUE
*/

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdarg.h>

#ifndef NO_ERR
#include <err.h>
#endif

#ifdef USE_KQUEUE
#include <sys/event.h>
#else
#ifndef NO_SYS_SELECT_H
#include <sys/select.h>
#endif
#endif

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <errno.h>

#ifdef __APPLE__
#include <nameser8_compat.h>
#endif

int Xerror[256];
int SendCount = 0;
int RecvCount = 0;

struct addr46 {
	int len;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin4;
		struct sockaddr_in6 sin6;
	} u;
};

#ifdef NO_ERR
void err(int err, char *format, ...)
{
	va_list ap; va_start(ap, format);
	(void) vfprintf(stderr, format, ap);
	va_end(ap);
	(void)exit(err);
}
#endif

int ipaddr2sockaddr(struct addr46 *a, char *addr, char *port)
{
	char *p;
	int len;
	int nport;
	char buff[64];

	bzero(a, sizeof(struct addr46));
	if ((p = strchr(addr, '/')) != NULL) {
		len = p - addr;
		if (len >= sizeof(buff))
			len = sizeof(buff) - 1;
		memcpy(buff, addr, len);
		buff[len] = 0;
		port = p + 1;
		addr = buff;
	}
	if (port == NULL || *port == 0) {
		nport = 53;
	} else {
		nport = atoi(port);
	}
	if (inet_pton(AF_INET, addr, (char *)&a->u.sin4.sin_addr)) {
		a->u.sin4.sin_port = htons(nport);
		a->u.sin4.sin_family = AF_INET;
		a->len = sizeof(struct sockaddr_in);
		return 1;
	} else
	if (inet_pton(AF_INET6, addr, (char *)&a->u.sin6.sin6_addr)) {
		a->u.sin6.sin6_port = htons(nport);
		a->u.sin6.sin6_family = AF_INET6;
		a->len = sizeof(struct sockaddr_in6);
		return 1;
	}
	return 0;
}

#ifdef DEBUG
void HexDump(char *str, unsigned char *buf, int len)
{
	int i;

	printf("%s [", str);
	for (i = 0; i < len; i++) {
		printf("%02x ", buf[i]);
	}
	printf("]\n");
}
#endif

long long NOW(void)
	struct timeval _current;

	gettimeofday(&_current, NULL);
	return _current.tv_sec * 1000000LL + _current.tv_usec;
}

#define PCAP_MAGIC 0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

struct pcap_file_header {
	u_int32_t magic;
	u_short version_major;
	u_short version_minor;
	int32_t thiszone;	/* gmt to local correction */
	u_int32_t sigfigs;	/* accuracy of timestamps */
	u_int32_t snaplen;	/* max length saved portion of each pkt */
	u_int32_t linktype;	/* data link type (LINKTYPE_*) */
};

struct pcap_header {
	struct pcap_timeval {
		u_int32_t tv_sec;	/* seconds */
		u_int32_t tv_usec;	/* microseconds */
	} ts;				/* time stamp */
	int32_t caplen;	/* length of portion present */
	int32_t len;	/* length this packet (off wire) */
};
#define DLT_NULL	0	/* BSD loopback encapsulation */

struct v4_header {
       u_int32_t dlt; /* 0 */
       u_int8_t  ip_hl_v; /* 0x45 */
       u_int8_t  ip_tos;  /* 0 */
       u_int16_t ip_len;
       u_int16_t ip_id;   /* 0 */
       u_int16_t ip_off;  /* 0 */
       u_int8_t  ip_ttl;  /* 63 */
       u_int8_t  ip_p;    /* 17 */
       u_int16_t ip_sum;
       u_int32_t ip_src;
       u_int32_t ip_dst;
       u_int16_t udp_src;
       u_int16_t udp_dst;
       u_int16_t udp_len;
       u_int16_t udp_sum;
};

struct v6_header {
       u_int32_t dlt; /* 0 */
       u_int32_t ip6_flow; /* 0x60000000 */
       u_int16_t ip6_plen;
       u_int8_t  ip6_nxt; /* 17 ? */
       u_int8_t  ip6_hlim; /* 63 ? */
       u_int8_t  ip6_src[16];
       u_int8_t  ip6_dst[16];
       u_int16_t udp_src;
       u_int16_t udp_dst;
       u_int16_t udp_len;
       u_int16_t udp_sum;
};

struct data_header {
	uint8_t flag;
	uint8_t af;
	uint16_t dnslen;
	uint32_t tv_sec; 
	uint32_t tv_usec;
	uint16_t c_port;
	uint16_t s_port;
};

/* <struct data_header><IPv4/IPv6 address><dnslen DNS data>*/

static u_short id = 0;

int send_packet(int s4, int s6, struct addr46 *destp, char *string, int fh)
{
	char *qname;
	int qtype;
	unsigned char *u;
	int dnssec_do = 0;
	int edns = 0;
	int destaddrspecified = 0;
	int broken_specified = 0;
	int waittime;
	int len;
	int alen;
	char *sep = " \t\r\n";
	struct addr46 dest;
	struct sockaddr_storage src;
	int srclen = sizeof(src);
	struct pcap_header ph;
	struct v4_header v4;
	struct v6_header v6;
	u_char sendbuf[512];
	u_char *w = sendbuf;
	u_char *p, *q;
	struct timeval now;
	u_char c;
	int randlen;

	if ((qname = strtok(string, sep)) == NULL)
	  errx(1, "1:qname=NULL");
	if (!strcmp(qname, "**")) {
		/* if qname=**, IP address, sleep time and raw data mode */
		/* Example:
** 192.168.1.1 1000 [ 12 34 28 00 / 00 01 00 01 00 01 00 00 / 07 65 78 61 6d 70 6c 65 02 6a 70 00 00 00 00 06 / 00 00 01 00 01 00 00 00 00 00 04 7f 00 00 01 / 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ]
		 */
		if ((p = strtok(NULL, sep)) == NULL)
			errx(1, "5:qname=%s", qname);
		if (ipaddr2sockaddr(&dest, p, NULL)) {
			destp = &dest;
		} else {
			errx(1, "6: cannot resolv %s", p);
		}
		if ((p = strtok(NULL, sep)) == NULL)
			errx(1, "no waittime : qname=%s", qname);
		waittime = atoi(p);
		if ((p = strtok(NULL, sep)) == NULL || strcmp(p, "["))
			errx(1, "no [");
		while ((p = strtok(NULL, sep)) != NULL && strcmp(p, "]")) {
			if (*p == '/')
				continue;
			if (*p == '*') {
				if (p[1] == '*') {
					randlen = (random() % 128);
				} else {
					randlen = atoi(p+1);
				}
				while(randlen-- > 0) {
					*w++ = random() & 0xff;
				}
			} else if (isxdigit(p[0]) && isxdigit(p[1]) && p[2] == 0) {
				c = ((isdigit(p[0]) ? p[0] & 0x0f : (p[0] & 0x0f) + 9) << 4)
					| (isdigit(p[1]) ? p[1] & 0x0f : (p[1] & 0x0f) + 9);
				*w++ = c;
				if (w - sendbuf >= sizeof(sendbuf))
					errx(1, "too large data");
			} else {
				errx(1, "proken digit %s", p);
			}
		}
		len = w - sendbuf;
		printf("len=%d\n", len);
	} else {
		if ((p = strtok(NULL, sep)) == NULL)
			errx(1, "2:qname=%s qtype=NULL", qname);
		if ((qtype = atoi(p)) == 0 && *p != '0')
			errx(1, "2:qname=%s qtype=%d", qname,qtype);
		if ((p = strtok(NULL, sep)) == NULL)
			errx(1, "3:qname=%s qtype=%d edns=NULL",
				qname,qtype);
		if (*p == 'D') {
			dnssec_do = 1;
			edns = 1;
			p++;
		}
		if (*p == 'E') {
			edns = 1;
			p++;
		}
		if (*p == 'd') {
			destaddrspecified = 1;
			p++;
		}
		if (*p == 'b') {
			broken_specified = 2;
		}
		if ((p = strtok(NULL, sep)) == NULL)
			errx(1, "4:qname=%s qtype=%d edns=%d wait=%s",
				qname,qtype,edns, p);
		waittime = atoi(p);
		if (destaddrspecified) {
			if ((p = strtok(NULL, sep)) == NULL)
			errx(1, "5:qname=%s qtype=%d edns=%d wait=%s destaddrspecified=%d but destaddr is not specified",
					qname,qtype,edns, waittime, destaddrspecified);
			if (ipaddr2sockaddr(&dest, p, NULL)) {
				destp = &dest;
			} else {
				errx(1, "6: cannot resolv %s", p);
			}
		}
		*w++ = (id >> 8);
		*w++ = (id & 0xff);
		id++;
		*w++ = 0; /* QR|opcode(4)|AA|TC|RD */
		*w++ = 0; /* RA|Z(3)|OPCODE(4) */
		*w++ = 0; *w++ = 1; /* QDCOUNT */
		*w++ = 0; *w++ = 0; /* ANCOUNT */
		*w++ = 0; *w++ = 0; /* NSCOUNT */
		*w++ = 0; *w++ = edns; /* ANCOUNT */
		p = qname;
		while(*p != 0 && *p != '.') {
			q = strchr(p, '.');
			len = 0;
			len = (q == NULL) ? strlen(p) : q - p;
			if (len > 63 || w+len+8+11 > sendbuf+sizeof(sendbuf))
				errx(1, "buffer overflow:qname=%s qtype=%d edns=%d wait=%s", qname,qtype,edns, waittime);
			*w++ = len;
			memcpy(w, p, len);
			w += len;
			p += len;
			if (*p == '.')
				p++;
		}
		*w++ = 0; /* end of DNAME */
		*w++ = (qtype >> 8);
		*w++ = (qtype & 0xff);
		*w++ = 0; *w++ = 1; /* class = IN */
		if (edns) {
			*w++ = 0; /* . */
			*w++ = 0; *w++ = 41; /* opt */
			*w++ = 16; *w++ = 00; /* payload size = 4096 */
			*w++ = 0; /* extended rcode */
			*w++ = 0; /* edns version */
			*w++ = dnssec_do? 0x80 : 0; /* DO=0x80 */
			*w++ = 0;
			*w++ = 0; *w++ = 0; /* rdlen = 0 */
		}
		len = w - sendbuf;
		if (broken_specified > 0) {
			len -= broken_specified;
			if (len < 0) len = 1;
		}
	}
	gettimeofday(&now, NULL);
	if (sendto(destp->u.sa.sa_family==AF_INET?s4:s6, sendbuf, len, 0, (struct sockaddr *)&destp->u, destp->len) != len) {
		int no;
		if (errno < 0)
			no = 0;
		else if (errno > 255)
			no = 0;
		else
			no = errno;
		Xerror[no]++;
	}
	ph.ts.tv_sec = now.tv_sec;
	ph.ts.tv_usec = now.tv_usec;
	if (header.af == AF_INET) {
		p = (char *)&destp->u.sin4.sin_addr;
		alen = sizeof(destp->u.sin4.sin_addr);
		header.s_port = destp->u.sin4.sin_port;
		if (getsockname(s4, (struct sockaddr *)&src, &srclen) < 0)
			err(1, "getsockname error: s4");
		header.c_port = ((struct sockaddr_in *)&src)->sin_port;
	} else {
		p = (char *)&destp->u.sin6.sin6_addr;
		alen = sizeof(destp->u.sin6.sin6_addr);
		header.s_port = destp->u.sin6.sin6_port;
		if (getsockname(s6, (struct sockaddr *)&src, &srclen) < 0)
			err(1, "getsockname error: s4");
		header.c_port = ((struct sockaddr_in6 *)&src)->sin6_port;
	}
	header.dnslen = len;
	if (write(fh, &header, sizeof(header)) != sizeof(header)
	  || write(fh, p, alen) != alen
	  || write(fh, sendbuf, len) != len) {
		err(1, "cannot write sent data");
	}
	SendCount++;
	return waittime;
}

receive_packet(int sock, int fh)
{
	struct sockaddr_storage ss, local;
	int slen = sizeof(ss);
	int locallen = sizeof(local);
	int len;
	struct data_header header;
	char *p;
	int alen;
	char buff[8192];
	struct timeval now;

	len = recvfrom(sock, buff, sizeof(buff), 0, (struct sockaddr *)&ss, &slen);
	if (getsockname(sock, (struct sockaddr *)&local, &locallen) < 0)
		err(1, "error: getsockname at recvfrom");
	header.af = ss.ss_family;
	header.dnslen = len;
	header.flag = 'R';
	if (header.af == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
		p = (char *)&sin->sin_addr;
		alen = sizeof(sin->sin_addr);
		header.s_port = sin->sin_port;
		header.c_port = ((struct sockaddr_in *)&local)->sin_port;
	} else
	if (header.af == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
		p = (char *)&sin6->sin6_addr;
		alen = sizeof(sin6->sin6_addr);
		header.s_port = sin6->sin6_port;
		header.c_port = ((struct sockaddr_in6 *)&local)->sin6_port;
	} else {
		err(1, "received source address is broken: slen=%d family=%d", slen, ss.ss_family);
	}
	gettimeofday(&now, NULL);
	header.tv_sec = htonl(now.tv_sec);
	header.tv_usec = htonl(now.tv_usec);
	if (write(fh, &header, sizeof(header)) != sizeof(header)
	  || write(fh, p, alen) != alen
	  || write(fh, buff, len) != len)
		err(1, "cannot write received data");
	RecvCount++;
}

void replay(FILE *i, int o, long long _Timeout, struct addr46 *destination, int ipv6)
{
	int n;
#ifdef USE_KQUEUE
	int kq;
	struct kevent kev, kevr;
	struct timespec _timeout;
#else
	int nfds;
	struct timeval _timeout;
	fd_set fdset0, fdset;
#endif
	long timeout;
	char *qname;
	int qtype;
	int edns;
	int dnssec_do;
	int destaddrspecified;
	long waittime;
	char *p;
	char *u;
	int len;
	int slen;
	int qid;
	long long current;
	long long last_sent;
	long long t;
	struct addr46 *destp;
	struct addr46 dest;
	int s4 = -1;
	int s6 = -1;
	int optval;
	int optsize;
	struct data_header header;

	u_char buff[512];
	u_char sendbuf[512];

#ifdef USE_KQUEUE
	kq = kqueue();
#else
	FD_ZERO(&fdset0);
#endif

	s4 = socket(AF_INET, SOCK_DGRAM, 0);
	if (s4 < 0)
		err(1, "socket(AF_INET)");
	memset(&dest.u.sin4, 0, sizeof(dest.u.sin4));
	dest.u.sin4.sin_family = AF_INET;
	if (bind(s4, (struct sockaddr *)&dest.u.sin4, sizeof(dest.u.sin4)) < 0)
		err(1, "bind");
	if (fcntl(s4, F_SETFL, O_NONBLOCK) == -1)
		err(1, "fcntl(,F_SETFL,O_NONBLOCK,,)");
	optsize = sizeof(optval);
	optval = 220 * 1024;
	if (setsockopt(s4, SOL_SOCKET, SO_SNDBUF, &optval, optsize) < 0)
		err(1, "setsocket(,SOL_SOCKET,SO_SNDBUF,,)");
	optsize = sizeof(optval);
	optval = 220 * 1024;
	if (setsockopt(s4, SOL_SOCKET, SO_RCVBUF, &optval, optsize) < 0)
		err(1, "setsocket(,SOL_SOCKET,SO_RCVBUF,,)");

#ifdef USE_KQUEUE
	EV_SET(&kev, s4, EVFILT_READ, EV_ADD, 0, 0, NULL);
	kevent(kq, &kev, 1, NULL, 0, NULL);
#else
	FD_SET(s4, &fdset0);
	nfds = s4 + 1;
#endif

	if (ipv6) {
		s6 = socket(AF_INET6, SOCK_DGRAM, 0);
		if (s6 < 0)
			err(1, "socket(AF_INET6)");
		memset(&dest.u.sin6, 0, sizeof(dest.u.sin6));
		dest.u.sin6.sin6_family = AF_INET6;
		if (bind(s6, (struct sockaddr *)&dest.u.sin6, sizeof(dest.u.sin6)) < 0)
		err(1, "bind");
		if (fcntl(s6, F_SETFL, O_NONBLOCK) == -1)
			err(1, "fcntl(,F_SETFL,O_NONBLOCK,,)");
		optsize = sizeof(optval);
		optval = 220 * 1024;
		if (setsockopt(s6, SOL_SOCKET, SO_SNDBUF, &optval, optsize) < 0)
			err(1, "setsocket(,SOL_SOCKET,SO_SNDBUF,,)");
		optsize = sizeof(optval);
		optval = 220 * 1024;
		if (setsockopt(s6, SOL_SOCKET, SO_RCVBUF, &optval, optsize) < 0)
			err(1, "setsocket(,SOL_SOCKET,SO_RCVBUF,,)");
#ifdef USE_KQUEUE
		EV_SET(&kev, s6, EVFILT_READ, EV_ADD, 0, 0, NULL);
		kevent(kq, &kev, 1, NULL, 0, NULL);
#else
		FD_SET(s6, &fdset0);
		nfds = ((s4>s6)?s4:s6) + 1;
#endif
	}
	last_sent = current = NOW();
	waittime = 0;

	for (;;) {
		current = NOW();
		t = current - last_sent;
		if (t >= waittime) {
			if (waittime > 0)
				last_sent += waittime;
			if (fgets(buff, sizeof buff, i) == NULL)
				break;
			if (buff[0] == ';')
				continue;
			waittime = send_packet(s4, s6, destination, buff, o);
			if (waittime == 0)
				continue;
			current = NOW();
			t = current - last_sent;
		}
		if (t < waittime) {
			timeout = waittime - t;
		} else {
			continue;
		}
#ifdef DEBUG
		printf("waittime > 0: %ld: now=%lld timeout=%ld\n",
			waittime, current, timeout);
#endif
		_timeout.tv_sec = timeout / 1000000;
#ifdef USE_KQUEUE
		_timeout.tv_nsec = (timeout % 1000000) * 1000;
		n = kevent(kq, NULL, 0, &kevr, 1, &_timeout);
		if (n > 0)
			receive_packet(kevr.ident, o);
#else
		_timeout.tv_usec = timeout % 1000000;
		fdset = fdset0;
		n = select(nfds, &fdset, NULL, NULL, &_timeout);
		if (FD_ISSET(s4, &fdset))
			receive_packet(s4, o);
		if (ipv6 && FD_ISSET(s6, &fdset))
			receive_packet(s6, o);
#endif
	}
	waittime = _Timeout;
	for (;;) {
		current = NOW();
		t = current - last_sent;
		if (t < waittime) {
			timeout = waittime - t;
		} else 
			break;
#ifdef USE_KQUEUE
		_timeout.tv_sec = timeout / 1000000;
		_timeout.tv_nsec = (timeout % 1000000) * 1000;
		n = kevent(kq, NULL, 0, &kevr, 1, &_timeout);
		current = NOW();
		if (n > 0)
			receive_packet(kevr.ident, o);
#else
		_timeout.tv_sec = timeout / 1000000L;
		_timeout.tv_usec = timeout % 1000000L;
		fdset = fdset0;
		n = select(nfds, &fdset, NULL, NULL, &_timeout);
		current = NOW();
		if (FD_ISSET(s4, &fdset))
			receive_packet(s4, o);
		if (ipv6 && FD_ISSET(s6, &fdset))
			receive_packet(s6, o);
#endif
	}
}

void usage()
{
	fprintf(stderr, 
"dns_replay [options] [host [port]]\n"
"\t-l num		loops specified seconds\n"
"\t-i file		specify input file [stdin]\n"
"\t-o file		specify output file [stdout]\n"
"\t-h host		specify remote host\n"
"\t-p port		specify remote port\n"
"\t-t timeout	specify timeout\n"
"\t-v		verbose\n"
"\tinput from stdin\n"
"\toutput to stdout\n"
);
	exit(1);
}

int main(int argc, char *argv[])
{
	int ch;
	int opt_v = 0;
	char *host = "127.0.0.1";
	char *port = "53";
	char *infile = NULL;
	char *ofile = NULL;
	int ipv6 = 1;
	long long _Timeout = 5 * 1000 * 1000;
	int opt_l = 0;
	FILE *in = stdin;
	int i;
	int o = 1;
	struct addr46 dest;

	memset(&Xerror, 0, sizeof(Xerror));

	while((ch = getopt(argc, argv, "6vl:i:o:h:p:t:")) != -1)
	switch(ch) {
	case '6':
		ipv6 = ~ipv6;
		break;
	case 'l':
		opt_l = atoi(optarg);
		break;
	case 'i':
		infile = strdup(optarg);
		break;
	case 'o':
		ofile = strdup(optarg);
		break;
	case 'h':
		host = strdup(optarg);
		break;
	case 'p':
		port = strdup(optarg);
		break;
	case 't':
		_Timeout = atol(optarg);
		break;
	case 'v':
		opt_v++;
		break;
	default:
		usage();
	}
	argc-=optind;
	argv+=optind;
	if (argc > 0) {
printf("argc=%d argv[0]=%s\n", argc, argv[0]);
		host = argv[0];
		if (argc > 1)
			port = argv[1];
	}
	if (opt_v)
		printf("!host=%s port=%s opt_l=%d i=%s o=%s\n",
			host, port, opt_l, infile, ofile);
	if (infile != NULL) {
		if ((in = fopen(infile, "r")) == NULL) {
			err(1, "error %d: %s", errno, infile);
		}
	}
	if (ofile != NULL) {
		if ((o = creat(ofile, 0755)) < 0) {
			err(1, "error %d: %s", errno, ofile);
		}
	}
	if (host == NULL)
		usage();

	if (!ipaddr2sockaddr(&dest, host, port))
		err(1, "error %s/%s", host, port);
	replay(in, o, _Timeout, &dest, ipv6);

	fprintf(stderr, "Send: %d\nRecv: %d\n", SendCount, RecvCount);
	for (i = 0; i < 256; i++) {
		if (Xerror[i] > 0) {
			fprintf(stderr, "!! errno[%d] = %d\n", i, Xerror[i]);
		}
	}
	return 0;
}
