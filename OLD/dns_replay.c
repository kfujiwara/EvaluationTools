/*
  $Id: dns_replay.c,v 1.28 2011/02/24 10:47:49 fujiwara Exp $

  Copyright (C) 1998-2006 Kazunori Fujiwara <fujiwara@wide.ad.jp>.
  All rights reserved.

  You can redistribute it and/or modify it
  under either the terms of the GPL version 2.
  GPL is shown in <http://www.gnu.org/licenses/gpl.html>.

  Complile:
	Solaris 10:	gcc -DNO_ERR dns_replay.c -lsocket -lresolv
	BSD:		cc dns_replay.c
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
#ifndef NO_SYS_SELECT_H
#include <sys/select.h>
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

#ifdef NO_ERR
void err(int err, char *format, ...)
{
	va_list ap; va_start(ap, format);
	(void) vfprintf(stderr, format, ap);
	va_end(ap);
	(void)exit(err);
}
#endif

int init(char *host, char *port)
{
	int error;
	const char *cause = NULL;
	int s = -1;
	int optval;
	int optsize;
	struct addrinfo hints, *res, *res0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	error = getaddrinfo(host, port, &hints, &res0);
	if (error) {
		 err(1, "%s", gai_strerror(error));
		 /*NOTREACHED*/
	}
	for (res = res0; res; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s < 0) {
			cause = "socket";
			continue;
		}
		if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
			cause = "connect";
			close(s);
			s = -1;
			continue;
		}
		break;  /* okay we got one */
	}
	if (s < 0) {
		 err(1, "%s", cause);
		 /*NOTREACHED*/
	}
	freeaddrinfo(res0);

	if (fcntl(s, F_SETFL, O_NONBLOCK) == -1)
		err(1, "fcntl(,F_SETFL,O_NONBLOCK,,)");
	optsize = sizeof(optval);
	optval = 220 * 1024;
	if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &optval, optsize) < 0)
		err(1, "setsocket(,SOL_SOCKET,SO_SNDBUF,,)");
	optsize = sizeof(optval);
	optval = 220 * 1024;
	if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &optval, optsize) < 0)
		err(1, "setsocket(,SOL_SOCKET,SO_RCVBUF,,)");
	return s;
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

int receivepacket(int sock, FILE *o, long long now)
{
	int sslen;
	u_char *p, *q, *lim, *w;
	u_int qdcount;
	int recvlen;
	int qid;
	int ra;
	int rcode;
	int qtype;
	struct sockaddr_storage ss;
	u_char recvbuf[PACKETSZ];
	u_char qname[257];

	memset(&ss, 0, sizeof(ss));
	sslen = sizeof(ss);
	recvlen = recvfrom(sock, recvbuf, sizeof recvbuf, 0,
		(struct sockaddr *)&ss, &sslen);
	if (recvlen == -1 && errno == EAGAIN)
		return 0;
	if (recvlen < 15 || sslen < sizeof(struct sockaddr_in)) {
		return -1;
	}
	qid = recvbuf[0] * 256 + recvbuf[1];
	ra = recvbuf[2] & 1;
	rcode = recvbuf[3] & 15;

	lim = recvbuf + recvlen;
	p = recvbuf + 4;
	qdcount = (p[0] << 8) | p[1];
	p += 8;
	if (qdcount != 1) return -1;
	q = p;
	w = qname;
	if (*p != 0) {
		while(*p > 0 && *p < 0x40) {
			if ((w - qname) >= (sizeof(qname) - 1 - *p))
				err(1, "recv packet parse error: too long qname");
			memcpy(w, p + 1, *p);
			w += *p;
			*w++ = '.';
			p += *p + 1;
		}
		w--;
	} else {
		*w++ = '.';
	}
	*w = 0;
	if (*p == 0)
		p++;
	else {
		/* p+=2; */
		err(1, "recv packet parse error: pointer in qname");
	}
	if (p > lim) return -1;
	qtype = p[0] * 256 + p[1];
	p += 4;	/* qtype, qclass */
	fprintf(o, "R %lld %d %s %d %d\n", now, qid, qname, qtype, rcode);
	return 1;
}

long long NOW(void)
{
	struct timeval _current;

	gettimeofday(&_current, NULL);
	return _current.tv_sec * 1000000LL + _current.tv_usec;
}

static u_short id = 0;
void replay(int sock, FILE *i, FILE *o, long long _Timeout, int RD)
{
	int n;
	int nfds;
	long timeout;
	char *qname;
	int qtype;
	int edns;
	int dnssec_do;
	long waittime;
	u_char *p, *q;
	int len;
	int qid;
	long long current;
	long long last_sent;
	long long t;
	char *sep = " \t\r\n";
	struct timeval _timeout;
	fd_set fdset0, fdset;
	u_char buff[512];
	u_char sendbuf[512];
	u_char *w = sendbuf;

	FD_ZERO(&fdset0);
	FD_SET(sock, &fdset0);
	nfds = sock + 1;
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
			if ((qname = strtok(buff, sep)) == NULL)
				err(1, "1:qname=NULL");
			if ((p = strtok(NULL, sep)) == NULL
				|| (qtype = atoi(p)) == 0)
				err(1, "2:qname=%s qtype=%d", qname,qtype);
			if ((p = strtok(NULL, sep)) == NULL)
				err(1, "3:qname=%s qtype=%d edns=NULL",
					qname,qtype);
			dnssec_do = (*p == 'D') ? 1 : 0;
			edns = (*p == 'E' || *p == 'D') ? 1 : 0;
			if ((p = strtok(NULL, sep)) == NULL)
				err(1, "4:qname=%s qtype=%d edns=%d wait=%s",
					qname,qtype,edns, p);
			waittime = atoi(p);
			*w++ = (id >> 8);
			id++;
			*w++ = (id & 0xff);
			*w++ = RD?0:1; /* QR|opcode(4)|AA|TC|RD */
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
					err(1, "buffer overflow:qname=%s qtype=%d edns=%d wait=%s", qname,qtype,edns, waittime);
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
/* dump */
			p = sendbuf;
			printf("[ \n");
			while(p < w) {
				printf("%02x ", *p++);
			}
			printf("]\n");

			if (send(sock, sendbuf, len, 0) != len) {
				int no;
				if (errno < 0)
					no = 0;
				else if (errno > 255)
					no = 0;
				else
					no = errno;
				Xerror[no]++;
			}
			current = NOW();
			qid = sendbuf[0] * 256 + sendbuf[1];
			fprintf(o, "S %lld %d %s %d\n", current, qid, qname, qtype);
			if (waittime == 0)
				continue;
			t = current - last_sent;
		}
		if (t < waittime) {
			timeout = waittime - t;
		} else {
			continue;
		}
#ifdef DEBUG
	I	printf("waittime > 0: %s %d %ld: now=%lld timeout=%ld\n",
			qname, qtype, waittime, current, timeout);
#endif
		_timeout.tv_sec = timeout / 1000000;
		_timeout.tv_usec = timeout % 1000000;
		fdset = fdset0;
		n = select(nfds, &fdset, NULL, NULL, &_timeout);
		if (FD_ISSET(sock, &fdset)) {
			current = NOW();
			if (receivepacket(sock, o, current) > 0)
				receivepacket(sock, o, current);
		}
	}
	waittime = _Timeout;
	for (;;) {
		current = NOW();
		t = current - last_sent;
		if (t < waittime) {
			timeout = waittime - t;
		} else 
			break;
		_timeout.tv_sec = timeout / 1000000L;
		_timeout.tv_usec = timeout % 1000000L;
		fdset = fdset0;
		n = select(nfds, &fdset, NULL, NULL, &_timeout);
		current = NOW();
		if (FD_ISSET(sock, &fdset))
			receivepacket(sock, o, current);
	}
}

void print_preamble(FILE *o, long long _Timeout)
{
	fprintf(o, "! date %lld\n", NOW());
	fprintf(o, "! timeout %lld\n", _Timeout);
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
"\t-r		RD bit set\n"
"\t-v		verbose\n"
"\tinput from stdin\n"
"\toutput to stdout\n"
);
	exit(1);
}

int main(int argc, char *argv[])
{
	int sock;
	int ch;
	int opt_v = 0;
	char *host = NULL;
	char *port = "53";
	char *infile = NULL;
	char *ofile = NULL;
	long long _Timeout = 5 * 1000 * 1000;
	int opt_l = 0;
	int opt_r = 0;
	FILE *in = stdin;
	FILE *out = stdout;
	int i;

	memset(&Xerror, 0, sizeof(Xerror));

	while((ch = getopt(argc, argv, "vrl:i:o:h:p:t:")) != -1)
	switch(ch) {
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
	case 'r':
		opt_r++;
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
	} else {
		in = stdin;
	}
	if (ofile != NULL) {
		if ((out = fopen(ofile, "w")) == NULL) {
			err(1, "error %d: %s", errno, ofile);
		}
	} else {
		out = stdout;
	}
	if (host == NULL)
		usage();

	sock = init(host, port);
	print_preamble(out, _Timeout);
	replay(sock, in, out, _Timeout, opt_r);

	for (i = 0; i < 256; i++) {
		if (Xerror[i] > 0) {
			fprintf(out, "!! errno[%d] = %d\n", i, Xerror[i]);
		}
	}
	return 0;
}
