#!/usr/bin/env perl
#
# $Id: dns_replay.pl,v 1.15 2017/02/02 12:01:35 fujiwara Exp $
#
#  Copyright (C) 1998-2006 Kazunori Fujiwara <fujiwara@wide.ad.jp>.
#  All rights reserved.
#
#  You can redistribute it and/or modify it
#  under either the terms of the GPL version 2.
#  GPL is shown in <http://www.gnu.org/licenses/gpl.html>.

# perl version of dns_replay2.c
#

use strict;
use Data::Dumper;
use IO::Select;
use IO::Socket::INET;
use IO::Socket::INET6;
use Time::HiRes qw(usleep gettimeofday tv_interval);
use Socket;
use Socket6;
use Getopt::Std;

# main

my $host = "127.0.0.1";
my $port = 53;
my $infile = "";
my $outfile = "";
my $_timeout = 15*1000000;
my $flag_rd = 0;
my $mag = 1.0;

my $usage = "dns_replay.pl [options] [host [port]]
 -M mode	specify output format: 1/[2]/3=dns_replay/dns_replay2/pcap
 -i file	specify input file [stdin]
 -o file	specify output file [stdout]
 -h host	specify remote host
 -p port	specify remote port
 -t sec		specify timeout
 -m mag		specify magnification to waittime
 -v		verbose
\tinput from stdin
\toutput to stdout\n";

my %opts;
&getopts('6vM:m:l:i:o:h:p:t:r:', \%opts);

my $in = \*STDIN;
if (defined($opts{'i'})) {
	open($in, "<", $opts{'i'}) || die "cannot open: ".$opts{'i'};
}
my $out= \*STDOUT;
if (defined($opts{'o'})) {
	open($out, ">", $opts{'o'}) || die "cannot open: ".$opts{'o'};
}
if (defined($opts{'h'})) {
	$host = $opts{'h'};
}
if (defined($opts{'p'})) {
	$port = $opts{'p'};
}
if (defined($opts{'r'})) {
	$flag_rd = 1;
}
if (defined($opts{'m'}) && $opts{'m'} > 0) {
	$mag = $opts{'m'} + 0.0;
}
my $output_format = $opts{'M'};
$| = 1;

my $lineno = 0;
my $qid = 1;
my $state = &init_wait_recv_send;

if ($output_format == 1) {
	$state->{output_func} = \&output_data_replay1;
} elsif ($output_format == 2) {
	$state->{output_func} = \&output_data_replay2;
} elsif (!defined($output_format) || $output_format == 3) {
	print $out pack("NnnNNNN", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101);
	$state->{output_func} = \&output_data_pcap;
}

while(<$in>) {
	$lineno++;
	chomp;
	#noexistence.pyon.org 16 DEd 1100 2001:2e8:602:0:2:1:0:9e
	my @d = split(/ /);
	if ($#d < 4) {
		print STDERR "to few input at $lineno: $_\n";
		exit 1;
	}
	my $remote;
	my $buf = &packet_encode($d[0], $d[1], $d[2]);
	my ($_host, $_port) = ($host, $port);
	if ($d[2] =~ /d/) {
 		($_host, $_port) = split(/\//, $d[4]);
		$_port = $port if (!defined($_port));
	}
	if ($_host =~ /:/) {
		$remote = pack_sockaddr_in6($_port,inet_pton(AF_INET6, $_host));
	} else {
		$remote = pack_sockaddr_in($_port,inet_aton($_host));
	}
	&wait_recv_send($state, $d[3], $remote, $buf);
}
#print "ExitWhile0\n";
my $e = &gettime - $state->{start};

&wait_recv_send($state, 1*1000000);

if ($e > 0 && $state->{num_sent} > 0) {printf STDERR "Send: %d, %d.%06d sec, %f qps, %d usec\n", $state->{num_sent}, int($e/1000000),$e % 1000000, $state->{num_sent} * 1000000 / $e, $e / $state->{num_sent}; }
print STDERR "Recv: ".$state->{num_received}."\n";

sub output_data_replay1
{
	my ($mode, $now, $s_sa, $d_sa, $buf) = @_;
	my ($af, $saddr, $sport, $daddr, $dport);

	$af = sockaddr_family($s_sa);
	if ($af == AF_INET) {
		($sport, $saddr) =unpack_sockaddr_in($s_sa);
		($dport, $daddr) =unpack_sockaddr_in($d_sa);
	} else {
		($sport, $saddr) =unpack_sockaddr_in6($s_sa);
		($dport, $daddr) =unpack_sockaddr_in6($d_sa);
	}
	my ($qid, $flag) = unpack("nn", $buf);
	# need to generate qname, qtype from $buf
	my $qname;
	my @label;
	my $qtype;
	my $offset = 12;
	my $len;
	while(($len = ord(substr($buf, $offset, 1))) > 0) {
		last if ($len > 63 || length($buf) < $offset+$len+2);
		push @label, substr($buf, $offset+1, $len);
		$offset += $len + 1;
	}
	if ($len == 0) {
		$qtype = unpack('n', substr($buf, $offset+1, 2));
		$qname = join(".", @label);
		$qname = "." if ($qname eq "");
	} else {
		$qname = "#ERROR";
		$qtype = 0;
	}
	printf $out "%s %d %d %s %d %04x\n", $mode, $now, $qid, $qname, $qtype, $flag;
}

sub output_data_replay2
{
	my ($mode, $now, $s_sa, $d_sa, $buf) = @_;
	my ($af, $saddr, $sport, $daddr, $dport);

	$af = sockaddr_family($s_sa);
	if ($af == AF_INET) {
		($sport, $saddr) =unpack_sockaddr_in($s_sa);
		($dport, $daddr) =unpack_sockaddr_in($d_sa);
} else {
		($sport, $saddr) =unpack_sockaddr_in6($s_sa);
		($dport, $daddr) =unpack_sockaddr_in6($d_sa);
	}
	#print STDERR $mode." saddr=".&hexdump($saddr)." daddr=".&hexdump($daddr)." sport=$sport dport=$dport\n";
  	print $out pack("aCnNNnn", $mode, $af, length($buf),
	     int($now/1000000), $now % 1000000,
		$mode eq 'S'?$sport:$dport,
		$mode eq 'R'?$sport:$dport)
		.($mode eq 'S'?$daddr:$saddr).$buf;
}

sub output_data_pcap
{
	my ($mode, $now, $s_sa, $d_sa, $buf) = @_;
	my ($af, $saddr, $sport, $daddr, $dport);

	$af = sockaddr_family($s_sa);
	if ($af == AF_INET) {
		($sport, $saddr) =unpack_sockaddr_in($s_sa);
		($dport, $daddr) =unpack_sockaddr_in($d_sa);
	} else {
		($sport, $saddr) =unpack_sockaddr_in6($s_sa);
		($dport, $daddr) =unpack_sockaddr_in6($d_sa);
	}
	my $ip;
	my $udp;
	if ($af == AF_INET) {
		$ip = pack("ccnnncc", 0x45, 0, 20+8+length($buf), 0,
				0, 63, 17);
		my $sum = unpack("%32n*", $ip.$saddr.$daddr);
		$sum = ~(($sum & 0xffff) + ($sum >> 16));
		$ip .= pack("n", $sum).$saddr.$daddr;
	} else {
		$ip = pack("ccccncc", 0x60,0,0,0,8+length($buf),17,0)
			.$saddr.$daddr;
	}
	$udp = pack("nnn", $sport, $dport, length($buf)+8);
	my $sum = unpack("%32n*", $saddr.$daddr.$udp.$buf.chr(0));
	$sum += length($buf)+8+17;
	$sum = ~(($sum & 0xffff) + ($sum >> 16));
	$udp .= pack("n", $sum);

	my $len = length($ip)+length($udp)+length($buf);
  	print $out pack("NNNN", int($now/1000000), $now % 1000000, $len, $len)
		.$ip.$udp.$buf;
}

##############################################################################
#
# wait_send_recv uses one hash reference as state
#
# $state->{s4} = IPv4 socket
#         {s6} = IPv6 socket
#         {s4_sa} = sockaddr s4
#         {s6_sa} = sockaddr s6
#         {sel} = IO::Select object
#         {start} = initialized time (*1000000)
#         {next_send} = next send time
#         {num_sent} = number of send udp packets
#         {num_received} = number of received udp packets
#	  {output_func} = Output Function

# initialize
sub init_wait_recv_send
{
	my $z = {};
	socket (my $s4, PF_INET, SOCK_DGRAM, 0) || die "socket4: $!";
	bind($s4, pack_sockaddr_in(0, &get_local_ipv4_address)) || die "bind4: $!";
	setsockopt($s4, SOL_SOCKET, SO_SNDBUF, 220*1024) || die "setsockopt:s4:$!";
	socket (my $s6, PF_INET6, SOCK_DGRAM, 0) || die "socket6: $!";
	bind($s6, pack_sockaddr_in6(0, &get_local_ipv6_address)) || die "bind6: $!";
	setsockopt($s6, SOL_SOCKET, SO_SNDBUF, 220*1024) || die "setsockopt:s6:$!";
	$z->{s4} = $s4;
	$z->{s6} = $s6;
	$z->{s6_sa} = getsockname($s6);
	$z->{s4_sa} = getsockname($s4);
	$z->{sel} = IO::Select->new($s4, $s6);

	$z->{num_sent} = 0;
	$z->{num_received} = 0;
	$z->{start} = &gettime;
	$z->{next_send} = $z->{start};
	$z->{output_func} = undef;

	return $z;
}

sub wait_recv_send
{
	my ($z, $_wait, $_remote, $_payload) = @_;
	my $sel_wait;
	my $now = &gettime;
	#print "Entered_wait_send_recv:now$now:next=".$z->{next_send}."\n";
	my ($buf, $sa, $sl, $sport, $dport, $saddr, $daddr, $a2);
	if (!defined($_payload)) {
		if (defined($_wait)) {
			$z->{next_send} += $_wait;
		}
	}
	do {
		#print "now=$now ". Dumper($z);
		$sel_wait = $z->{next_send} - $now;
		if ($sel_wait < 0) { $sel_wait = 0; }
		#print STDERR "Wait:$sel_wait\n";
		my @s = ($z->{sel})->can_read($sel_wait/1000000);
		$now = &gettime;
		foreach my $so (@s) {
		  my $sa = recv $so, $buf, 65535, 0;
		  my $d_sa = getsockname($so);
		  if (defined($sa) && length($buf) > 0) {
			if (defined($z->{output_func})) {
				$z->{output_func}->('R', $now, $sa, $d_sa, $buf);
			}
			$z->{num_received}++;
		  }
		}
		$now = &gettime;
	} while($now < $z->{next_send});

	if (defined($_payload)) {
		$z->{next_send} += $_wait;
		my $err = 0;
		my $so = (sockaddr_family($_remote)==AF_INET)?$z->{s4}:$z->{s6};
		my $sa = getsockname($so);
		$err = send $so, $_payload, 0, $_remote;
		#print &hexdump($r, "remote=");
		#print &hexdump($packet, "payload=");
		#print "return=$err\n";
		if (defined($z->{output_func})) {
			$z->{output_func}->('S', $now, $sa, $_remote, $_payload);
		}
		$z->{num_sent}++;
	}
}

sub packet_encode
{
	my ($name, $type, $flag) = @_;

	my $d = '';
	foreach my $n (split(/\./, $name)) {
		last if (length($n) <= 0);
		$d = $d.chr(length($n)).$n;
	}
	$d .= chr(0);
	my $edns = 0;
	if ($flag =~ /E/) { $edns = 1; };
	my $do = 0;
	my $p = pack("nnnnnn", $qid % 65536, $flag_rd, 1, 0, 0, $edns);
	$qid++;
	if ($flag =~ /D/) { $do = 1; };
	$p .= $d.pack("nn", $type, 1);
	if ($edns) {
		$p .= chr(0).pack("nnnnn", 41, 4096, 0, $do? 32768:0, 0);
	}
	return $p;
}

sub gettime
{
	my ($sec, $usec) = gettimeofday;
	return $sec * 1000000 + $usec;
}

sub hexdump
{
	my $data = shift;
	my $head = shift;
	my $L = length($data);

	my $o = "";
	$o = $head if (defined($head));
	$o .= sprintf ("%d [", $L);
	for (my $i = 0; $i < $L; $i++) {
		$o.=sprintf("%02x ", ord(substr($data, $i, 1)));
	}
	$o.= "]";
}

sub get_local_ipv4_address
{
	my $socket = IO::Socket::INET->new(
		Proto => 'udp',
		PeerAddr => '198.41.0.4',
		PeerPort => 53,
	);
	my $sa = getsockname($socket);
	my ($port, $ipv4) = unpack_sockaddr_in($sa);
	close($socket);
	return $ipv4;
}

sub get_local_ipv6_address
{
	my $socket = IO::Socket::INET6->new(
		Proto => 'udp',
		PeerAddr => '2001:503:ba3e::2:30',
		PeerPort => 53,
	);
	my $sa = getsockname($socket);
	my ($port, $ipv6) = unpack_sockaddr_in6($sa);
	close($socket);
	return $ipv6;
}
