/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/07 17:17:24 by reclaire          #+#    #+#             */
/*   Updated: 2024/09/03 03:52:51 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"
#include "libft/std.h"
#include "libft/limits.h"
#include "libft/strings.h"
#include "libft/time.h"
#include "libft/io.h"
#include "libft/socket.h"
#include "libft/getopt.h"
#include "libft/debug.h"
#include "libft/maths.h"

#ifndef __USE_MISC
#define __USE_MISC 1
#endif
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <math.h>
#include <limits.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#define __USE_XOPEN2K 1
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

static void sigint_handler(S32 sig);

static U16 checksum(U16 *ptr, U64 nbytes);

static void print_help();
static void print_statistics_and_exit();

/* stats */
U32 errors;
U32 n_packets_sent;
U32 n_packets_received;
t_clock total_clk;

U32 dstaddr;

/* rtt */
F32 rtt;
F32 *rtt_buffer;
U64 rtt_buffer_cnt;
U64 rtt_buffer_alloc;

int main(S32 argc, const_string *argv)
{
	uid_t uid;
	/* parameters */
	bool verbose;
	bool audible;			  /* makes bell sound for each ping received */
	F32 interval;			  /* interval in secs between each ping sent. defaults to 1. The program needs to be run as root to be under 2ms */
	S32 count;				  /* amount of pings to send before stopping. -1 means infinite (default) */
	bool print_timestamps;	  /* print timestamps before each pings */
	bool so_debug;			  /* set the sock opt SO_DEBUG */
	bool flood;				  /* set the interval to 0. Requires the program to be run as root */
	S64 mark;				  /* mark packets. -1 means no marking (default) */
	t_time timeout;			  /* duration to wait for a ping reply */
	U8 ttl;					  /* time to live */
	S32 sndbuf;				  /* SO_SNDBUF size. -1 means no change (default) */
	string interface_name;	  /* interface to send the ping through. NULL means auto */
	bool interface_specified; /* TRUE if interface_name was specified in the args */
	S32 deadline;			  /* time in secs after which the program exits. 0 means infinite */
	U64 payload_size;		  /* ICMP payload size. defaults to 56 */
	U16 seq;				  /* ICMP seq value (auto incremented each ping sent) */
	U32 srcaddr;			  /* source address taken from interface */
	U32 tos;				  /* Type of Service byte in the IP header */
	bool quiet;				  /* quiet output */
	bool do_reverse_dns;	  /* -n flag */
	U8 payload_pattern[16];	  /* payload pattern buffer */
	U8 payload_pattern_len;	  /* payload pattern buffer len */

	/* icmp */
	file sock;					/* socket fd */
	t_ip_header *ip_header;		/* IP header to send. Start of packet. send() should receive this as data pointer */
	t_icmp_header *icmp_header; /* ICMP header to send */
	U8 *payload;				/* ICMP payload to send */
	U64 packet_size;			/* ICMP payload size */

	/*
	Sending ICMP Echo packets, so:
	ICMP Header:
	type		= U8	= +1 byte
	code		= U8	= +1 byte
	checksum	= U16	= +2 bytes
	ICMP Echo:
	id			= U16	= +2 bytes
	seq			= U16	= +2 bytes
	= 8 bytes
	*/
	const U8 icmp_echo_header_size = 8;
	/* recvfrom/sendto */
	S64 sent_recv;				  /* total data sent/receive */
	U8 recv_buff[65535];		  /* buffer for recvfrom. 65535 is the max IP packet size */
	t_ip_header *reply_iphdr;	  /* IP header from reply */
	t_icmp_header *reply_icmphdr; /* ICMP header from reply */
	U8 *reply_payload;			  /* payload from reply */

	/* utils */
	struct addrinfo hints;
	struct addrinfo *res;
	struct addrinfo *res2;
	t_time timestamp;
	S32 opt;
	S64 i;
	struct sockaddr_in dummy_addr;

	char dstaddr_str[16 /* xxx.xxx.xxx.xxx */ +
					 NI_MAXHOST /* max hostname size */ +
					 4 /* ' ', '(', ')', '\0' */
	] = {0};

	signal(SIGINT, sigint_handler);

	seq = 1;

	errors = 0;
	n_packets_sent = 0;
	n_packets_received = 0;
	ft_clk_init(&total_clk);

	uid = getuid();

	{ /* Args parsing */
		ft_optchr = '!'; /* Change return character for unknown args from '?' to '!' because we need to check for option '-?' */

		payload_size = 56 - sizeof(U64); /* ICMP packet is 8, so 56 + 8 = 64 bytes of data each packet */

		audible = FALSE;
		verbose = FALSE;
		interval = 1.f;
		count = -1;
		print_timestamps = FALSE;
		so_debug = FALSE;
		mark = -1;
		timeout.seconds = 1;
		timeout.nanoseconds = 0;
		ttl = U8_MAX;
		sndbuf = -1;
		interface_name = NULL;
		interface_specified = FALSE;
		deadline = 0;
		tos = 0;
		flood = FALSE;
		quiet = FALSE;
		do_reverse_dns = TRUE;
		payload_pattern_len = 0;

		while ((opt = ft_getopt(argc, argv, "ac:DdfI:i:m:np:Q:qS:s:t:vW:w:?")) != -1)
		{
			switch (opt)
			{
			case 'a':
				audible = TRUE;
				break;

			case 'c':
				if (!ft_str_isnbr((string)ft_optarg))
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s'\n", ft_argv[0], ft_optarg);
					return 1;
				}
				count = ft_atoi(ft_optarg);
				break;

			case 'D':
				print_timestamps = TRUE;
				break;

			case 'd':
				so_debug = TRUE;
				break;

			case 'I':
				interface_name = (string)ft_optarg;
				interface_specified = TRUE;
				break;

			case 'f':
				ft_optarg = "0";
				flood = TRUE;
				quiet = TRUE;
				/* fallthrough */
			case 'i':
				if (!ft_str_isflt((string)ft_optarg))
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s'\n", ft_argv[0], ft_optarg);
					return 1;
				}
				interval = ft_atof(ft_optarg);
				if (uid != 0 && interval < 0.002f)
				{
					ft_dprintf(ft_errno, "%s: cannot flood; minimal interval allowed for user is 2ms\n", ft_argv[0]);
					return 1;
				}
				break;

			case 'm':
				if (!ft_str_isnbr((string)ft_optarg))
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s'\n", ft_argv[0], ft_optarg);
					return 1;
				}
				mark = ft_atoi(ft_optarg);
				if (mark < 0)
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s': out of range: 0 <= value <= 2147483647\n", ft_argv[0], ft_optarg);
					return 1;
				}
				break;

			case 'n':
				do_reverse_dns = FALSE;
				break;

			case 'p':
				i = 0;
				if (ft_strlen(ft_optarg) > 16)
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s': out of range: 0 <= value <= 18446744073709551615\n", ft_argv[0], ft_optarg);
					return 1;
				}
				if (!ft_str_ishex((string)ft_optarg))
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s'\n", ft_argv[0], ft_optarg);
					return 1;
				}
				while (ft_optarg[i] && payload_pattern_len < sizeof(payload_pattern))
				{
					recv_buff[0] = ft_optarg[i];
					recv_buff[1] = ft_optarg[i + 1];
					recv_buff[3] = '\0';
					payload_pattern[payload_pattern_len] = ft_atoix((const_string)recv_buff, NULL);
					i += ft_optarg[i + 1] ? 2 : 1;
					payload_pattern_len++;
				}
				break;

			case 'q':
				quiet = TRUE;
				break;

			case 'Q':
				if (!ft_str_ishex((string)ft_optarg))
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s'\n", ft_argv[0], ft_optarg);
					return 1;
				}
				tos = ft_atoix(ft_optarg, NULL);
				if (tos > 255)
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s': out of range: 0 <= value <= 255\n", ft_argv[0], ft_optarg);
					return 1;
				}
				break;

			case 's':
				if (!ft_str_isnbr((string)ft_optarg))
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s'\n", ft_argv[0], ft_optarg);
					return 1;
				}
				payload_size = ft_atoi(ft_optarg);
				break;

			case 'S':
				if (!ft_str_isnbr((string)ft_optarg))
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s'\n", ft_argv[0], ft_optarg);
					return 1;
				}
				sndbuf = ft_atoi(ft_optarg);
				if (sndbuf <= 0)
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s': out of range: 1 <= value <= 2147483647\n", ft_argv[0], ft_optarg);
					return 1;
				}
				break;

			case 't':
				if (!ft_str_isnbr((string)ft_optarg))
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s'\n", ft_argv[0], ft_optarg);
					return 1;
				}
				S32 ttl_val = ft_atoi(ft_optarg);
				if (ttl_val < 1 || ttl_val > 255)
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s': out of range: 1 <= value <= 255\n", ft_argv[0], ft_optarg);
					return 1;
				}
				ttl = ttl_val;
				break;

			case 'w':
				if (!ft_str_isnbr((string)ft_optarg))
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s'\n", ft_argv[0], ft_optarg);
					return 1;
				}
				deadline = ft_atoi(ft_optarg);
				if (deadline < 0)
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s': out of range: 0 <= value <= 2147483647\n", ft_argv[0], ft_optarg);
					return 1;
				}
				break;

			case 'W':
				if (!ft_str_isnbr((string)ft_optarg))
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s'\n", ft_argv[0], ft_optarg);
					return 1;
				}
				S32 timeout_v = ft_atoi(ft_optarg);
				if (timeout_v < 0)
				{
					ft_dprintf(ft_errno, "%s: bad linger time: %d\n", ft_argv[0], timeout_v);
					return 1;
				}
				timeout.seconds = (U64)timeout_v / 1000;
				timeout.nanoseconds = (U64)timeout_v * 1000 % 1000000;
				break;

			case 'v':
				verbose = TRUE;
				break;
			case '!':
				ft_printf("\n");
				/* fallthrough */
			case '?':
			case 'h':
				print_help();
				return 1;
			}
		}

		if (ft_optind >= argc)
		{
			ft_dprintf(ft_stderr, "%s: usage error: Destination address required\n", ft_argv[0]);
			return 1;
		}

		{ /* DNS */
			hints = (struct addrinfo){0};
			hints.ai_family = AF_INET;
			hints.ai_socktype = SOCK_STREAM;

			if ((i = getaddrinfo(argv[ft_optind], NULL, &hints, &res)) != 0)
			{
				ft_dprintf(ft_stderr, "%s: getaddrinfo: %s\n", ft_argv[0], gai_strerror(i));
				return 1;
			}
			res2 = res;
			while (res->ai_family != AF_INET)
				res = res->ai_next;

			if (!res)
			{
				ft_dprintf(ft_stderr, "%s: %s: No address associated with hostname\n", ft_argv[0], argv[ft_optind]);
				return 1;
			}

			dstaddr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
			freeaddrinfo(res2);
		}

		if (inet_pton(AF_INET, ft_argv[ft_optind], &i))
			/* Address is an ip (x.x.x.x) */
			ft_strlcat(dstaddr_str, ft_argv[ft_optind], sizeof(dstaddr_str));
		else if (!do_reverse_dns)
			/* Show ip */
			ft_strlcat(dstaddr_str, addr_to_str(dstaddr), sizeof(dstaddr_str));
		else
		{ /* Address is a hostname (xxx.abcdefg.yyy) */
			dummy_addr = (struct sockaddr_in){0};
			dummy_addr.sin_family = AF_INET;
			dummy_addr.sin_addr.s_addr = dstaddr;
			if ((i = getnameinfo((struct sockaddr *)&dummy_addr, sizeof(struct sockaddr_in), dstaddr_str, sizeof(dstaddr_str), NULL, 0, NI_NAMEREQD)) != 0)
			{
				if (verbose)
					ft_dprintf(ft_stderr, "%s: %s\n", ft_argv[0], gai_strerror(i));
				return 1;
			}

			i = ft_strlen(dstaddr_str);
			if (i > NI_MAXHOST)
			{
				ft_memcpy(&dstaddr_str[NI_MAXHOST - 4], "...", 4);
				i = NI_MAXHOST;
			}

			ft_strcat(dstaddr_str, " (");
			ft_strcat(dstaddr_str, addr_to_str(dstaddr));
			ft_strcat(dstaddr_str, ")");
		}

		interval *= 1e6;
		payload_size += sizeof(U64); /* space for timestamp sent in ICMP data */

		packet_size = sizeof(t_ip_header) + icmp_echo_header_size + payload_size;
		if ((ip_header = malloc(packet_size)) == NULL)
		{
			ft_dprintf(ft_stderr, "%s: out of memory\n", ft_argv[0]);
			return 1;
		}
	}

	{ /* Get own IP address from interface */
		struct ifaddrs *ifaddr, *ifa;
		struct sockaddr_in *sa;

		if (getifaddrs(&ifaddr) == -1)
		{
			ft_dprintf(ft_stderr, "%s: getifaddrs: %s", ft_argv[0], strerror(errno));
			return 1;
		}

		srcaddr = 0;
		if (interface_name == NULL)
		{
			/* No interface specified */
			for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
			{
				if (ifa->ifa_addr == NULL || !ft_strcmp(ifa->ifa_name, "lo"))
					continue;

				if (ifa->ifa_addr->sa_family == AF_INET)
				{
					sa = (struct sockaddr_in *)ifa->ifa_addr;
					if ((sa->sin_addr.s_addr & ifa->ifa_netmask->sa_data[0]) ==
						(dstaddr & ifa->ifa_netmask->sa_data[0]))
					{
						interface_name = ifa->ifa_name;
						srcaddr = sa->sin_addr.s_addr;
						break;
					}
				}
			}
			if (srcaddr == 0)
			{
				ft_dprintf(ft_stderr, "%s: no interface found\n", ft_argv[0]);
				return 1;
			}
		}
		else
		{
			/* Search for specified interface */
			for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
			{
				if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET)
					continue;

				if (!ft_strcmp(ifa->ifa_name, interface_name))
				{ /* Found match */
					sa = (struct sockaddr_in *)ifa->ifa_addr;
					srcaddr = sa->sin_addr.s_addr;
					break;
				}
			}
			if (srcaddr == 0)
			{
				ft_dprintf(ft_stderr, "%s: couldn't find interface: %s\n", ft_argv[0], interface_name);
				return 1;
			}
		}
		freeifaddrs(ifaddr);
	}

	{ /* Round-trip-time stats initialization */
		rtt_buffer = NULL;
		rtt_buffer_cnt = 0;
		rtt_buffer_alloc = 20;
		if ((rtt_buffer = malloc(sizeof(F32) * rtt_buffer_alloc)) == NULL)
		{
			ft_dprintf(ft_stderr, "%s: out of memory\n", ft_argv[0]);
			return 1;
		}
	}

	{
		S32 on = 1;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
		(void)setuid(0);
		if ((sock = ft_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
		{
			ft_dprintf(ft_stderr, "error: socket: %s\n", strerror(errno));
			return -1;
		}
		(void)setuid(uid);
#pragma GCC diagnostic pop

		if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1)
		{
			close(sock); // TODO: ft_close
			ft_dprintf(ft_stderr, "error: setsockopt: IP_HDRINCL: %s\n", strerror(errno));
			return -1;
		}

		// allow socket to send datagrams to broadcast addresses
		if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == -1)
		{
			close(sock);
			ft_dprintf(ft_stderr, "error: setsockopt: SO_BROADCAST: %s\n", strerror(errno));
			return -1;
		}

		if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(t_time)) == -1)
		{
			close(sock);
			ft_dprintf(ft_stderr, "error: setsockopt: SO_RCVTIMEO: %s\n", strerror(errno));
			return -1;
		}

		if (so_debug)
		{
			if (setsockopt(sock, SOL_SOCKET, SO_DEBUG, &on, sizeof(on)) == -1)
			{
				close(sock);
				ft_dprintf(ft_stderr, "error: setsockopt: SO_DEBUG: %s\n", strerror(errno));
				return -1;
			}
		}

		if (mark >= 0)
		{
			U32 dummy = (U32)mark;
			if (setsockopt(sock, SOL_SOCKET, SO_MARK, &dummy, sizeof(dummy)) == -1)
			{
				close(sock);
				ft_dprintf(ft_stderr, "error: setsockopt: SO_MARK: %s\n", strerror(errno));
				return -1;
			}
		}

		if (sndbuf > 0)
		{
			if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) == -1)
			{
				close(sock);
				ft_dprintf(ft_stderr, "error: setsockopt: SO_SNDBUF: %s\n", strerror(errno));
				return -1;
			}
		}
	}

	ft_clk_start(&total_clk);

	// Loop
	while (TRUE)
	{
		ft_clk_get(&timestamp);

		{ /* ICMP Packet construction */
			ft_memset(ip_header, 0, packet_size);

			icmp_header = (t_icmp_header *)(((U8 *)ip_header) + sizeof(t_ip_header));
			payload = (U8 *)(((U8 *)icmp_header) + icmp_echo_header_size);

			*(U64 *)(payload) = ft_clk_to_timestamp(timestamp);

			if (payload_pattern_len == 0)
			{
				for (U64 i = 0; i < payload_size - sizeof(U64); i++)
					payload[i + sizeof(U64)] = i;
			}
			else
			{
				for (U64 i = 0; i < payload_size - sizeof(U64); i++)
					payload[i + sizeof(U64)] = payload_pattern[i % payload_pattern_len];
			}

			ip_header->ver = 4;
			ip_header->ihl = sizeof(t_ip_header) / 4;
			ip_header->tos = tos;
			ip_header->len = htons(sizeof(t_ip_header) + icmp_echo_header_size + payload_size);
			ip_header->id = rand();
			ip_header->flgs_frg = 0;
			ip_header->ttl = ttl;
			ip_header->protocol = IPPROTO_ICMP;
			ip_header->src_addr = srcaddr;
			ip_header->dst_addr = dstaddr;
			ip_header->check = 0;
			ip_header->check = checksum((U16 *)ip_header, sizeof(t_ip_header));

			icmp_header->type = ICMP_MSG_ECHO;
			icmp_header->code = 0;
			icmp_header->req.echo.id = rand();
			icmp_header->req.echo.seq = seq;
			icmp_header->checksum = 0;
			icmp_header->checksum = checksum((U16 *)icmp_header, icmp_echo_header_size + payload_size);
		}

		if (seq == 1)
		{
			ft_printf("PING %s (%s) ", argv[ft_optind], dstaddr_str);
			if (interface_specified)
				ft_printf("from %s %s: ", addr_to_str(srcaddr), interface_name);
			ft_printf("%ld(%ld) bytes of data.\n", payload_size, packet_size);
			if (flood)
				ft_printf(".");
		}

		sent_recv = 0;
		dummy_addr = (struct sockaddr_in){0};
		dummy_addr.sin_family = AF_INET;
		dummy_addr.sin_addr.s_addr = dstaddr;
		i = 0;
		while (packet_size - sent_recv > 0 &&
			   (i = sendto(sock, ip_header + sent_recv, packet_size - sent_recv, 0, (struct sockaddr *)&dummy_addr, sizeof(struct sockaddr_in))) > 0)
			sent_recv += i;
		if (i < 0)
		{
			ft_dprintf(ft_stderr, "error: sendto: %s\n", strerror(errno)); // TODO: check ping error codes + error message
			return -1;
		}

		{ // Try to receive a response
			i = 0;
			sent_recv = 0;

			reply_iphdr = NULL;
			reply_icmphdr = NULL;
			reply_payload = NULL;

			do
			{
				i = recvfrom(sock, recv_buff + sent_recv, sizeof(recv_buff) - sent_recv, 0, NULL, NULL);
				sent_recv += i;

				if (sent_recv >= (S64)sizeof(t_ip_header) && reply_iphdr == NULL)
				{
					reply_iphdr = (t_ip_header *)recv_buff;
					reply_iphdr->len = htons(reply_iphdr->len);
				}
			} while (
				(i > 0) &&
				((!reply_iphdr) ||				 /* IP header (without options) not yet received */
				 (sent_recv < reply_iphdr->len)) /* Full IP packet not yet received */
			);

			if (i < 0)
			{
				if (errno == EINTR || errno == EAGAIN)
				{
					if (verbose)
						ft_dprintf(ft_stderr, "%s: Request timed out for icmp_seq=%u\n", ft_argv[0], seq);
				}
				else
				{
					ft_dprintf(ft_stderr, "error: recvfrom: %s\n", strerror(errno));
					return 1;
				}
			}
			else
			{
				reply_icmphdr = (t_icmp_header *)(recv_buff + reply_iphdr->ihl * 4);
				reply_payload = ((U8 *)reply_icmphdr) + 8;
			}
		}
		n_packets_sent++;

		if (print_timestamps && !quiet)
			ft_printf("[%ld.%.6ld] ", timestamp.seconds, timestamp.nanoseconds);

		if (reply_iphdr && reply_icmphdr)
		{
			if (audible && !quiet)
				ft_printf("\a");

			switch (reply_icmphdr->type)
			{
			case ICMP_MSG_ECHO_REPLY:
				rtt = (F32)(ft_clk_timestamp() - *(U64 *)(reply_payload)) / 1000.0f;
				if (rtt_buffer_cnt >= rtt_buffer_alloc)
				{
					F32 *tmp = rtt_buffer;
					if ((rtt_buffer = malloc(sizeof(F32) * rtt_buffer_alloc * 2)) == NULL)
					{
						ft_dprintf(ft_errno, "%s: out of memory\n", ft_argv[0]);
						return 1;
					}
					ft_memcpy(rtt_buffer, tmp, sizeof(F32) * rtt_buffer_alloc);
					rtt_buffer_alloc *= 2;
				}
				rtt_buffer[rtt_buffer_cnt] = rtt;
				rtt_buffer_cnt++;
				if (!quiet)
				{

					if (reply_icmphdr->req.echo.seq != seq)
					{
						if (verbose)
							ft_dprintf(ft_stderr, "%s: received icmp_seq=%u later\n", ft_argv[0], reply_icmphdr->req.echo.seq);
					}
					else
					{
						printf("%u bytes from %s: icmp_seq=%u ttl=%u time=%.1fms\n",
							   reply_iphdr->len - reply_iphdr->ihl * 4,
							   dstaddr_str,
							   reply_icmphdr->req.echo_reply.seq,
							   reply_iphdr->ttl,
							   rtt);
						fflush(stdout);
					}
				}
				n_packets_received++;
				break;
			default:
				if (!quiet)
				{
					ft_printf("From %s icmp_seq=%u ", addr_to_str(reply_iphdr->src_addr), seq);
					icmp_print_error(reply_iphdr, reply_icmphdr, verbose);
				}
				errors++;
				break;
			}
		}

		if ((count > -1) && (n_packets_sent >= (U32)count))
			break;

		seq++;
		while (ft_clk_timestamp() - ft_clk_to_timestamp(timestamp) < interval)
			;

		if (deadline)
		{
			S64 secs, nsecs;
			ft_clk_stop(&total_clk);
			ft_clk_diff(&total_clk.t1, &total_clk.t2, &secs, &nsecs);

			if (secs > deadline)
			{
				free(ip_header);
				close(sock);
				print_statistics_and_exit();
			}
		}
	}

	free(ip_header);
	close(sock);
	print_statistics_and_exit();
	return 0;
}

string addr_to_str(U32 addr)
{
	static char buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &addr, buf, sizeof(buf));
	return buf;
}

static void sigint_handler(S32 sig)
{
	(void)sig;
	print_statistics_and_exit();
}

static void print_statistics_and_exit()
{
	S64 secs, nsecs;
	F32 rtt_min, rtt_max, rtt_avg, rtt_mdev;

	ft_clk_stop(&total_clk);
	ft_clk_diff(&total_clk.t1, &total_clk.t2, &secs, &nsecs);

	ft_printf("\n--- %s ping statistics ---\n", ft_argv[ft_optind]);
	ft_printf("%u packets transmitted, %u received, ",
			  n_packets_sent,
			  n_packets_received);
	if (errors)
		ft_printf("+%u errors, ", errors);
	printf("%.2f%% packet loss, time %.0fms\n",
		   (F32)(n_packets_sent - n_packets_received) * 100.0f / (F32)(n_packets_sent),
		   (F32)(nsecs / 1e6) + (secs * 1000));
	fflush(stdout);

	if (rtt_buffer_cnt == 0)
		exit(0);

	ft_printf("rtt min/avg/max/mdev = ");
	rtt_min = F32_MAX;
	rtt_max = F32_MIN;
	rtt_avg = 0;
	for (U64 i = 0; i < rtt_buffer_cnt; i++)
	{
		rtt_min = rtt_buffer[i] < rtt_min ? rtt_buffer[i] : rtt_min;
		rtt_max = rtt_buffer[i] > rtt_max ? rtt_buffer[i] : rtt_max;
		rtt_avg += rtt_buffer[i];
	}
	rtt_avg /= rtt_buffer_cnt;

	rtt_mdev = 0.0f;
	for (U64 i = 0; i < rtt_buffer_cnt; i++)
		rtt_mdev += (rtt_buffer[i] - rtt_avg) * (rtt_buffer[i] - rtt_avg);
	rtt_mdev = sqrtf(rtt_mdev / (F32)rtt_buffer_cnt);

	printf("%.3f/%.3f/%.3f/%.3f ms\n", rtt_min, rtt_avg, rtt_max, rtt_mdev);
	fflush(stdout);
	exit(0);
}

__attribute__((destructor)) void on_program_exit()
{
	if (rtt_buffer)
		free(rtt_buffer);
}

static U16 checksum(U16 *ptr, U64 nbytes)
{
	U64 sum;
	U16 oddbyte;
	U16 answer;

	sum = 0;
	while (nbytes > 1)
	{
		sum += *ptr++;
		nbytes -= 2;
	}

	if (nbytes == 1)
	{
		oddbyte = 0;
		*((U8 *)&oddbyte) = *(U8 *)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return answer;
}

/*
TODO:
-p
*/
static void print_help()
{
	ft_printf(
		"Usage\n\
  ping [options] <destination>\n\
\n\
Options:\n\
  <destination>      dns name or ip address\n\
  -a                 use audible ping\n\
  -c <count>         stop after <count> replies\n\
  -D                 print timestamps\n\
  -d                 use SO_DEBUG socket option\n\
  -f                 flood ping\n\
  -h -?              print help and exit\n\
  -I <interface>     either interface name\n\
  -i <interval>      seconds between sending each packet\n\
  -m <mark>          tag the packets going out\n\
  -n                 no dns name resolution\n\
  -p <pattern>       contents of padding byte\n\
  -q                 quiet output\n\
  -Q <tclass>        use quality of service <tclass> bits\n\
  -s <size>          use <size> as number of data bytes to be sent\n\
  -S <size>          use <size> as SO_SNDBUF socket option value\n\
  -t <ttl>           define time to live\n\
  -v                 verbose output\n\
  -w <deadline>      reply wait <deadline> in seconds, and quits on ping error\n\
  -W <timeout>       time to wait for response\n");
}