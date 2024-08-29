/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/07 17:17:24 by reclaire          #+#    #+#             */
/*   Updated: 2024/08/29 22:02:38 by reclaire         ###   ########.fr       */
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

#ifndef __USE_MISC
#define __USE_MISC 1
#endif
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <net/if.h>
#define __USE_XOPEN2K 1
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

static void sigint_handler(S32 sig);

static void print_help();
static void print_statistics_and_exit();
/*
Opens raw socket ( socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) )
+ setsockopt IPPROTO_IP IP_HDRINCL
+ setsockopt SOL_SOCKET SO_BROADCAST
*/
static file init_socket(bool so_debug, S64 mark);
static bool get_host_addr(U32 *addr);

static S64 send_data(file sock, U8 *data, S64 data_size, U32 addr);

/* stats */
U32 errors;
U32 n_packets_sent;
U32 n_packets_received;
t_clock total_clk;

U32 dstaddr;

int main(S32 argc, const_string *argv)
{
	bool running_as_root;
	/* parameters */
	bool verbose;
	bool audible;
	F32 interval; // secs
	S32 count;
	bool print_timestamps;
	bool so_debug;
	bool flood;
	S64 mark;
	t_time timeout;
	U8 ttl;
	S32 sndbuf;

	U64 payload_size;
	U16 seq;
	U32 srcaddr;
	/* icmp */
	file sock;
	t_icmp_packet packet;
	/* recvfrom */
	U8 recv_buff[65535]; // Max IP packet size
	S64 received;
	t_ip_header *reply_iphdr;
	t_icmp_header *reply_icmphdr;
	U8 *reply_payload;
	/* timers */
	t_clock clk;
	S64 secs, nsecs;
	t_time timestamp;
	/* utils */
	S64 i;

	signal(SIGINT, sigint_handler);

	seq = 1;
	ft_clk_init(&clk);

	errors = 0;
	n_packets_sent = 0;
	n_packets_received = 0;
	ft_clk_init(&total_clk);

	running_as_root = getuid() == 0;

	{ // Args
		S32 v;

		// Change return character for unknown args to '!' because we need to check for '-?'
		ft_optchr = '!';

		// Default to 56 - sizeof(U64) (timestamp)
		payload_size = 56 - sizeof(U64);

		audible = FALSE;
		verbose = FALSE;
		interval = 1.f;
		count = -1;
		print_timestamps = FALSE;
		so_debug = FALSE;
		flood = FALSE;
		mark = -1;
		timeout.seconds = 0;
		timeout.nanoseconds = 0;
		ttl = U8_MAX;
		sndbuf = -1;

		while ((v = ft_getopt(argc, argv, "ac:Ddfi:m:t:s:S:vW:?")) != -1)
		{
			switch (v)
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

			case 'f':
				ft_optarg = "0";
				flood = TRUE;
				/* fallthrough */
			case 'i':
				if (!ft_str_isflt((string)ft_optarg))
				{
					ft_dprintf(ft_errno, "%s: invalid argument: '%s'\n", ft_argv[0], ft_optarg);
					return 1;
				}
				interval = ft_atof(ft_optarg);
				if (!running_as_root && interval < 0.2f)
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
				return 2;
			}
		}

		if (ft_optind >= argc)
		{
			ft_dprintf(ft_stderr, "%s: usage error: Destination address required\n", ft_argv[0]);
			return 1;
		}

		if (inet_aton(argv[ft_optind], (struct in_addr *)&dstaddr) == -1)
		{
			ft_dprintf(ft_stderr, "%s: %s: Name or service not known\n", ft_argv[0]);
			return 2;
		}

		interval *= 1e6;
	}

	if (get_host_addr(&srcaddr) == FALSE)
		return 1;

	{
		S32 on = 1;
		if ((sock = ft_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
		{
			ft_dprintf(ft_stderr, "error: socket: %s\n", strerror(errno));
			return -1;
		}

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
		packet = make_icmp_echo(srcaddr, dstaddr, payload_size, seq, ttl, ft_clk_to_timestamp(timestamp));

		if (seq == 1)
		{
			ft_printf("PING %s (%s) %ld(%ld) bytes of data.\n", argv[ft_optind], argv[ft_optind], payload_size, packet.packet_size);
			if (flood)
				ft_printf(".");
		}

		if (send_data(sock, packet.packet, packet.packet_size, dstaddr) == -1)
		{
			ft_dprintf(ft_stderr, "%s: send: %s\n", ft_argv[0], strerror(errno));
			return 1;
		}
		n_packets_sent++;

		{ // Receive response
			i = 0;
			received = 0;

			reply_iphdr = NULL;
			reply_icmphdr = NULL;
			reply_payload = NULL;

			ft_memset(recv_buff, 2, sizeof(recv_buff));

			do
			{
				i = recvfrom(sock, recv_buff + received, sizeof(recv_buff) - received, 0, NULL, NULL);
				received += i;

				if (received >= (S64)sizeof(t_ip_header) && reply_iphdr == NULL)
				{
					reply_iphdr = (t_ip_header *)recv_buff;
					reply_iphdr->len = htons(reply_iphdr->len);
				}
			} while (
				(i > 0) &&
				((!reply_iphdr) ||				// IP header (without options) not yet received
				 (received < reply_iphdr->len)) // Full IP packet not yet received
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
					ft_dprintf(ft_stderr, "error: recvfrom: %s %d\n", strerror(errno));
					return 1;
				}
			}
			else
			{
				reply_icmphdr = (t_icmp_header *)(recv_buff + reply_iphdr->ihl * 4);
				reply_payload = ((U8 *)reply_icmphdr) + 8;
				n_packets_received++;
			}
		}

		if (flood == FALSE)
		{
			if (print_timestamps)
				ft_printf("[%ld.%.6ld] ", timestamp.seconds, timestamp.nanoseconds);

			if (reply_iphdr && reply_icmphdr)
			{
				if (audible)
					ft_printf("\a");
				switch (reply_icmphdr->type)
				{
				case ICMP_MSG_ECHO_REPLY:
					printf("%u bytes from %s: icmp_seq=%u ttl=%u time=%.1fms\n",
						   reply_iphdr->len - reply_iphdr->ihl * 4,
						   addr_to_str(reply_iphdr->src_addr),
						   reply_icmphdr->req.echo_reply.seq,
						   reply_iphdr->ttl,
						   (F32)(ft_clk_timestamp() - *(U64 *)(reply_payload)) / 1000.0f);
					break;
				default:
					ft_printf("From %s icmp_seq=%u ", addr_to_str(reply_iphdr->src_addr), seq);
					icmp_print_error(reply_iphdr, reply_icmphdr, verbose);
					errors++;
					break;
				}
			}
		}

		free(packet.packet);

		if ((count > -1) && (n_packets_sent >= (U32)count))
			break;

		seq++;
		while (ft_clk_timestamp() - ft_clk_to_timestamp(timestamp) < interval)
			;
	}

	close(sock);
	print_statistics_and_exit();
	return 0;
}

char *reverse_dns_lookup(char *ip_str, int family)
{
	t_sa_in sa_in;
	char buff_hostname[NI_MAXHOST];
	int status;

	if ((status = inet_pton(family, ip_str, (family == AF_INET ? (void *)&sa_in.ip4.sin_addr : (void *)&sa_in.ip6.sin6_addr))) == -1)
		PERROR("inet_pton");
	if (status == 0)
	{
		dprintf(STDERR_FILENO, "%s: inet_pton: Invalid string\n", PROG_NAME);
		exit_clean(EXIT_FAILURE);
	}
	if (family == AF_INET)
	{
		sa_in.ip4.sin_family = family;
		sa_in.ip4.sin_port = 0;
	}
	else
	{
		sa_in.ip6.sin6_family = family;
		sa_in.ip6.sin6_port = 0;
	}

	if ((status = getnameinfo((family == AF_INET ? (struct sockaddr *)&sa_in.ip4 : (struct sockaddr *)&sa_in.ip6), (family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)), buff_hostname, sizeof(buff_hostname), NULL, 0, NI_NAMEREQD)) != 0)
	{
		if (g_ping->options.set[e_option_verbose])
			dprintf(STDERR_FILENO, "%s: getnameinfo: %s\n", PROG_NAME, gai_strerror(status)); // not authorized by the subject but it would be stupid to not do it
		return (NULL);
	}
	return (ft_strdup(buff_hostname));
}

bool resolve_ip(char *dest, struct s_ping *ping)
{
	struct addrinfo hints;
	struct addrinfo *res;
	struct addrinfo *tmp_ptr;
	S32 ret;
	const char *tmp_str = NULL;

	hints = (struct addrinfo){0};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if ((ret = getaddrinfo(dest, NULL, &hints, &res)) != 0)
	{
		ft_dprintf(ft_stderr, "%s: getaddrinfo: %s\n", ft_argv[0], gai_strerror(ret));
		return FALSE;
	}

	tmp_ptr = res;
	while (tmp_ptr)
	{
		ft_memcpy(&(ping->dest.sa_in.ip4), (void *)tmp_ptr->ai_addr, sizeof(struct sockaddr_in));
		tmp_str = inet_ntop(AF_INET, &(ping->dest.sa_in.ip4.sin_addr), ping->dest.ip, INET_ADDRSTRLEN);
		ping->dest.family = AF_INET;
		if (!ping->options.set[e_option_version] || (ping->options.set[e_option_version] && ping->options.version == e_ip4))
			break;
		tmp_ptr = tmp_ptr->ai_next;
	}
	freeaddrinfo(res); // not authorized by the subject but it would be stupid to not do it
	if (!tmp_str)
		PERROR("inet_ntop");
	if (!tmp_ptr)
	{
		dprintf(STDERR_FILENO, "%s: %s: No address associated with hostname\n", PROG_NAME, dest);
		exit_clean(EXIT_FAILURE);
	}
}

static bool get_host_addr(U32 *addr)
{
	file sock;
	struct ifreq ifr = {0};

	if ((sock = ft_socket(AF_INET, SOCK_DGRAM, 0)) == (file)-1)
	{
		ft_dprintf(ft_stderr, "error: socket 2\n");
		return FALSE;
	}
	ifr.ifr_addr.sa_family = AF_INET;
	ft_strlcpy(ifr.ifr_name, "wlo1", IFNAMSIZ - 1);

	if (ioctl(sock, SIOCGIFADDR, &ifr) == -1)
	{
		ft_dprintf(ft_stderr, "error: ioctl: %s\n", strerror(errno));
		close(sock);
		return FALSE;
	}

	close(sock);
	*addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
	return TRUE;
}

string addr_to_str(U32 addr)
{
	static char buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &addr, buf, sizeof(buf));
	return buf;
}

static S64 send_data(file sock, U8 *data, S64 data_size, U32 addr)
{
	S64 sent = 0, tmp = 0;
	struct sockaddr_in addr_in = {0};
	addr_in.sin_addr.s_addr = addr;

	while (data_size - sent > 0 && (tmp = sendto(sock, data + sent, data_size - sent, 0, (struct sockaddr *)&addr_in, sizeof(struct sockaddr_in))) > 0)
		sent += tmp;
	if (tmp < 0)
	{
		ft_dprintf(ft_stderr, "error: sendto: %s\n", strerror(errno)); // TODO: check ping error codes + error message
		return -1;
	}
	return sent;
}

static void sigint_handler(S32 sig)
{
	(void)sig;
	print_statistics_and_exit();
}

static void print_statistics_and_exit()
{
	S64 secs, nsecs;

	ft_clk_stop(&total_clk);
	ft_clk_diff(&total_clk.t1, &total_clk.t2, &secs, &nsecs);

	ft_printf("\n--- %s ping statistics ---\n", addr_to_str(dstaddr));
	printf("%u packets transmitted, %u received, %.2f%% packet loss, time %.0fms\n",
		   n_packets_sent,
		   n_packets_received,
		   (F32)(n_packets_sent - n_packets_received) * 100.0f / (F32)(n_packets_sent),
		   (F32)(nsecs / 1e6) + (secs * 1000));

	exit(0);
}

/*
TODO:
-A
-I
-L
-l
-M
-n
-O
-p
-q
-Q
-r
-U
-V
-w
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
  -A                 use adaptive ping\n\
  -c <count>         stop after <count> replies\n\
  -D                 print timestamps\n\
  -d                 use SO_DEBUG socket option\n\
  -f                 flood ping\n\
  -h                 print help and exit\n\
  -I <interface>     either interface name or address\n\
  -i <interval>      seconds between sending each packet\n\
  -L                 suppress loopback of multicast packets\n\
  -l <preload>       send <preload> number of packages while waiting replies\n\
  -m <mark>          tag the packets going out\n\
  -M <pmtud opt>     define mtu discovery, can be one of <do|dont|want>\n\
  -n                 no dns name resolution\n\
  -O                 report outstanding replies\n\
  -p <pattern>       contents of padding byte\n\
  -q                 quiet output\n\
  -Q <tclass>        use quality of service <tclass> bits\n\
  -s <size>          use <size> as number of data bytes to be sent\n\
  -S <size>          use <size> as SO_SNDBUF socket option value\n\
  -t <ttl>           define time to live\n\
  -U                 print user-to-user latency\n\
  -v                 verbose output\n\
  -V                 print version and exit\n\
  -w <deadline>      reply wait <deadline> in seconds\n\
  -W <timeout>       time to wait for response\n\
\n\
IPv4 options:\n\
  -4                 use IPv4\n\
  -b                 allow pinging broadcast\n\
  -R                 record route\n\
  -T <timestamp>     define timestamp, can be one of <tsonly|tsandaddr|tsprespec>\n\
\n\
IPv6 options:\n\
  -6                 use IPv6\n\
  -F <flowlabel>     define flow label, default is random\n\
  -N <nodeinfo opt>  use icmp6 node info query, try <help> as argument\n");
}