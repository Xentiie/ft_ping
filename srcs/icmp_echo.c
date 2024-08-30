/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   icmp_echo.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/28 23:55:07 by reclaire          #+#    #+#             */
/*   Updated: 2024/08/30 04:13:20 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"
#include "libft/std.h"
#include "libft/io.h"
#include "libft/limits.h"
#include "libft/time.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>

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

t_icmp_packet make_icmp_echo(U32 srcaddr, U32 dstaddr, U64 payload_size, U16 seq, U8 ttl, U64 timestamp)
{
	const U8 icmp_echo_header_size = 8;

	U8 *packet;
	U64 packet_size;

	t_ip_header *ip_header;
	t_icmp_header *icmp_header;
	U8 *payload;

	payload_size += sizeof(U64);

	packet_size = sizeof(t_ip_header) + icmp_echo_header_size + payload_size;
	if ((packet = malloc(packet_size)) == NULL)
	{
		ft_dprintf(ft_stderr, "%s: out of memory\n", ft_argv[0]);
		return (t_icmp_packet){0};
	}
	ft_memset(packet, 0, packet_size);

	ip_header = (t_ip_header *)(packet);
	icmp_header = (t_icmp_header *)(packet + sizeof(t_ip_header));
	payload = (U8 *)(packet + sizeof(t_ip_header) + icmp_echo_header_size);

	*(U64 *)(payload) = timestamp;
	for (U64 i = 0; i < payload_size - sizeof(U64); i++)
		payload[i + sizeof(U64)] = i;

	ip_header->ver = 4;
	ip_header->ihl = sizeof(t_ip_header) / 4;
	ip_header->tos = 0;
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

	return (t_icmp_packet){
		.packet = packet,
		.packet_size = packet_size,
		.ip_hdr = ip_header,
		.icmp_hdr = icmp_header,
		.payload = payload
	};
}
