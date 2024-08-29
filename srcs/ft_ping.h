/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ping.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/28 16:13:16 by reclaire          #+#    #+#             */
/*   Updated: 2024/08/29 20:58:52 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_PING_H

#include "libft/types.h"

typedef struct s_ip_header
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	U8 ihl:4; // Internet header length
	U8 ver:4; // 4:IPv4 6:IPv6
#else
	U8 ver:4; // 4:IPv4 6:IPv6
	U8 ihl:4; // Header length
#endif
	U8 tos; // Deprecated. 0
	U16 len; // Total packet length
	U16 id; // Identification
	U16 flgs_frg; // Flags / frag off
	U8 ttl;
	U8 protocol;
	U16 check; // Header checksum
	U32 src_addr;
	U32 dst_addr;
	/* opts */
}	t_ip_header;

#define ICMP_MSG_DESTINATION_UNREACHABLE 3
#define ICMP_MSG_TIME_EXCEEDED 11
#define ICMP_MSG_PARAMETER_PROBLEM 12
#define ICMP_MSG_SOURCE_QUENCH 4
#define ICMP_MSG_REDIRECT 5
#define ICMP_MSG_ECHO 8
#define ICMP_MSG_ECHO_REPLY 0
#define ICMP_MSG_TIMESTAMP 13
#define ICMP_MSG_TIMESTAMP_REPLY 14
#define ICMP_MSG_INFORMATION 15
#define ICMP_MSG_INFORMATION_REPLY 16

#define ICMP_HEADER_MIN_SIZE 8
#define ICMP_HEADER_MAX_SIZE 20
typedef struct s_icmp_header
{
	U8 type;
	U8 code;
	U16 checksum;

	union {
		/*
		Destination unreachable
		type: 3
		codes:
		0 = net unreachable (gateway)
		1 = host unreachable (gateway)
		2 = protocol unreachable (host)
		3 = port unreachable (host)
		4 = fragmentation needed and DF set (gateway)
		5 = source route failed (gateway)
		*/
		struct {
			U32 unused;
		} dest_unreachable;
		
		/*
		Time exceeded
		type: 11
		codes:
		0 = ttl exceeded in transit
		1 = fragment reassembly time exceeded
		*/
		struct {
			U32 unused;
		} time_exceeded;
	
		/*
		Invalid ICMP header
		type: 12
		codes:
		0 = ptr indicates the byte ofs where there is an error
		*/
		struct {
			U32 ptr; // >> 24
		} param_problem;

		/*
		Gateway couldn't process the message
		type: 4
		codes:
		0 =
		*/
		struct {
			U32 unused;
		} src_quench;
	
		/*
		Redirect
		type: 5
		codes:
		0 = Redirect datagrams for the Network
		1 = Redirect datagrams for the Host
		2 = Redirect datagrams for the Type of Service and Network
		3 = Redirect datagrams for the Type of Service and Host	
		*/
		struct {
			U32 gateway_addr;
		} redirect;

		/*
		Echo
		type: 8
		codes:
		0 = id is set to track messages
		*/
		struct {
			U16 id;
			U16 seq;
		} echo;

		/*
		Echo reply
		type: 0
		codes:
		0 = id is set to track messages
		*/
		struct {
			U16 id;
			U16 seq;
		} echo_reply;

		/*
		Timestamp
		type: 13
		codes:
		0 = id is set to track messages
		*/
		struct {
			U16 id;
			U16 seq;
			U32 src_timestamp;
			U32 rcv_timestamp;
			U32 transmit_timestamp;
		} timestamp;

		/*
		Timestamp reply
		type: 14
		codes:
		0 = id is set to track messages
		*/
		struct {
			U16 id;
			U16 seq;
			U32 src_timestamp;
			U32 rcv_timestamp;
			U32 transmit_timestamp;
		} timestamp_reply;

		/*
		Information request
		type: 15
		codes:
		0 = id is set to track messages
		*/
		struct {
			U16 id;
			U16 seq;
		} information;

		/*
		Information reply
		type: 16
		codes:
		0 = id is set to track messages
		*/
		struct {
			U16 id;
			U16 seq;
		} information_reply;
	} req;
}	t_icmp_header;

typedef struct s_icmp_packet
{
	U8 *packet;
	U64 packet_size;
	t_ip_header *ip_hdr;
	t_icmp_header *icmp_hdr;
	U8 *payload;
} t_icmp_packet;

string addr_to_str(U32 addr);

t_icmp_packet make_icmp_echo(U32 srcaddr, U32 dstaddr, U64 payload_size, U16 seq, U8 ttl, U64 timestamp);

void ip_header_print(t_ip_header *hdr);
void icmp_print_error(t_ip_header *ip_hdr, t_icmp_header *hdr, bool verbose);

#endif