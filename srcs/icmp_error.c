/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   icmp_error.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/29 05:07:20 by reclaire          #+#    #+#             */
/*   Updated: 2024/08/29 05:24:14 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"
#include <libft/io.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

void ip_header_print(t_ip_header *hdr)
{
	ft_printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst Data\n");
	ft_printf(" %1x  %1x  %02x %04x %04x",
	       hdr->ver, hdr->ihl, hdr->tos, hdr->len, hdr->id);
	ft_printf("   %1x %04x", ((hdr->flgs_frg) & 0xe000) >> 13,
	       (hdr->flgs_frg) & 0x1fff);
	ft_printf("  %02x  %02x %04x", hdr->ttl, hdr->protocol, hdr->check);
	ft_printf(" %s ", inet_ntoa(*(struct in_addr *)&hdr->src_addr));
	ft_printf(" %s ", inet_ntoa(*(struct in_addr *)&hdr->dst_addr));
	ft_printf("\n");
}


void icmp_print_error(t_ip_header *ip_hdr, t_icmp_header *hdr, bool verbose)
{
	switch (hdr->type)
	{
	case ICMP_MSG_ECHO_REPLY:
		ft_printf("Echo Reply\n");
		break;
	case ICMP_MSG_DESTINATION_UNREACHABLE:
		switch (hdr->code)
		{
		case ICMP_NET_UNREACH:
			ft_printf("Destination Net Unreachable\n");
			break;
		case ICMP_HOST_UNREACH:
			ft_printf("Destination Host Unreachable\n");
			break;
		case ICMP_PROT_UNREACH:
			ft_printf("Destination Protocol Unreachable\n");
			break;
		case ICMP_PORT_UNREACH:
			ft_printf("Destination Port Unreachable\n");
			break;
		case ICMP_FRAG_NEEDED:
			ft_printf("Frag needed and DF set\n");
			break;
		case ICMP_SR_FAILED:
			ft_printf("Source Route Failed\n");
			break;
		case ICMP_NET_UNKNOWN:
			ft_printf("Destination Net Unknown\n");
			break;
		case ICMP_HOST_UNKNOWN:
			ft_printf("Destination Host Unknown\n");
			break;
		case ICMP_HOST_ISOLATED:
			ft_printf("Source Host Isolated\n");
			break;
		case ICMP_NET_ANO:
			ft_printf("Destination Net Prohibited\n");
			break;
		case ICMP_HOST_ANO:
			ft_printf("Destination Host Prohibited\n");
			break;
		case ICMP_NET_UNR_TOS:
			ft_printf("Destination Net Unreachable for Type of Service\n");
			break;
		case ICMP_HOST_UNR_TOS:
			ft_printf("Destination Host Unreachable for Type of Service\n");
			break;
		case ICMP_PKT_FILTERED:
			ft_printf("Packet filtered\n");
			break;
		case ICMP_PREC_VIOLATION:
			ft_printf("Precedence Violation\n");
			break;
		case ICMP_PREC_CUTOFF:
			ft_printf("Precedence Cutoff\n");
			break;
		default:
			ft_printf("Dest Unreachable, Bad Code: %d\n", hdr->code);
			break;
		}
		if (verbose && ip_hdr != NULL)
			ip_header_print(ip_hdr);
		break;
	case ICMP_SOURCE_QUENCH:
		ft_printf("Source Quench\n");
		if (verbose && ip_hdr != NULL)
			ip_header_print(ip_hdr);
		break;
	case ICMP_REDIRECT:
		switch (hdr->code)
		{
		case ICMP_REDIR_NET:
			ft_printf("Redirect Network");
			break;
		case ICMP_REDIR_HOST:
			ft_printf("Redirect Host");
			break;
		case ICMP_REDIR_NETTOS:
			ft_printf("Redirect Type of Service and Network");
			break;
		case ICMP_REDIR_HOSTTOS:
			ft_printf("Redirect Type of Service and Host");
			break;
		default:
			ft_printf("Redirect, Bad Code: %d", hdr->code);
			break;
		}
		if (ip_hdr)
			ft_printf("(New nexthop: %s)\n", addr_to_str(hdr->req.redirect.gateway_addr));
		if (verbose && ip_hdr != NULL)
			ip_header_print(ip_hdr);
		break;
	case ICMP_ECHO:
		ft_printf("Echo Request\n");
		break;
	case ICMP_TIME_EXCEEDED:
		switch (hdr->code)
		{
		case ICMP_EXC_TTL:
			ft_printf("Time to live exceeded\n");
			break;
		case ICMP_EXC_FRAGTIME:
			ft_printf("Frag reassembly time exceeded\n");
			break;
		default:
			ft_printf("Time exceeded, Bad Code: %d\n", hdr->code);
			break;
		}
		if (verbose && ip_hdr != NULL)
			ip_header_print(ip_hdr);
		break;
	case ICMP_PARAMETERPROB:
		ft_printf("Parameter problem: pointer = %u\n", ntohl(hdr->req.param_problem.ptr) >> 24);
		if (verbose && ip_hdr != NULL)
			ip_header_print(ip_hdr);
		break;
	case ICMP_TIMESTAMP:
		ft_printf("Timestamp\n");
		break;
	case ICMP_TIMESTAMPREPLY:
		ft_printf("Timestamp Reply\n");
		break;
	case ICMP_INFO_REQUEST:
		ft_printf("Information Request\n");
		/* XXX ID + Seq */
		break;
	case ICMP_INFO_REPLY:
		ft_printf("Information Reply\n");
		/* XXX ID + Seq */
		break;
#ifdef ICMP_MASKREQ
	case ICMP_MASKREQ:
		ft_printf("Address Mask Request\n");
		break;
#endif
#ifdef ICMP_MASKREPLY
	case ICMP_MASKREPLY:
		ft_printf("Address Mask Reply\n");
		break;
#endif
	default:
		ft_printf("Bad ICMP type: %d\n", hdr->type);
	}
}