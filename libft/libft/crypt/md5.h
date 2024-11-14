/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md5.h                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/11/09 22:56:32 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/12 15:05:46 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#if !defined(FT_MD5_H)
#define FT_MD5_H

#include "../_libft.h"

struct s_md5_state
{
  U32 state[4];  /* state (ABCD) */
  U32 count[2];  /* number of bits, modulo 2^64 (lsb first) */
  U8 buffer[64]; /* input buffer */
};

void ft_md5_init(struct s_md5_state *state);
void ft_md5_update(struct s_md5_state *state, const U8 *input, U32 inputLen);
void ft_md5_final(struct s_md5_state *state, U8 digest[16]);

#endif