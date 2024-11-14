/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   deflate_int.h                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/05/31 15:06:59 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/09 23:09:42 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#if !defined(DEFLATE_H)
# define DEFLATE_H

# include "libft_int.h"

# include "libft/compression/deflate.h"

// clang-format off
struct s_ll_code
{
	U16 code;
	U8 bits;
};

struct s_table_entry
{
	U16 min;
	U16 max;
	U16 mask;
	U8 extra_bits;
};

extern const struct s_ll_code		ll_codes_full[];
extern const U16					ll_codes[];
extern const U8						ll_codes_bits[];

// ll_code: index + 257
extern const struct s_table_entry	ll_table[];
extern const U8						ll_table_size;

extern const struct s_table_entry	offset_table[];
extern const U8						offset_table_size;
// clang-format on

#endif