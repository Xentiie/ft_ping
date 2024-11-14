/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   addler.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/11/09 15:23:59 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/09 23:09:42 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#if !defined(FT_ADDLER_H)
#define FT_ADDLER_H

# include "../_libft.h"

U64 ft_adler32(U8 *data, U64 len, U64 adler);
U32 ft_adler32_end(U64 adler);

#endif