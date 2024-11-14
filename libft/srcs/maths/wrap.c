/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   wrap.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/06/08 15:54:03 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/10 21:52:33 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include "libft/maths.h"

#include <math.h>

S32	ft_wrap(S32 n, S32 min, S32 max)
{
	S32	range;

	range = max - min + 1;
	n = ((n - min) % range);
	if (n < 0)
		return (max + 1 + n);
	else
		return (min + n);
}

F32	ft_fwrap(F32 x, F32 min, F32 max)
{
	F32	f;

	if (x >= 0)
		f = min;
	else
		f = max;
	return (f + fmod(x, max - min));
}
