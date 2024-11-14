/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   rotate.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/06 22:56:39 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/10 21:51:53 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include "libft/maths.h"

#include <math.h>

t_v2	ft_rotate2(t_v2 v, F32 angle, t_v2 origin)
{
	t_v2	p;
	t_v2	tmp;

	p.x = v.x - origin.x;
	p.y = v.y - origin.y;
	tmp.x = p.x * cos(angle) - p.y * sin(angle);
	tmp.y = p.x * sin(angle) + p.y * cos(angle);
	return (vec2(tmp.x + origin.x, tmp.y + origin.y));
}
