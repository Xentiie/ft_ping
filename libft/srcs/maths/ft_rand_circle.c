/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_rand_circle.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/08 01:17:38 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/10 21:51:37 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include "libft/maths.h"

#include <math.h>

t_v2	ft_rand_circle(U32 seed)
{
	return (vec2(ft_sin(ft_frand(seed)), ft_cos(ft_frand(seed) + 1)));
}
