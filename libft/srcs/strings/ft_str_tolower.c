/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_str_tolower.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/11 23:58:00 by reclaire          #+#    #+#             */
/*   Updated: 2024/09/03 03:11:09 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

void	ft_str_tolower(string str)
{
	while (*str)
	{
		*str = ft_tolower(str);
		str++;
	}
}
