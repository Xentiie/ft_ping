/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnstr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/22 21:47:40 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/10 22:35:44 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include "libft/strings.h"

const_string	ft_strnstr(const_string haystack, const_string needle, U64 len)
{
	U64 i;
	U64 needle_len;

	i = 0;
	needle_len = ft_strlen(needle);
	while (haystack[i] && i < len)
	{
		if (!ft_strncmp(&haystack[i], needle, needle_len))
			return &haystack[i];
		i++;
	}
	return NULL;
}
