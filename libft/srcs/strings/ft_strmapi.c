/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strmapi.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/23 18:19:15 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/11 17:28:55 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include "libft/strings.h"

string ft_strmapi(const_string s, U8 (*f)(U64, U8))
{
	U64 i;
	string new;

	if (UNLIKELY((new = ft_strdup(s)) == NULL))
		__FTRETURN_ERR(NULL, FT_EOMEM);

	i = 0;
	while (s[i])
	{
		new[i] = f(i, s[i]);
		i++;
	}
	return new;
}
