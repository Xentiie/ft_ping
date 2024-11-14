/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_substr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/23 15:39:44 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/10 22:37:29 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include "libft/strings.h"

#include <stdlib.h>

string ft_substr(const_string s, U64 start, U64 len)
{
	const char z = 0;
	string	r;

	if (ft_strlen(s) <= start)
	{
		if (UNLIKELY((r = ft_memdup(&z, 1)) == NULL))
			__FTRETURN_ERR(NULL, FT_EOMEM);
		__FTRETURN_OK(r);
	}
	if (UNLIKELY((r = malloc(sizeof(char) * (len + 1))) == NULL))
		__FTRETURN_ERR(NULL, FT_EOMEM);

	ft_strlcpy(r, (s + start), len + 1);
	__FTRETURN_OK(r);
}
