/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strdup.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/23 14:51:38 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/11 17:27:29 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include "libft/strings.h"

#include <stdlib.h>

string ft_strdup(const_string str)
{
	return ft_strdup_l(str, NULL);
}

string ft_strdup_l(const_string str, U64 *len)
{
	U64 l;
	string dup;

	if (len == NULL)
		len = &l;

	if (UNLIKELY(str == NULL))
	{
		*len = 0;
		__FTRETURN_ERR(NULL, FT_EINVPTR);
	}

	*len = ft_strlen(str);
	if (UNLIKELY((dup = malloc(sizeof(U8) * ((*len) + 1))) == NULL))
	{
		*len = 0;
		__FTRETURN_ERR(NULL, FT_EOMEM);
	}

	ft_memcpy(dup, str, (*len) + 1);
	__FTRETURN_OK(dup);
}

string ft_strndup(const_string str, U64 n)
{
	return ft_strndup_l(str, n, NULL);
}

string ft_strndup_l(const_string str, U64 n, U64 *len)
{
	U64 l;
	string dup;

	if (len == NULL)
		len = &l;

	if (UNLIKELY(str == NULL))
	{
		*len = 0;
		__FTRETURN_ERR(NULL, FT_EINVPTR);
	}

	*len = ft_strlen(str);
	(*len) = (*len) < n ? (*len) : n;
	if (UNLIKELY((dup = malloc((sizeof(U8) * (*len) + 1))) == NULL))
	{
		*len = 0;
		__FTRETURN_ERR(NULL, FT_EOMEM);
	}

	ft_memcpy(dup, str, (*len) + 1);
	__FTRETURN_OK(dup);
}
