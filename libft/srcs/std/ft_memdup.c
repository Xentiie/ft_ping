/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memdup.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/28 17:49:36 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/10 22:45:10 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"

#include <stdlib.h>

void	*ft_memdup(const void *p, U64 n)
{
	void	*data;

	if (UNLIKELY((data = malloc(n)) == NULL))
		__FTRETURN_ERR(NULL, FT_EOMEM);
	ft_memcpy(data, p, n);
	__FTRETURN_OK(data);
}
