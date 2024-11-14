/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstdelone.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/03/01 20:02:15 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/10 21:49:46 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include "libft/lists.h"

#include <stdlib.h>

void	ft_lstdelone(t_list *lst, void (*del)(void *))
{
	if (UNLIKELY(lst == NULL))
		__FTRETURN_ERR(, FT_EINVPTR);

	if (del)
		del(lst->content);
	free(lst);

	__FTRETURN_OK();
}
