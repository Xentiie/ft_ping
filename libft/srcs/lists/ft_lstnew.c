/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstnew.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/03/01 16:42:40 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/10 22:42:05 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include "libft/lists.h"

#include <stdlib.h>

t_list	*ft_lstnew(void *content)
{
	t_list *new;

	if (UNLIKELY((new = malloc(sizeof(t_list))) == NULL))
		__FTRETURN_ERR(NULL, FT_EOMEM);
	new->content = content;
	new->prev = NULL;
	new->next = NULL;
	__FTRETURN_OK(new);
}
