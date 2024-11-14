/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstsort.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/09 17:28:10 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/10 21:49:18 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include "libft/lists.h"

void ft_lstsort(t_list **pp, S32 (*key)(void *, void *))
{
	t_list *p = *pp;
	*pp = NULL;

	while (p)
	{
		t_list **lhs = &p;
		t_list **rhs = &p->next;
		bool swapped = FALSE;

		while (*rhs)
		{
			if (key((*lhs)->content, (*rhs)->content) > 0)
			{
				void *tmp = *rhs;
				*rhs = *lhs;
				*lhs = tmp;

				tmp = (*rhs)->next;
				(*rhs)->next = (*lhs)->next;
				(*lhs)->next = tmp;

				lhs = &(*lhs)->next;
				swapped = TRUE;
			}
			else
			{
				lhs = rhs;
				rhs = &(*rhs)->next;
			}
		}
		*rhs = *pp;

		if (swapped)
		{
			*pp = *lhs;
			*lhs = NULL;
		}
		else
		{
			*pp = p;
			break;
		}
	}
}
