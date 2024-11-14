/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstmap.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/03/01 20:20:56 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/10 22:41:35 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_int.h"
#include "libft/lists.h"

t_list	*ft_lstmap(t_list *lst, void *(*f)(void *), void (*del)(void *))
{
	t_list	*new_element;

	if (UNLIKELY(lst == NULL))
		__FTRETURN_ERR(NULL, FT_EINVPTR);

	t_list	*new_lst = NULL;
	while (lst)
	{
		if (UNLIKELY((new_element = ft_lstnew(f ? f(lst->content) : lst->content)) == NULL))
		{
			ft_lstclear(&new_lst, del);
			__FTRETURN_ERR(NULL, ft_errno);
		}

		lst = lst->next;
		ft_lstadd_back(&new_lst, new_element);
	}
	return (new_lst);
}
