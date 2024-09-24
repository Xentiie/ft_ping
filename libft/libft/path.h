/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   path.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/11 19:49:34 by reclaire          #+#    #+#             */
/*   Updated: 2024/02/20 18:12:54 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_PATH_H
# define LIBFT_PATH_H

# include "_libft.h"

void	ft_path_parse(t_list **lst, string path);
void	ft_path_clean(t_list **path);

#endif