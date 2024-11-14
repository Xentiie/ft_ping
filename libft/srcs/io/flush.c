/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   flush.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/10/12 11:48:16 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/09 23:11:31 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "file.h"
#include "libft/io.h"

void ft_fflush(t_file *file)
{
	ft_write(file->fd, file->buff, file->buff_cnt);
	file->buff_cnt = 0;
}
