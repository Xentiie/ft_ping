/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   read.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/01/22 20:19:41 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/10 14:47:27 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "file.h"
#include "libft/io.h"

# if defined(FT_OS_WIN)
#  include <windows.h>

S64	ft_read(filedesc fd, char *buffer, U64 size)
{
	S64 bytes_read = 0;
	if (UNLIKELY(ReadFile(fd, buffer, size, (LPDWORD)&bytes_read, NULL) == FALSE))
		__FTRETURN_ERR(-1, FT_ESYSCALL);
	__FTRETURN_OK(bytes_read);
}

# elif defined(FT_OS_LINUX) || defined(FT_OS_MAC)
#  include <unistd.h>

S64 ft_read(filedesc fd, char *buffer, U64 size)
{
	if (buffer == NULL)
		__FTRETURN_ERR(-1, FT_EINVPTR);
	S64 bytes_read = read(fd, buffer, size);
	if (UNLIKELY(bytes_read == -1))
		__FTRETURN_ERR(-1, FT_ESYSCALL);
	__FTRETURN_OK(bytes_read);
}

# endif

S64 ft_fread(t_file *file, char *buffer, U64 size)
{
	S64 ret;

	if (UNLIKELY(!ft_ffilelock(file)))
		return -1;
	ret = ft_read(file->fd, buffer, size);
	ft_ffileunlock(file);
	return ret;
}
