/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/03/16 16:43:53 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/11 21:18:02 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"
#include "../file.h"
#include "libft/limits.h"

#if defined(TEST)
#include <stdio.h>
#endif

static S64 write_interface_fd(const_string str, U64 len, void *data)
{
	return ft_write(*((filedesc *)data), (string)str, len);
}

static S64 write_interface_file(const_string str, U64 len, void *data)
{
	return ft_fwrite(data, (string)str, len);
}

S64 ft_printf(const_string fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	U64 out = ft_vfprintf(ft_fstdout, fmt, args);
	va_end(args);
	return out;
}

S64 ft_fprintf(t_file *file, const_string fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	U64 out = ft_vfprintf(file, fmt, args);
	va_end(args);
	return out;
}

S64 ft_dprintf(filedesc fd, const_string fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	U64 out = ft_vdprintf(fd, fmt, args);
	va_end(args);
	return out;
}

S64 ft_vprintf(const_string fmt, va_list args)
{
	return ft_vfprintf(ft_fstdout, fmt, args);
}

S64 ft_vfprintf(t_file *file, const_string fmt, va_list args)
{
	U64 ret;

	ft_ffilelock(file);
	ret = printf_internal(fmt, args, write_interface_file, file);
	ft_ffileunlock(file);
	return ret;
}

S64 ft_vdprintf(filedesc fd, const_string fmt, va_list args)
{
	return printf_internal(fmt, args, write_interface_fd, &fd);
}

struct s_wr_i_str_data
{
	U64 n;
	string str;
};

static S64 write_interface_str(const_string str, U64 len, void *data)
{
	struct s_wr_i_str_data *_data = (struct s_wr_i_str_data *)data;

	U64 i = 0;
	while (i < len && i < _data->n)
	{
		_data->str[i] = str[i];
		i++;
	}
	_data->str += i;
	_data->n -= i;
	return i;
}

S64 ft_sprintf(string str, const_string fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	U64 out = ft_vsprintf(str, fmt, args);
	va_end(args);
	return out;
}

S64 ft_snprintf(string str, U64 n, const_string fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	U64 out = ft_vsnprintf(str, n, fmt, args);
	va_end(args);
	return out;
}

S64 ft_vsprintf(string str, const_string fmt, va_list args)
{
	return ft_vsnprintf(str, U64_MAX, fmt, args);
}

S64 ft_vsnprintf(string str, U64 n, const_string fmt, va_list args)
{
	struct s_wr_i_str_data data = {n, str};
	U64 out = printf_internal(fmt, args, write_interface_str, &data);
	if (data.n == 0 && n != 0)
		*(data.str - 1) = '\0';
	else
		out += write_interface_str("", 1, &data);
	return out;
}

#if defined(TEST)

// gcc -g  -DFT_OS_LINUX -DTEST  -I../../ -L../../  *.c  -lft -lm
int main()
{
#define TEST_STR(fmt, ...) { ft_printf(fmt, __VA_ARGS__); printf("  "); printf(fmt, __VA_ARGS__); printf("\n"); }
	TEST_STR("|%5c|", 'a');
	TEST_STR("|%05c|", 'a');
	TEST_STR("|% 5c|", 'a');
	TEST_STR("|%-5c|", 'a');
	TEST_STR("|%- 5c|", 'a');
	TEST_STR("|%-05c|", 'a');
}

#endif
