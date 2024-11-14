/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   printf_internal.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/03/11 14:08:44 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/11 21:18:54 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"
#include "libft/strings.h"
#include "libft/limits.h"

#include <stdlib.h>

#if defined(FT_OS_WIN)
#include <malloc.h>
#else
#include <alloca.h>
#endif

#if defined(TEST)
#include <stdio.h>
#endif

static const_string l_base16 = "0123456789abcdef";
static const_string u_base16 = "0123456789ABCDEF";

#define GET_ARG(type) (*(type *)(&args[pos_nextarg == -1 ? nextarg++ : pos_nextarg]))
#define BUF_SIZE U64_MAX_MAG + 1

static S64 pad(char c, S64 s, t_fmtwr_i wr_i, void *data)
{
	char _padding[512];
	S64 out;
	S64 ret;

	out = 0;
	ft_memset(_padding, c, MIN(s, (S64)sizeof(_padding)));
	while (s > 0)
	{
		if (UNLIKELY((ret = wr_i(_padding, MIN(s, (S64)sizeof(_padding)), data)) == -1))
			return -1;
		out += ret;
		s -= ret;
	}
	return out;
}

static S64 pad_sp(S64 s, t_fmtwr_i wr_i, void *data)
{
	static char _padding[512] = {[0 ... 511] = ' '};
	S64 out;
	S64 ret;

	out = 0;
	while (s > 0)
	{
		if (UNLIKELY((ret = wr_i(_padding, MIN(s, (S64)sizeof(_padding)), data)) == -1))
			return -1;
		out += ret;
		s -= ret;
	}
	return out;
}

static S64 pad_ze(S64 s, t_fmtwr_i wr_i, void *data)
{
	static char _padding[512] = {[0 ... 511] = '0'};
	S64 out;
	S64 ret;

	out = 0;
	while (s > 0)
	{
		if (UNLIKELY((ret = wr_i(_padding, MIN(s, (S64)sizeof(_padding)), data)) == -1))
			return -1;
		out += ret;
		s -= ret;
	}
	return out;
}

S64 printf_internal(const_string fmt, va_list vaargs, t_fmtwr_i wr_i, void *data)
{
	const_string base;
	U64 basel;

	char buffer[BUF_SIZE];
	const_string str = NULL;
	S64 str_len = 0;

	const_string sv = fmt;

	U64 *args;

	S32 nextarg;
	S32 pos_nextarg;

	S64 cnt;
	S64 ret;
	S32 n, n2;

	if (UNLIKELY(!build_arg_table(fmt, vaargs, &args)))
		__FTRETURN_ERR(-1, FT_EOMEM);
	nextarg = 0;
	cnt = 0;
	while (*fmt)
	{
		while (*fmt && *fmt != '%')
			fmt++;
		if (*fmt == '\0' || *(fmt + 1) == '\0')
			break;
		if (*(fmt + 1) == '%')
		{
			fmt += 2;
			continue;
		}
		if (fmt > sv)
		{
			if (UNLIKELY((ret = wr_i(sv, fmt - sv, data)) == -1))
				return -1;
			cnt += ret;
		}
		fmt++;

		S32 width = -1;
		S32 prec = -1;
		S32 flags = 0;
		char sign = '\0';
		base = l_base16;
		basel = 10;

		pos_nextarg = parse_specifier_n(&fmt);
		flags |= parse_flags(&fmt);
		if (flags & FL_SPACESIGN)
			sign = ' ';
		if (flags & FL_SHOWSIGN)
			sign = '+';

		n = parse_width(&fmt, &n2, &nextarg);
		if (n2 < 0)
			width = n;
		else
			width = *(S32 *)(&args[n2]);

		n = parse_prec(&fmt, &n2, &nextarg);
		if (n2 < 0)
			prec = n;
		else
			prec = *(S32 *)(&args[n2]);
		flags |= parse_size_flags(&fmt);

		switch (*fmt)
		{
		case 'n':
			if (flags & FL_T_LONGLONG)
				*GET_ARG(LS64 *) = cnt;
			else if (flags & FL_T_LONG)
				*GET_ARG(S64 *) = cnt;
			else if (flags & FL_T_SHORT)
				*GET_ARG(S16 *) = cnt;
			else
				*GET_ARG(S32 *) = cnt;
			fmt++;
			continue;

		case 'c':
			buffer[0] = GET_ARG(char);
			str = buffer;
			str_len = 1;
			sign = '\0';
			break;

		case 'D':
			flags |= FL_T_LONG;
			/* fallthrough */
		case 'd':
		case 'i':
			flags |= FL_NUMBER;
			break;

		case 'e':
		case 'E':
		case 'f':
		case 'g':
		case 'G':
			flags |= FL_FP;
			break;

		case 'X':
			base = u_base16;
			flags |= FL_HEX_M;
			/* fallthrough */
		case 'x':
			basel = 16;
			flags |= FL_UNSIGNED | FL_NUMBER | ((flags & FL_ALT) ? FL_HEX : 0);
			break;

		case 'U':
			flags |= FL_T_LONGLONG;
			/* fallthrough */
		case 'u':
			flags |= FL_UNSIGNED | FL_NUMBER;
			break;

		case 'O':
			flags |= FL_T_LONGLONG;
			/* fallthrough */
		case 'o':
			basel = 8;
			flags |= FL_UNSIGNED | FL_NUMBER;
			break;

		case 'p':
			basel = 16;
			flags = (flags & ~FL_T_LONGLONG) | FL_T_LONG | FL_UNSIGNED | FL_NUMBER | FL_HEX;
			break;
		case 's':
			str = GET_ARG(const_string);
			if (str == NULL)
				str = "(null)";
			if (prec >= 0)
			{
				const_string tmp = ft_memchr(str, '\0', prec);
				if (tmp != NULL)
				{
					str_len = tmp - str;
					if (str_len > prec)
						str_len = prec;
				}
				else
					str_len = prec;
			}
			else
				str_len = ft_strlen(str);
			sign = '\0';
			break;

		default:
			//char tmp[2] = {'%', *fmt};
			cnt += wr_i("%", 1, data);
			cnt += wr_i(fmt, 1, data);
			fmt++;
			sv = fmt;
			continue;
		}

		if (flags & FL_NUMBER)
		{
			LU64 value;
			if (flags & FL_UNSIGNED)
			{
				value = (LU64)(flags & FL_T_LONGLONG ? GET_ARG(LU64) : flags & FL_T_LONG ? GET_ARG(U64)
																						 : GET_ARG(U32));
			}
			else
			{
				value = (LU64)(flags & FL_T_LONGLONG ? GET_ARG(LS64) : flags & FL_T_LONG ? GET_ARG(S64)
																						 : GET_ARG(S32));
				if (((LS64)value) < 0)
				{
					value = (LU64)(-(LS64)value);
					sign = '-';
				}
			}

			if (value == 0)
				flags &= ~FL_HEX;
			if (value != 0 || prec != 0)
			{
				U64 n_digits = _ft_utoa(base, basel, 0, value, NULL, BUF_SIZE - 1);
				_ft_utoa(base, basel, n_digits, value, buffer, BUF_SIZE - 1);
				str = buffer;
				str_len = n_digits;
			}
			else
			{
				str = "";
				str_len = 0;
			}
		}

		if (flags & FL_UNSIGNED)
			sign = '\0';

		S64 real_len = str_len < prec ? prec : str_len;
		if (sign)
			real_len++;
		else if (flags & FL_HEX)
			real_len += 2;

		S64 p = width - real_len;
		if ((flags & (FL_LEFTJUST | FL_ZEROPAD)) == 0)
			cnt += pad_sp(p, wr_i, data);

		if (sign)
			cnt += wr_i(&sign, 1, data);
		else if (flags & FL_HEX)
			cnt += wr_i(flags & FL_HEX_M ? "0X" : "0x", 2, data);

		if ((flags & (FL_LEFTJUST | FL_ZEROPAD)) == FL_ZEROPAD)
			cnt += pad_ze(p, wr_i, data);

		cnt += pad_ze(prec - str_len, wr_i, data);
		cnt += wr_i(str, str_len, data);
		if (flags & FL_LEFTJUST)
			cnt += pad_sp(p, wr_i, data);

		fmt++;
		sv = fmt;
	}

	if (fmt > sv)
		cnt += wr_i(sv, fmt - sv, data);

	free(args);
	return cnt;
}
//TODO: 0x 0X only if non zero
