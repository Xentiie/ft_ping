/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   forbidden_chars.h                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/25 05:57:04 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/09 23:09:42 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#if !defined(FORBIDDEN_CHARS_H)
#define FORBIDDEN_CHARS_H

#include "libft/types.h"

const char forbidden_chars_linux[] = {
	'/',
};

const char forbidden_chars_windows[] = {
	'/',
	'\\',
	':',
	'*',
	'?',
	'"',
	'<',
	'>',
	'|',
};

static inline const_string get_forbidden_chars(S32 target)
{
	if (target & FT_TARGET_LINUX)
		return forbidden_chars_linux;
	else if (target & FT_TARGET_WIN)
		return forbidden_chars_windows;

	return forbidden_chars_linux;
}

#endif