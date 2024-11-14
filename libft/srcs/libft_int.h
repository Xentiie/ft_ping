/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft_int.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/02/11 19:57:38 by reclaire          #+#    #+#             */
/*   Updated: 2024/11/09 23:09:42 by reclaire         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#if !defined(LIBFT_INT_H)
# define LIBFT_INT_H

# include "../libft/_libft.h"
# include "../libft/std.h"

/*Private usage*/
# define __FTRETURN_OK(ret) do { ft_errno=FT_OK; return ret; } while (0)

# if defined(DEBUG)
#  define __FTRETURN_ERR(ret, err) do { ft_errno = err ; ft_debug_break(); return ret; } while (0)
# else
#  define __FTRETURN_ERR(ret, err) do { ft_errno = err ; return ret; } while (0)
# endif

# if !defined(LIBFT_AVOID_ALLOCA)
#  if defined(FT_OS_WIN) || defined(FT_OS_WIN_WSL)
#   include <malloc.h>
#  else
#   include <alloca.h>
#  endif
#  define a_malloc(...) alloca(__VA_ARGS__)
#  define a_free(...)
# endif

# define MAX(x, y) (x > y ? x : y)
# define MIN(x, y) (x < y ? x : y)

#endif