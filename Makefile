# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2022/02/25 09:55:54 by reclaire          #+#    #+#              #
#    Updated: 2024/08/27 18:12:52 by reclaire         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME		=	libft.so
include config.mk

#CFLAGS		+=	-Wall -Wextra -Werror -O3 -g
CFLAGS		+=	-g -Wall -Wextra -O3
INCLUDES  	+=	-I./ -I./srcs

$(NAME):	_libft $(OBJS)
			$(CC) $(CFLAGS) $(INCLUDES) $(LIBS_PATHS) $(OBJS) $(LIBS) -o $(NAME)

test:
	$(CC) -DFT_OS_LINUX -fprofile-generate -fprofile-arcs -ftest-coverage -I./ ./test.c -L./ -lft -o test

_libft:
	$(MAKE) -C ../libft

.PHONY= test _libft
