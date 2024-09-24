# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: reclaire <reclaire@student.42mulhouse.f    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2022/02/25 09:55:54 by reclaire          #+#    #+#              #
#    Updated: 2024/09/24 19:07:41 by reclaire         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME=ft_ping
.DEFAULT_GOAL := all
all: _libft $(NAME)

RM=rm -rf
CC=gcc
CFLAGS=-DFT_OS_LINUX -g -Wall -Wextra -O3 -Wno-unknown-pragma
INCLUDES=-I../libft -I./
LIBS_PATHS=-L../libft
LIBS=-lft -lm

$(NAME):	./main.c
			$(CC) $(CFLAGS) $(INCLUDES) ./main.c $(LIBS_PATHS) $(LIBS) -o $(NAME)

install: $(NAME)
			chown root:root ./$(NAME)
			chmod u+s ./$(NAME)

clean:

fclean:	clean
			$(RM) $(NAME)

re:			fclean all

_libft:
	$(MAKE) -C ./libft

.PHONY: all clean fclean re install _libft
