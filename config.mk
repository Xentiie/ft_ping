NAME=ft_ping
.DEFAULT_GOAL := all
all: objs $(NAME)

RM=rm -rf
CC=gcc
MKLIB=
CFLAGS=-DFT_OS_LINUX 
INCLUDES=-I../libft -I./
LIBS_PATHS=-L../libft
LIBS=-lft -lm
OBJS_PATH=./objs
SRCS=./srcs/main.c ./srcs/icmp_echo.c ./srcs/icmp_error.c
OBJS=./objs/main.o ./objs/icmp_echo.o ./objs/icmp_error.o

objs:
	mkdir -p ./objs
./objs/main.o: ./srcs/main.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/main.c -o ./objs/main.o

./objs/icmp_echo.o: ./srcs/icmp_echo.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/icmp_echo.c -o ./objs/icmp_echo.o

./objs/icmp_error.o: ./srcs/icmp_error.c
	$(CC) $(CFLAGS) $(INCLUDES) -c ./srcs/icmp_error.c -o ./objs/icmp_error.o


clean:
			$(RM) $(OBJS)

fclean:	clean
			$(RM) $(NAME)

re:			fclean all

.PHONY:		 all clean fclean re
