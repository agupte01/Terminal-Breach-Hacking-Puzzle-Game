CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -O2
TARGET  = terminal_breach
SRCS    = main.c commands.c levels.c utils.c network.c puzzles.c save.c
OBJS    = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
