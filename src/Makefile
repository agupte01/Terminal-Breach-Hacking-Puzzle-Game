CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -O2
TARGET  = terminal_breach
SRCS    = main.c commands.c levels.c utils.c network.c puzzles.c save.c
OBJS    = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

HDRS    = commands.h levels.h network.h puzzles.h save.h utils.h

# Every object depends on every header: the structs in levels.h are shared,
# so a stale object compiled against an old layout silently corrupts data.
%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
