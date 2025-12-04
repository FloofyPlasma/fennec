TARGET = linux
ifeq ($(TARGET),linux)
CFLAGS += -std=c23 -Ofast -Wall -Wextra -Wpedantic -Werror
else
$(error unsupported TARGET)
endif

CFILES = src/main.c

OBJS = $(addsuffix .o, $(basename $(CFILES)))

.PHONY: all

all: fennec$(TARGET_FILE_EXTENSION)

fennec$(TARGET_FILE_EXTENSION): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -rf fennec fennec.exe $(OBJS)
