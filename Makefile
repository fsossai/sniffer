CC=gcc

all:
	$(CC) -std=c99 -Wall -O3 sniffer.c prints.c -o sniffer.out

format:
	find . -regex '.*\.[c|h]' | xargs clang-format -i

clean:
	rm -f sniffer.out

.PHONY: clean format
