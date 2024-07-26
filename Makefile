CC=gcc

all:
	$(CC) -Wall -O3 sniffer.c -o sniffer.out

format:
	find . -regex '.*\.[c|h]' | xargs clang-format -i

clean:
	rm -f sniffer.out

.PHONY: clean format
