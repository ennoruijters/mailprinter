mailprinter: $(wildcard *.c) $(wildcard *.h)
	$(CC) $(CFLAGS) -o mailprinter $(wildcard *.c)
