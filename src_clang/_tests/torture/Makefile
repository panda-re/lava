all: torture

torture: torture.c
	$(CC) -c -o torture $<

torture-df: torture.df.c
	$(CC) -c -o torture-df $<

clean:
	rm -f torture
