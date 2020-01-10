all:
	gcc -g dns.c
	sudo ./a.out 127.0.0.1 127.0.0.1