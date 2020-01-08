#all:
	#gcc udp_modified2.c
	#sudo ./a.out 127.0.0.1 127.0.0.1
all:
	gcc dns.c
	sudo ./a.out 127.0.0.1 127.0.0.1