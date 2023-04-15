build:
	gcc main.c filter.c sniffer.c -lpcap -o ipk-sniffer
clean:
	rm ipk-sniffer