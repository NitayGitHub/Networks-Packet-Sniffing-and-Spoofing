all: Sniffer

Sniffer: Sniffer.c
	gcc Sniffer.c -o Sniffer -lpcap
	
clean:
	rm -f *.o Sniffer
	
runsniff:
	sudo ./Sniffer
