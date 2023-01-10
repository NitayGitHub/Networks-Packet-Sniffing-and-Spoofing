all: Sniffer

Sniffer: Sniffer.c
	gcc Sniffer.c -o Sniffer -lpcap
	
clean:
	rm -f *.o Sniffer log.txt
	
runsniff:
	sudo ./Sniffer
