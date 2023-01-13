all: Sniffer Spoofer

Sniffer: Sniffer.c
	gcc Sniffer.c -o Sniffer -lpcap

Spoofer: Spoofer.c
	gcc Spoofer.c -o Spoofer
	
clean:
	rm -f *.o Sniffer log.txt Spoofer
	
runsniff:
	sudo ./Sniffer

runspoof:
	./Spoofer
