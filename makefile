all: Sniffer Spoofer Gateway

Sniffer: Sniffer.c
	gcc Sniffer.c -o Sniffer -lpcap

Spoofer: Spoofer.c
	gcc Spoofer.c -o Spoofer

Gateway: Gateway.c
	gcc Gateway.c -o Gateway
	
clean:
	rm -f *.o Sniffer log.txt Spoofer Gateway
	
runsn:
	sudo ./Sniffer

runspICMP:
	sudo ./Spoofer ICMP

runspUDP:
	sudo ./Spoofer UDP

rungate:
	./Gateway 8.8.8.8
