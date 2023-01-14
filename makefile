all: Sniffer Spoofer Gateway GatewayClient GatewayHost

Sniffer: Sniffer.c
	gcc Sniffer.c -o Sniffer -lpcap

Spoofer: Spoofer.c
	gcc Spoofer.c -o Spoofer

Gateway: Gateway.c
	gcc Gateway.c -o Gateway

GatewayClient: GatewayClient.c
	gcc GatewayClient.c -o GatewayClient

GatewayHost: GatewayHost.c
	gcc GatewayHost.c -o GatewayHost
	
clean:
	rm -f *.o Sniffer log.txt Spoofer Gateway GatewayClient GatewayHost
	
runsn:
	sudo ./Sniffer

runspICMP:
	sudo ./Spoofer ICMP

runspUDP:
	sudo ./Spoofer UDP

rungate:
	./Gateway 127.0.0.1
