all: Sniffer Spoofer Gateway GatewayClient GatewayHost Sniff_and_spoof

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

Sniff_and_spoof: Sniff_and_spoof.c
	gcc Sniff_and_spoof.c -o Sniff_and_spoof -lpcap
	
clean:
	rm -f *.o Sniffer 319096251_213934599.txt Spoofer Gateway GatewayClient GatewayHost Sniff_and_spoof
	
runsn:
	sudo ./Sniffer

runspICMP:
	sudo ./Spoofer ICMP

runspUDP:
	sudo ./Spoofer UDP

runspTCP:
	sudo ./Spoofer TCP

rungate:
	./Gateway 127.0.0.1

runsnsp:
	sudo ./Sniff_and_spoof
