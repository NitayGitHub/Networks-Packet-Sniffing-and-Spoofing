all: Sniffer

Sniffer: Sniffer.c
	gcc Sniffer.c -o Sniffer
	
clean:
	rm -f *.o parta watchdog partb ping
	
runsniff:
	./Sniffer
