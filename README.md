# Packet-Sniffing-and-Spoofing
## **Introduction**
This assignment includes four tasks: writing a sniffer to sniff TCP packets, writing a spoofer to spoof ICMP packets, combining the sniffing and spoofing techniques to establish an attacker machine, 
and lastly creating a gateway program that redirects incoming packets from one port to another.

## **Installation**

To install Project Title, follow these steps:

1. Clone the repository: **`git clone https://github.com/NitayGitHub/Networks-Packet-Sniffing-and-Spoofing.git`**
2. Navigate to the project directory: **`cd Networks-Packet-Sniffing-and-Spoofing`**
3. Build the project: **`make all`**
4. Start the project: look at the makefile for a list of commands to run each program individually.

## **Task A**
Create a sniffer to sniff TCP packets. The format of each packet should be { source_ip: <input>, dest_ip: <input>, source_port: <input>, dest_port: <input>, timestamp: <input>, total_length: <input>, cache_flag: <input>, steps_flag: <input>, type_flag: <input>, status_code: <input>, cache_control: <input>, data: <input> }. The data output may be unreadable in ASCII form so write the output as hexadecimal.

## **Task B**
Write a spoofer for spoofing ICMP packets.
The spoofer should fake the sender’s IP and have a valid response. Your code should be able to spoof other protocols with small changes.

## **Task C**
In this task, you will combine the sniffing and spoofing techniques to implement the following sniff-and-then-spoof program. You will use the local callback network and two processes as two separate machines. From machine A, you ping an IP X. This will generate an ICMP echo request packet. If X is alive, the ping program will receive an echo reply, and print out the response. Your sniff-and-then-spoof program runs on the attacker machine, which monitors the local callback network through packet sniffing. Whenever it sees an ICMP echo request, regardless of what the target IP address is, your program should immediately send out an echo reply using the packet spoofing technique.
Please follow these steps: 
a. First run – send a ping from Host A to Host B. 
b. Second run – send a ping from Host A to a WAN IP (e.g., google DNS – 8.8.8.8). 
c. Third run – send a ping from Host A to a fake IP. 

## **Task D**
In this task, you will implement the Gateway.c file.
The program will take the name of a host on the command line and create a datagram socket for that host (using port number P+1). It will also create another datagram socket where it can receive datagrams from any host on port number P. Next, it enters an infinite loop in each iteration of which it receives a datagram from port P, then samples a random number using ((float)random())/((float)RAND_MAX) - if the number obtained is greater than 0.5, the datagram received is forwarded onto the outgoing socket to port P+1, otherwise the datagram is discarded and the process goes back to waiting for another incoming datagram. Note that this gateway will simulate an unreliable network that loses datagrams with a 50% probability.
