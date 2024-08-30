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
