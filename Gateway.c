#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h> //Provides declarations for sockets
#include <netinet/in.h>
#include <netinet/ip.h> //Provides declarations for ip header
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

#define SERVER_IP_ADDRESS "127.0.0.1"
#define SERVER_PORT 5060

#define P 9998
#define HOST_PORT (P + 1)
#define ANY_HOST_PORT P

struct sockaddr_in HostAddress;
struct sockaddr_in AnyHostAddress;
int host_sock = -1;
int gate_sock = -1;

int open_gateway()
{
    char buffer[80] = {'\0'};
    char message[] = "Hello, from the Server\n";
    int messageLen = strlen(message) + 1;

    // Create socket
    if ((gate_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) // In Windows -1 is SOCKET_ERROR
    {
        printf("Could not create socket : %d", errno);
        return -1;
    }

    // setup Server address structure
    memset((char *)&AnyHostAddress, 0, sizeof(AnyHostAddress));
    AnyHostAddress.sin_family = AF_INET;
    AnyHostAddress.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, (const char *)SERVER_IP_ADDRESS, &(AnyHostAddress.sin_addr));

    // Bind
    if (bind(gate_sock, (struct sockaddr *)&AnyHostAddress, sizeof(AnyHostAddress)) == -1)
    {
        printf("bind() failed with error code : %d", errno);
        return -1;
    }
    printf("After bind(). Waiting for clients");

    // setup Client address structure
    struct sockaddr_in clientAddress;
    socklen_t clientAddressLen = sizeof(clientAddress);

    memset((char *)&clientAddress, 0, sizeof(clientAddress));

    // keep listening for data
    while (1)
    {
        fflush(stdout);

        // zero client address
        memset((char *)&clientAddress, 0, sizeof(clientAddress));
        clientAddressLen = sizeof(clientAddress);

        // clear the buffer by filling null, it might have previously received data
        memset(buffer, '\0', sizeof(buffer));

        int recv_len = -1;

        // try to receive some data, this is a blocking call
        if ((recv_len = recvfrom(gate_sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&clientAddress, &clientAddressLen)) == -1)
        {
            printf("recvfrom() failed with error code : %d", errno);
            break;
        }

        char clientIPAddrReadable[32] = {'\0'};
        inet_ntop(AF_INET, &clientAddress.sin_addr, clientIPAddrReadable, sizeof(clientIPAddrReadable));

        // print details of the client/peer and the data received
        printf("Received packet from %s:%d\n", clientIPAddrReadable, ntohs(clientAddress.sin_port));
        printf("Data is: %s\n", buffer);

        // now reply to the Client
        if (sendto(gate_sock, message, messageLen, 0, (struct sockaddr *)&clientAddress, clientAddressLen) == -1)
        {
            printf("sendto() failed with error code : %d", errno);
            break;
        }
    }

    return 1;
}

int connect_to_host(char *host_ip)
{
    // Create socket
    if ((host_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        printf("Could not create socket : %d", errno);
        return -1;
    }

    // Setup the server address structure.
    // Port and IP should be filled in network byte order
    memset(&HostAddress, 0, sizeof(HostAddress));
    HostAddress.sin_family = AF_INET;
    HostAddress.sin_port = htons(HOST_PORT);
    int rval = inet_pton(AF_INET, (const char *)host_ip, &HostAddress.sin_addr);
    if (rval <= 0)
    {
        printf("inet_pton() failed");
        return -1;
    }
    return 1;
}

int send_to_host()
{
    char bufferReply[80] = {'\0'};
    char message[] = "Good morning\n";
    int messageLen = strlen(message) + 1;
    // send the message
    if (sendto(host_sock, message, messageLen, 0, (struct sockaddr *)&HostAddress, sizeof(HostAddress)) == -1)
    {
        printf("sendto() failed with error code  : %d", errno);
        return -1;
    }

    struct sockaddr_in fromAddress;
    // Change type variable from int to socklen_t: int fromAddressSize = sizeof(fromAddress);
    socklen_t fromAddressSize = sizeof(fromAddress);

    memset((char *)&fromAddress, 0, sizeof(fromAddress));

    // try to receive some data, this is a blocking call
    if (recvfrom(host_sock, bufferReply, sizeof(bufferReply) - 1, 0, (struct sockaddr *)&fromAddress, &fromAddressSize) == -1)
    {
        printf("recvfrom() failed with error code  : %d", errno);
        return -1;
    }
    printf(bufferReply);
    return 1;
}

int main(int count, char *argv[])
{

    connect_to_host(argv[1]);
    send_to_host();
    open_gateway();

    close(host_sock);
    close(gate_sock);

    return 0;
}