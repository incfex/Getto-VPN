#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

#include <createTunfd.h>
#include <TLSClient.h>
#include <TUNxSocket.h>

#define BUFF_SIZE 1500
#define PORT 2552
#define SERVER_IP "127.0.0.1"


struct sockaddr_in peerAddr;

int main (int argc, char * argv[]){
    char* hostname = "feng.kuroa.me"
    int tunfd, sockfd;
    tunfd = createTUNfd();
    sockfd = TLSClient();

    while (1) {
        fd_set readFDSet;

        FD_ZERO(&readFDSet);
        FD_SET(sockfd, &readFDSet);
        FD_SET(tunfd, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

        if (FD_ISSET(tunfd, &readFDSet)) TUNtoSock(tunfd, sockfd);
        if (FD_ISSET(sockfd, &readFDSet)) SocktoTUN(tunfd, sockfd);
    }
}