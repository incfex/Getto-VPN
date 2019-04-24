#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#include "creatTUNfd.h"
#include "TUNxSocket.h"

#define PORT_NUMBER 2552
#define BUFF_SIZE 1500

struct sockaddr_in peerAddr;

int main(int argc, char* argv[]) {
    int tunfd, sockfd;

    tunfd = createTunfd();
    sockfd = initTCPServer();

    while(1){
        fd_set readFDSet;

        FD_ZERO(&readFDSet);
        FD_SET(sockfd, &readFDSet);
        FD_SET(tunfd, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
        
        if(FD_ISSET(tunfd, &readFDSet)) TUNtoSock(tunfd, sockfd, BUFF_SIZE);
        if(FD_ISSET(sockfd, &readFDSet)) SocktoTUN(tunfd, sockfd, BUFF_SIZE);
    }
}