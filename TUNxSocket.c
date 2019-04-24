#include "TUNxSocket.h"


void TUNtoSock (int tunfd, SSL* ssl, int bufsize){
    int len;
    char buff[bufsize];

    printf("Got a packet from TUN\n");

    bzero(buff, bufsize);
    len = read(tunfd, buff, bufsize-1);
    SSL_write(ssl, send, len);
}

void SocktoTUN (int tunfd, SSL* ssl, int bufsize){
    int len;
    char buff[bufsize];

    printf("Got a packet from the tunnel\n");

    bzero(buff, bufsize);

    len = SSL_read(ssl, buff, bufsize-1);
    write(tunfd, buff, len);
}