//peerAddr is defined globally

void TUNtoSock (int tunfd, int sockfd){
    int len;
    char buff[BUFF_SIZE];

    printf("Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr, sizeof(peerAddr));
}

void SocktoTUN (int tunfd, int sockfd){

}