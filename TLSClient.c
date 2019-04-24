SSL* setupTLSClient(const char* hostname){
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    SSL_METHOD* meth;
    SSL_CTX* ctx;
    SSL* ssl;

    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if(SSL_CTX_load_verify_location(ctx, NULL, CA_DIR) < 1){
        printf("Error setting the verify locations. \n");
        exit(0);
    }
    ssl = SSL_new(ctx);
    
    X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

    return ssl;
}

int setupTCPClient(const char* hostname, int port, const char* ipAddr){
    struct sockaddr_in server_addr;

    int sockfd = socket(AF_INET, SOCK_StREAM, IPPROTO_TCP);

    memset(&server_addr, '\0', sizeof(server_addr));

    server_addr.sin_addr.s_addr = inet_addr(ipAddr);
    server_addr.sin_port = htons(port);
    server_addr.sin_family = AF_INET;

    connect(sockfd, (struct sockaddr*) &server_addr, sizeof(server_addr));

    return sockfd;
}

int TLSClient(const char* hostname, int port, const char* ipAddr){
    SSL *ssl = setTLSClient(hostname);
    int sockfd = setupTCPClient(hostname, port, ipAddr);

    SSL_set_fd(ssl, sockfd);
    int err = SSL_connect(ssl);
    CHK_SSL(err);
    printf("SSL connection is successful\n");
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    return ssl;
}