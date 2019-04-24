int setupTCPServer(){
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset(&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port = htons(4433);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}

int TLSServer(){
    SSL_METHOD *meth;
    SSL_CTX* ctx;
    SSL *ssl;
    int err;

    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);
    SSL_CTX_use_certificate_file(ctx, "./cert_server/server-cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/server-key.pem", SSL_FILETYPE_PEM);

    ssl = SSL_NEW(ctx);

    struct sockaddr_in sa_client;
    size_t client_len;
    int listen_sock = setupTCPServer();

    
    int sock = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);
    close(listen_sock);

    SSL_set_fd(ssl, sock);
    int err = SSL_accept(ssl);
    CHK_SSL(err);
    printf("SSL connection establishedd!/n");
    
    return ssl;
}