#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

#include <shadow.h>
#include <crypt.h>

#include <pthread.h>

#define BUFF_SIZE 1500
#define MAXINT 65536
#define CA_FILE "./ca.crt"

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

struct sockaddr_in peerAddr;

typedef struct context{
    char* buf;
    int fd;
    SSL* ssl;
} context;

typedef struct userpass{
    char user[32];
    char pass[255];
} userpass;

int shadow_server(SSL* ssl){
    struct spwd *pw;
    char *epasswd;
    userpass up;
    userpass rp;

    int len = SSL_read(ssl, (void*)&up, 287);
    
    printf("Login name: %s\n", up.user);
    printf("Password  : %s\n", up.pass);

    char* user = up.user;
    char* pass = up.pass;

    pw = getspnam(user);
    if (pw == NULL){
        strcpy(rp.user, "0");
        strcpy(rp.pass, "No Such User!!!");
        SSL_write(ssl, (void*)&rp, 287);
        return -1;
    }

    epasswd = crypt(pass, pw->sp_pwdp);
    if(strcmp(epasswd, pw->sp_pwdp)){
        strcpy(rp.user, "0");
        strcpy(rp.pass, "Wrong Password!!!");
        SSL_write(ssl, (void*)&rp, 287);
        return -1;
    }

    strcpy(rp.user, "1");
    strcpy(rp.pass, "Welcome to Getto-VPN!!!");
    SSL_write(ssl, (void*)&rp, 287);
    return 1;
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);

    if (preverify_ok == 1) {
       printf("Verification passed.\n");
    } else {
       int err = X509_STORE_CTX_get_error(x509_ctx);
       printf("Verification failed: %s.\n",
                    X509_verify_cert_error_string(err));
    }
}

int createTUNfd() {
    printf("Now setting up TCP Server!!!\n");
    int tunfd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    tunfd = open("/dev/net/tun", O_RDWR);
    ioctl(tunfd, TUNSETIFF, &ifr);

    return tunfd;
}

int setupTCPServer(int port)
{
    printf("Now setting up TLS Server!!!\n");
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset (&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons (port);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}

void* readSSL(void* v){
    //And write into TUN
    printf("SSL IN!!!\n");
    context* c = (context*)v;
    int len;
    while(len = SSL_read(c->ssl, c->buf, MAXINT)){
        printf("SSL to TUN!!!\n");
        write(c->fd, c->buf, len);
    }
}

void* readTUN(void* v){
    //And write into SSL
    printf("TUN IN!!!\n");
    context* c = (context*)v;
    int len;
    while(len = read(c->fd, c->buf, MAXINT)){
        printf("TUN to SSL!!!\n");
        SSL_write(c->ssl, c->buf, len);
    }
}

int main(int argc, char* argv[]) {
    int port = 2552;
    char* ca_file = "./ca.crt";
    char* cert = "./cert_server/server.crt";
    char* key = "./cert_server/server-nopa.key";
    if(argc >= 2){
        port = atoi(argv[1]);
    }
    if(argc >= 3){
        ca_file = argv[2];
    }
    if(argc >= 4){
        cert = argv[3];
    }
    if(argc >= 5){
        key = argv[4];
    }

    

    //TLS start
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    SSL_METHOD *meth;
    SSL_CTX* ctx;
    SSL *ssl;
    int err;
    // Step 1: SSL context initialization
    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);

    if(SSL_CTX_load_verify_locations(ctx, ca_file, NULL) < 1){
        ERR_print_errors_fp(stderr);
        printf("Error setting the verify locations. \n");
        exit(0);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    
    // Step 2: Set up the server certificate and private key
    if(SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stderr);
        exit(2);
    }
    if(SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stderr);
        exit(2);
    }
    // Step 3: Create a new SSL structure for a connection
    ssl = SSL_new (ctx);

    struct sockaddr_in sa_client;
    size_t client_len;
    int listen_sock = setupTCPServer(port);

    int sock = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);
    close (listen_sock);
    SSL_set_fd (ssl, sock);
    err = SSL_accept (ssl);
    CHK_SSL(err);
    printf ("SSL connection established!\n");

    if(shadow_server(ssl) <= 0) exit(0);

    //create TUN file descriptor
    int tunfd;
    tunfd = createTUNfd();

    char sslbuf[MAXINT];
    char tunbuf[MAXINT];
    bzero(sslbuf, MAXINT);
    bzero(tunbuf, MAXINT);

    //pthread START
    pthread_t sslT;
    pthread_t tunT;

    context sslC;
    sslC.buf = sslbuf; sslC.fd = tunfd; sslC.ssl = ssl;
    context tunC;
    tunC.buf = tunbuf; tunC.fd = tunfd; tunC.ssl = ssl;

    pthread_create(&sslT, NULL, readSSL, &sslC);
    pthread_create(&tunT, NULL, readTUN, &tunC);

    pthread_join(sslT, NULL);
    pthread_join(tunT, NULL);
}