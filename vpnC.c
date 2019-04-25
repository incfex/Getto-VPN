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

#include <pthread.h>
#include <unistd.h>

#define MAXINT 65535
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }

struct sockaddr_in peerAddr;

typedef struct context{
    char* buf;
    int fd;
    SSL* ssl;
} context;

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
    printf("Now Creating TUN fd!!!\n");
    int tunfd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    tunfd = open("/dev/net/tun", O_RDWR);
    ioctl(tunfd, TUNSETIFF, &ifr);

    return tunfd;
}

int setupTCPClient(int port, const char* ipAddr){
    printf("Now setting up TCP Client!!!\n");
    struct sockaddr_in server_addr;

    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    memset(&server_addr, '\0', sizeof(server_addr));

    server_addr.sin_addr.s_addr = inet_addr(ipAddr);
    server_addr.sin_port = htons(port);
    server_addr.sin_family = AF_INET;

    connect(sockfd, (struct sockaddr*) &server_addr, sizeof(server_addr));

    return sockfd;
}



SSL* setupTLSClient(const char* hostname, const char* ca_file, const char* cert, const char* key){
    printf("Now setting up TLS Client!!!\n");
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    SSL_METHOD* meth;
    SSL_CTX* ctx;
    SSL* ssl;

    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);

    // Step 1: SSL context initialization
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
    ssl = SSL_new(ctx);
    
    X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

    return ssl;
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

int main (int argc, char * argv[]){
    int port = 2552;
    char* server_ip = "127.0.0.1";
    char* hostname = "seedpkilab2018.com";
    char* ca_file = "./ca.crt";
    char* cert = "./cert_server/server-cert.pem";
    char* key = "./cert_server/server-key-nopa.pem";
    if(argc >= 2){
        port = atoi(argv[1]);
    }
    if(argc >= 3){
        server_ip = argv[2];
    }
    if(argc >= 4){
        hostname = argv[3];
    }
    if(argc >= 5){
        ca_file = argv[4];
    }
    if(argc >= 6){
        cert = argv[5];
    }
    if(argc >= 7){
        key = argv[6];
    }
    

    //create socks for TLS connection
    int sockfd = setupTCPClient(port, server_ip);
    SSL *ssl = setupTLSClient(hostname, ca_file, cert, key);

    if (sockfd < 0) {
        printf("sockfd < 0");
    }
    else {printf("you are fine :)\n");}

    SSL_set_fd(ssl, sockfd);
    int err = SSL_connect(ssl);
    printf("err: %d\n", err);
    CHK_SSL(err);
    printf("SSL connection is successful\n");
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    //create TUN device and get its file discriptor
    int tunfd;
    tunfd = createTUNfd();
    //create buffer for data
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