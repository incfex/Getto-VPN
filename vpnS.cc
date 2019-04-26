#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <vector>
#include <map>
#include <utility>

#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

#include <shadow.h>
#include <crypt.h>

#include <pthread.h>
#include <netinet/ip.h>
#include <inttypes.h>

#include "shadowAuth.c"

#define BUFF_SIZE 1500
#define MAXINT 65536
#define CA_FILE "./ca.crt"

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

struct sockaddr_in peerAddr;

std::map <uint32_t, SSL*> route_book;
pthread_mutex_t lock;

typedef struct context{
    char* buf;
    int fd;
    SSL* ssl;
} context;

void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

/*
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
*/
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

int updateBook(uint32_t ipad, SSL* ssl){
    printf("Update: The address is: %d\n", ipad);
    pthread_mutex_lock(&lock);
    std::map <uint32_t, SSL*>::iterator it = route_book.begin();
    int found = 0;
    while(it != route_book.end()){
        if(it->first == ipad){
            found = 1;
            it->second = ssl;
        }
    }
    if(!found){
        std::pair <uint32_t, SSL*> record (ipad, ssl);
        route_book.insert(record);
    }
    pthread_mutex_unlock(&lock);
}

int lkupBook(context* c){
    pthread_mutex_lock(&lock);
    uint32_t ipad = ((ip*)c->buf)->ip_dst.s_addr;
    printf("Look Up: The address is: %d\n", ipad);
    std::map <uint32_t, SSL*>::iterator it = route_book.find(ipad);
    if(it == route_book.end()){
        printf("Return Address NOT Found in Route Book!!!\n");
        return -1;
    }
    else {
        c->ssl = it->second;
    }
    return 1;
    pthread_mutex_unlock(&lock);
}

void* readSSL(void* v){
    //And write into TUN
    printf("SSL IN!!!\n");
    context* c = (context*)v;
    int len;
    while(len = SSL_read(c->ssl, c->buf, MAXINT)){
        DumpHex(c->buf, len);
        uint32_t ipad = ((ip*)c->buf)->ip_src.s_addr;
        updateBook(ipad, c->ssl);
        printf("SSL to TUN!!!\n");
        write(c->fd, c->buf, len);
    }
    printf("SSL OUT!!!\n");
}

void* readTUN(void* v){
    //And write into SSL
    printf("TUN IN!!!\n");
    context* c = (context*)v;
    int len;
    while(len = read(c->fd, c->buf, MAXINT)){
        DumpHex(c->buf, len);
        lkupBook(c);
        printf("TUN to SSL!!!\n");
        SSL_write(c->ssl, c->buf, len);
    }
    printf("TUN OUT!!!\n");
}

int main(int argc, char* argv[]) {
    int port = 2552;
    char *ca_file, *cert, *key;
    ca_file = (char*) malloc(100);
    cert = (char*) malloc(100);
    key = (char*) malloc(100);
    memcpy(ca_file, "./ca.crt", 100);
    memcpy(cert, "./cert_server/server.crt", 100);
    memcpy(key, "./cert_server/server-nopa.key", 100);
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

    //create TUN file descriptor
    int tunfd;
    tunfd = createTUNfd();
    char tunbuf[MAXINT];
    bzero(tunbuf, MAXINT);

    pthread_t tunT;
    context tunC;
    tunC.buf = tunbuf; tunC.fd = tunfd; tunC.ssl = ssl;
    pthread_create(&tunT, NULL, readTUN, &tunC);

    //Multi-client
    while(int sock = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len)){
        SSL_set_fd (ssl, sock);
        err = SSL_accept (ssl);
        CHK_SSL(err);
        printf("SSL connection established!\n");
        //Authentication
        if(shadow_server(ssl) <= 0) continue;
        //Start reading
        char sslbuf[MAXINT];
        bzero(sslbuf, MAXINT);
        //pthread START
        pthread_t sslT;
        context sslC;
        sslC.buf = sslbuf; sslC.fd = tunfd; sslC.ssl = ssl;
        pthread_create(&sslT, NULL, readSSL, &sslC);
    }
    
    
    //pthread joining
    //pthread_join(sslT, NULL);
    pthread_join(tunT, NULL);
}