#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "ca_client" 

SSL* setupTLSClient(const char* hostname);
int setupTCPClient(const char* hostname, int port, const char* ipAddr);
SSL* TLSClient(const char* hostname, int port, const char* ipAddr);