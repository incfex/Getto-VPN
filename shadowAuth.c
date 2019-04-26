// This Program untilized the server side shadow file to authorize the client user through given ssl connection
#include <crypt.h>
#include <shadow.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct userpass{
    char user[32];
    char pass[255];
} userpass;


int shadow_client(SSL* ssl){
    userpass up;
    
    printf("Enter Username: ");
    scanf("%s", up.user);

    printf("Enter Password: ");
    scanf("%s", up.pass);

    SSL_write(ssl, (void*)&up, 287);

    userpass rp;
    
    int len = SSL_read(ssl, (void*)&rp, 287);
    //printf("%s\n", rp.user);
    printf("%s\n", rp.pass);
    fflush(stdout);
    if (rp.user[0] == '1') return 1;
    else return -1;
}

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

