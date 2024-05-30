#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#define PORT 8053

#define DNS_PACKET_SIZE 512

#define QR_QUERY 0
#define QR_RESPONSE 1

#define OPCODE_QUERY 0
#define OPCODE_IQUERY 1
#define OPCODE_STATUS 2

#define AA_NONAUTHORITY 0
#define AA_AUTHORITY 1

char upstreamServer[16];
char blackList[256];
char code[16];

typedef struct {
    u_int16_t id;

    u_int16_t qr :1;
    u_int16_t opcode :4;
    u_int16_t aa :1;
    u_int16_t tc :1;
    u_int16_t rd :1;
    u_int16_t ra :1;
    u_int16_t z :3;
    u_int16_t rcode :4;

    u_int16_t qdcount;
    u_int16_t ancount;
    u_int16_t nscount;
    u_int16_t arcount;
} DNS_HEADER;

typedef struct {
    char* qname;
    unsigned short qtype;
    unsigned short qclass;
} QUESTION;

typedef struct {
    char* name;
    u_int16_t type;
    u_int16_t class;
    u_int32_t ttl;
    u_int16_t rdlength;
    char* rdata;
} RESPONSE;

typedef struct{
    DNS_HEADER header;
    QUESTION question;
    char* data;
    u_int16_t data_size;
} DNS_PACKET;


int main(void){
    
    FILE *fp = fopen("settings.conf", "r");

    if(fp){
        fgets(upstreamServer, 16, fp);
        fgets(blackList, 256, fp);
        fgets(code, 16, fp);
        fclose(fp);
    } else {
        perror("Error with config file");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serv_addr, client_addr;
    char buf[DNS_PACKET_SIZE+4];
    socklen_t client_len;
    int listenfd = 0, conn = 0;

    int data_size;

    if((listenfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        perror("Error with server socket creation");
        exit(EXIT_FAILURE);
    }
    memset(&serv_addr, '0', sizeof(serv_addr));
    memset(buf, '0', sizeof(buf));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(PORT);

    if(bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0){
        perror("Error with server socket binding");
        exit(EXIT_FAILURE);
    }

    while(1){
        if((data_size = recvfrom(listenfd, buf, DNS_PACKET_SIZE + 4, 0, (struct sockaddr*)&client_addr, &client_len))< 0){
            perror("Error with data");
            exit(EXIT_FAILURE);
        }

        write(1, buf, DNS_PACKET_SIZE+4);

    }

    printf("%s%s%s", upstreamServer, blackList, code);
    close(listenfd);
}


/*
    TODO: 
    Реализовать извлечение информации из получаемых сервером транзитных пакетов
    Реализовать фильтрацию по черному списку и возврат кода
*/