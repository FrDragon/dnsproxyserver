#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

char upstreamServer[16];
char blackList[256];
char code[16];

typedef struct {
    unsigned short id;
    unsigned char rd :1;
    unsigned char tc : 1;
    unsigned char aa :1;
    unsigned char opcode :4;
    unsigned char qr :1;

    unsigned char rcode :4;
    unsigned char cd :1;
    unsigned char ad :1;
    unsigned char z :1;
    unsigned char ra :1;

    unsigned short q_count;
    unsigned short ans_count;
    unsigned short auth_count;
    unsigned short add_count;
} DNS_HEADER;

typedef struct {
    unsigned short qtype;
    unsigned short qclass;
} QUESTION;


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

    struct sockaddr_in addr;
    char sendBuff[1025];
    int listenfd = 0, conn = 0;

    if((listenfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        perror("Error with server socket creation");
        exit(EXIT_FAILURE);
    }
    memset(&addr, '0', sizeof(addr));
    memset(sendBuff, '0', sizeof(sendBuff));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(53);

    if(bind(listenfd, (struct sockaddr*)&addr, sizeof(serv)) < 0){
        perror("Error with server socket binding");
        exit(EXIT_FAILURE);
    }

    if(listen(listenfd, 10) < 0){
        perror("Error with listening");
        exit(EXIT_FAILURE);
    }

    while(1){
        if((conn = accept(listenfd, (struct sockaddr*)&addr, sizeof(addr))) < 0){
            perror("Error with client connection");
            exit(EXIT_FAILURE);
        }


    }

    printf("%s%s%s", upstreamServer, blackList, code);
}


/*
    TODO: 
    Реализовать структуры заголовков DNS пакета
    Реализовать извлечение информации из получаемых сервером транзитных пакетов
    Реализовать фильтрацию по черному списку и возврат кода
*/