#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "dnsproxyserver.h"

char upstreamServer[16];
char blackList[256];
char code[16];

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

    DNS_PACKET* packet;

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

        packet = malloc(sizeof(DNS_PACKET));
        char** domains = dns_request_parser(packet, buf, data_size);

    }

    printf("%s%s%s", upstreamServer, blackList, code);
    close(listenfd);
}


/*
    TODO: 
    Реализовать фильтрацию по черному списку и возврат кода
*/