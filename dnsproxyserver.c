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

    char banned_domains[256];
    char* token = strtok(blackList, ' ,');

    for(int t = 0; t < 256; t++){
        if(*token == NULL){
            break;
        }
        banned_domains[t] = *token;
        token = strtok(NULL, ' ,');
    }

    struct sockaddr_in serv_addr, client_addr, upstream_server_addr;
    char buf[DNS_PACKET_SIZE+4];
    socklen_t client_len = sizeof(client_addr), upstream_len = sizeof(upstream_server_addr);
    int listenfd = 0, conn = 0;

    int data_size;

    DNS_PACKET* packet;

    if((listenfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        perror("Error with server socket creation");
        exit(EXIT_FAILURE);
    }
    memset(&serv_addr, '0', sizeof(serv_addr));
    memset(&client_addr, '0', sizeof(client_addr));
    memset(&upstream_server_addr, '0', sizeof(upstream_server_addr));
    memset(buf, '0', sizeof(buf));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(PORT);

    upstream_server_addr.sin_family = AF_INET;
    inet_aton(upstreamServer, &upstream_server_addr.sin_addr);
    upstream_server_addr.sin_port = htons(PORT);


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
        token = strtok(blackList, ' ,');
        for(int t = 0; t < 65536; t++){
            for(int i = 0; i < 256; i++){
                if(!strcmp(domains[t], banned_domains[i])){
                    send_code(packet, listenfd, client_addr, client_len);
                    exit(1);
                }
            }
        }

        sendto(listenfd, buf, DNS_PACKET_SIZE + 4, 0, (struct sockaddr*)&upstream_server_addr, &upstream_len);
        recvfrom(listenfd, buf, DNS_PACKET_SIZE + 4, 0, (struct sockaddr*)&upstream_server_addr, &upstream_len);
        sendto(listenfd, buf, DNS_PACKET_SIZE + 4, 0, (struct sockaddr*)&client_addr, &client_len);
    }

    close(listenfd);
}
