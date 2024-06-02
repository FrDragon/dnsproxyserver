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

int main(int argc, char**argv){
    FILE *fp;

    if(!(fp = fopen("settings.conf", "r"))) {
    	printf("Error with settings file opening"); 
    	return -1;
    }
    static char* upstreamServer = NULL;
    size_t upstreamServer_len = 0;
    static char* blackList = NULL;
    size_t blackList_len = 0;
    static char* code = NULL;
    size_t code_len = 0;

    if(fp){
        getline(&upstreamServer, &upstreamServer_len, fp);
        getline(&blackList, &blackList_len, fp);
        getline(&code, &code_len, fp);
        close(fp);
    } else {
        perror("Error with config file");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serv_addr, client_addr, upstream_server_addr;
    char buf[DNS_PACKET_SIZE + 4];
    socklen_t client_len = sizeof(client_addr), upstream_len = sizeof(upstream_server_addr);
    int listenfd = 0;

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
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(PORT);

    upstream_server_addr.sin_family = AF_INET;
    inet_aton(upstreamServer, &upstream_server_addr.sin_addr);
    upstream_server_addr.sin_port = htons(53);


    if(bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0){
        perror("Error with server socket binding");
        exit(EXIT_FAILURE);
    }

    while(1){
        if((data_size = recvfrom(listenfd, buf, sizeof(buf), 0, (struct sockaddr*)&client_addr, &client_len)) < 0){
            perror("Error with data");
            exit(EXIT_FAILURE);
        }

        packet = malloc(sizeof(DNS_PACKET));
        if(dns_request_parser(packet, buf, data_size, blackList)){
            send_code(packet, listenfd, client_addr, client_len, code);
            continue;
        }

        sendto(listenfd, buf, DNS_PACKET_SIZE + 4, 0, (struct sockaddr*)&upstream_server_addr, upstream_len);
        recvfrom(listenfd, buf, sizeof(buf), 0, (struct sockaddr*)&upstream_server_addr, &upstream_len);
        sendto(listenfd, buf, DNS_PACKET_SIZE + 4, 0, (struct sockaddr*)&client_addr, client_len);
        free(packet);
    }

    close(listenfd);
}

void send_code(DNS_PACKET *packet_in, int listenfd, struct sockaddr_in client_addr, socklen_t client_len, char* code){
    char buf[256];
    int buf_len = 0;

    DNS_PACKET *pack = malloc(sizeof(DNS_PACKET));
    pack->header.id = 2048;
    if(!strcmp(code, "not found")){
        pack->header.rcode = 3;
    } else if(!strcmp(code, "refused")){
        pack->header.rcode = 5;
    } else {
        memcpy(buf, &pack->header, 12);
        buf_len = 12;
        memcpy(buf + buf_len, &packet_in->question, sizeof(QUESTION));
        buf_len += sizeof(QUESTION);
        memcpy(buf+buf_len, code, sizeof(16));
        buf_len += 16;
        sendto(listenfd, buf, buf_len, 0, (struct sockaddr*) &client_addr, client_len);
        return;
    }
    memcpy(buf, &pack->header, 12);
    sendto(listenfd, buf, buf_len, 0, (struct sockaddr*) &client_addr, client_len);
    free(pack);
    return;
}

int dns_request_parser(DNS_PACKET* packet, void* data, u_int16_t size, char* blackList){
    int i = 0;

    dns_header_parser(&packet->header, data);
    packet->data = malloc(size - 12);
    memcpy(packet->data, data + 12, size - 12);
    packet->data_size = size - 12;

    char* token;

    do{
        token = strtok(blackList, " ,");
        while(i < packet->header.qdcount){
            if(!strcmp(token, dns_question_parse(packet))){
                return 1;
            };
            i++;
        }
        
    } while((token = strtok(NULL, " ,"))!= NULL);

    free(packet->data);

    return 0;
}


int dns_header_parser(DNS_HEADER* header, void* data){
    memcpy(header, data, 12);

    header->id = ntohs(header->id);
    header->qdcount = ntohs(header->qdcount);
    header->ancount = ntohs(header->ancount);
    header->nscount = ntohs(header->nscount);
    header->arcount = ntohs(header->arcount);

    return 1;
}

char* dns_question_parse(DNS_PACKET* packet){
    u_int16_t i, j, k, length;
    char* question = packet->data;
    static char domain[253];
    i = 0, k = 0;
    length = question[i++];

    do{
        j = 0;

        while(j < length){
            domain[k] = question[i+j];
            j++;
            k++;
        }
        domain[k] = '.';
        k++;    
        i+=length;

        length = question[i++];
    } while(length != 0 && i < packet->data_size);

    return domain;
}