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

void send_code(DNS_PACKET *packet_in, int listenfd, struct sockaddr_in client_addr, socklen_t client_len){
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
    return;
}

char** dns_request_parser(DNS_PACKET* packet, void* data, u_int16_t size){
    int i = 0;
    static char domains[65536][253];

    dns_header_parser(&packet->header, data);
    packet->data = malloc(size - 12);
    memcpy(packet->data, data + 12, size - 12);
    packet->data_size = size - 12;

    while(i < packet->header.qdcount){
        strcpy(domains[i], dns_question_parse(packet));
        i++;
    }

    return domains;
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