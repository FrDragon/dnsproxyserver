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

char** dns_request_parser(DNS_PACKET* packet, void* data, u_int16_t size){
    int i = 0;
    char domains[65536][253];

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