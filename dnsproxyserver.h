#include <sys/types.h>

#define PORT 8053

#define DNS_PACKET_SIZE 512

#define QR_QUERY 0
#define QR_RESPONSE 1

#define OPCODE_QUERY 0
#define OPCODE_IQUERY 1
#define OPCODE_STATUS 2

#define AA_NONAUTHORITY 0
#define AA_AUTHORITY 1

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
    u_int16_t rclass;
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

char** dns_request_parser(DNS_PACKET* packet, void* data, u_int16_t size);
int dns_header_parser(DNS_HEADER* header, void* data);
char* dns_question_parse(DNS_PACKET* packet);
void send_code(DNS_PACKET *packet_in, int listenfd, struct sockaddr_in client_addr, socklen_t client_len, char* code);
