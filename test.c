#include<stdio.h> //printf
#include<string.h> //memset
#include<stdlib.h> //for exit(0);
#include<sys/socket.h>
#include<errno.h> //For errno - the error number
#include<pthread.h>
#include<netdb.h> //hostend
#include<arpa/inet.h>
#include<unistd.h>
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include <pcap/pcap.h>
#include <sys/types.h>
#include <ifaddrs.h>
 
int start_sniffer();
void * receive_ack( void *ptr );
void process_packet(unsigned char* , int);
unsigned short csum(unsigned short * , int );
char *dns_lookup(char *addr_host, struct sockaddr_in	*addr_con);

int	get_local(char *ip, char *device)
{
	char				        *dev;
	char			 	        errbuf[PCAP_ERRBUF_SIZE];
	struct ifaddrs	    *ifap;
	struct ifaddrs		  *p;
	struct sockaddr_in	*sa;

	if ((dev = pcap_lookupdev(errbuf)) == NULL)
		return (0);
	strcpy((char *)device, dev);
	if (getifaddrs(&ifap) == -1)
		return (0);
	p = ifap;
	while (p)
	{
		if (p->ifa_addr->sa_family == AF_INET && strcmp(p->ifa_name, dev) == 0)
		{
			sa = (struct sockaddr_in *)p->ifa_addr;
			strcpy((char *)ip, inet_ntoa(sa->sin_addr));
			return (1);
		}
		p = p->ifa_next;
	}
	freeifaddrs(ifap);
	return (0);
}
 
struct pseudo_header    //needed for checksum calculation
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
     
    struct tcphdr tcp;
};

struct	in_addr dest_ip;
 
int main(int argc, char *argv[])
{
    //Create a raw socket
    int s = socket (AF_INET, SOCK_RAW , IPPROTO_TCP);
    if(s < 0)
    {
        printf ("Error creating socket. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }
    //Datagram to represent the packet
    char datagram[4096];    
     
    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;
     
    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
     
    struct sockaddr_in  dest;
    struct pseudo_header psh;
     
    char *target = argv[1];
     
    if(argc < 2)
    {
        printf("Please specify a hostname \n");
        exit(1);
    }
    char dev[20];
	char *ip = dns_lookup(target, &dest);
     
    int source_port = 43591;
    char source_ip[20];
    get_local(source_ip, dev);
    dest_ip.s_addr = inet_addr(ip); 
    printf("%s (%s) scanning open ports on %s \n" , source_ip, dev, ip);
     
    memset(datagram, 0, 4096); /* zero out the buffer */
     
    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    iph->id = htons (54321); //Id of this packet
    iph->frag_off = htons(16384);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;      //Set to 0 before calculating checksum
    iph->saddr = inet_addr(source_ip);    //Spoof the source ip address
    iph->daddr = dest.sin_addr.s_addr;//dest_ip.s_addr;
	//dest_ip = dest.sin_addr;
     
    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
     
    //TCP Header
    tcph->source = htons(source_port);
   // tcph->dest = htons(42);
    tcph->seq = htonl(1105024978);
    tcph->ack_seq = 0;
    tcph->doff = sizeof(struct tcphdr) / 4;      //Size of tcp header
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons (14600);  // maximum allowed window size
    tcph->check = 0; //if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
    tcph->urg_ptr = 0;
     
    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
     
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }
    char *message1 = "Thread 1";
    int  iret1;
    pthread_t sniffer_thread;
 
    if( pthread_create( &sniffer_thread , NULL ,  receive_ack , (void*) message1) < 0)
    {
        printf ("Could not create sniffer thread. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }
 
    //printf("Starting to send syn packets\n");
     
    int port;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = dest_ip.s_addr;
    for(port = 1 ; port < 1024 ; port++)
    {
        tcph->dest = htons (port);
        tcph->check = 0; // if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
         
      	psh.source_address = inet_addr(source_ip);
        psh.dest_address = dest.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons( sizeof(struct tcphdr) );
         
        memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));
         
        tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));
         
        //Send the packet
        if ( sendto (s, datagram , sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &dest, sizeof (dest)) < 0)
        {
            printf ("Error sending syn packet. Error number : %d . Error message : %s \n" , errno , strerror(errno));
            exit(0);
        }
    }
     
    pthread_join( sniffer_thread , NULL);
    printf("%d" , iret1);
     
    return 0;
}
 
/*
    Method to sniff incoming packets and look for Ack replies
*/
void * receive_ack( void *ptr )
{
    //Start the sniffer thing
    start_sniffer();
}
 
int start_sniffer()
{
    int sock_raw;
     
    int saddr_size , data_size;
    struct sockaddr saddr;
     
    unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
     
    //printf("Sniffer initialising...\n");
     
    //Create a raw socket that shall sniff
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
     
    if(sock_raw < 0)
    {
        printf("Socket Error\n");
        return 1;
    }
     
    saddr_size = sizeof saddr;
     
    while(1)
    {
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
         
        if(data_size <= 0)
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
         
        //Now process the packet
        process_packet(buffer , data_size);
    }
     
    close(sock_raw);
    printf("Sniffer finished.");
    return 0;
}
 
void process_packet(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr*)buffer;
    struct sockaddr_in source,dest;
    unsigned short iphdrlen;
     
    if(iph->protocol == 6)
    {
        struct iphdr *iph = (struct iphdr *)buffer;
        iphdrlen = iph->ihl*4;
     
        struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
             
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr;
     
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = iph->daddr;
         
        if(tcph->syn == 1 && tcph->ack == 1 && source.sin_addr.s_addr == dest_ip.s_addr )
        {
            printf("Port %d open \n" , ntohs(tcph->source));
        }
    }
}
 
/*
 Checksums - IP and TCP
 */
unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}
 
void			exit_err(char *s)
{
	printf("%s", s);
	exit(1);
}

char			*dns_lookup(char *addr_host, struct sockaddr_in	*addr_con)
{
	struct addrinfo		hints;
	struct addrinfo		*res;
	struct sockaddr_in	*sa_in;
	char				*ip;

	memset(&(hints), 0, sizeof(hints));
	hints.ai_family = AF_INET;
	ip = malloc(INET_ADDRSTRLEN);
	if (getaddrinfo(addr_host, NULL, &hints, &(res)) < 0)
		exit_err("ft_traceroute: unknown host\n");
	sa_in = (struct sockaddr_in *)res->ai_addr;
	inet_ntop(res->ai_family, &(sa_in->sin_addr), ip, INET_ADDRSTRLEN);
	(*addr_con) = *sa_in;
	(*addr_con).sin_port = htons(1);
	return (ip);
}