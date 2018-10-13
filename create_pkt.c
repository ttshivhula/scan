#include "scan.h"

void    ip_header(char *source_ip, struct sockaddr_in  dest, char *buff)
{
    struct iphdr *iph;

    iph = (struct iphdr *)buff;
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
	iph->check = csum ((unsigned short *)buff, iph->tot_len >> 1);
}

void    tcp_header(int source_port, char *buff)
{
    struct tcphdr *tcph;
    
    tcph = (struct tcphdr *)(buff + sizeof (struct iphdr));
    tcph->source = htons(source_port);
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
	tcph->check = 0;
	tcph->urg_ptr = 0;
}

void    *create_pkt(char *source_ip, struct sockaddr_in  dest, char *buff, int sport, int port)
{
    void    *ret;
    t_pseudo psh;
    struct tcphdr *tcph;
    
    ip_header(source_ip, dest, buff);
    tcp_header(sport, buff);
    tcph = (struct tcphdr *)(buff + sizeof (struct iphdr));
    ret = (void *)buff;
    tcph->dest = htons (port);
	tcph->check = 0; // if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
	psh.source_address = inet_addr(source_ip);
	psh.dest_address = dest.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons( sizeof(struct tcphdr) );
	memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));
	tcph->check = csum( (unsigned short*)&psh , sizeof(t_pseudo));
    return (buff);
}