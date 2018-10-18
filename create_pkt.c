#include "scan.h"

void    ip_header(t_nmap *p, char *buff)
{
	struct iphdr *iph;
	int len;

	iph = (struct iphdr *)buff;
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	len = (p->type != UDP) ? sizeof(struct tcphdr) : sizeof(struct udphdr);
	iph->tot_len = sizeof(struct iphdr) + len;
	iph->id = getpid();//htons (54321); //Id of this packet
	iph->frag_off = 0;//htons(16384);
	iph->ttl = 64;
	iph->protocol = (p->type != UDP) ? IPPROTO_TCP : IPPROTO_UDP;
	iph->check = 0;      //Set to 0 before calculating checksum
	iph->saddr = inet_addr(p->source_ip);    //Spoof the source ip address
	iph->daddr = p->dest.sin_addr.s_addr;//dest_ip.s_addr;
	iph->check = csum((unsigned short *)buff, iph->tot_len >> 1);
}

void    tcp_header(t_nmap *p, char *buff)
{
	struct tcphdr *tcph;

	tcph = (struct tcphdr *)(buff + sizeof (struct iphdr));
	tcph->source = htons(p->source_port);
	tcph->seq = htonl(1105024978);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr) / 4;      //Size of tcp header
	tcph->fin = (p->type == FIN) ? 1 : 0;
	tcph->syn = (p->type == SYN) ? 1 : 0;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = (p->type == ACK) ? 1 : 0;
	tcph->urg = 0;
	tcph->window = htons (14600);  // maximum allowed window size
	tcph->check = 0;
	tcph->urg_ptr = 0;
}

void	tcp_calc(t_nmap *p, char *buff)
{
	t_pseudo psh;
	struct tcphdr *tcph;
	
	if (p->type != UDP)
	{
		tcph = (struct tcphdr *)(buff + sizeof (struct iphdr));
		tcph->dest = htons (p->port);
		tcph->check = 0;
		psh.source_address = inet_addr(p->source_ip);
		psh.dest_address = p->dest.sin_addr.s_addr;
		psh.placeholder = 0;
		psh.protocol = IPPROTO_TCP;
		psh.tcp_length = htons( sizeof(struct tcphdr) );
		memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));
		tcph->check = csum( (unsigned short*)&psh , sizeof(t_pseudo));
	}
}

void	udp_packet(t_nmap *p, char *buff)
{
	struct iphdr	*iph;
	struct udphdr	*udph;

	iph = (struct iphdr *)(buff);
	udph = (struct udphdr *)(buff + (iph->ihl * 4));
	udph->source = htons((unsigned short)p->source_port);
	udph->dest = htons(p->port);
	udph->len = htons(sizeof(struct udphdr));
	udph->check = 0;
	udph->check = csum((unsigned short *)&udph, iph->ihl * 4);
}

void    create_pkt(t_nmap *p, char *buff)
{
	ip_header(p, buff);
	(p->type != UDP) ? tcp_header(p, buff) : 0;
	tcp_calc(p, buff);
	(p->type == UDP) ? udp_packet(p, buff) : 0;
}
