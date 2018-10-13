#include "scan.h"

void recv_pkt(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt)
{
	struct	iphdr	*iph;
	struct  tcphdr	*tcph;
	int		size_ip;
	struct sockaddr_in source,dest;

	pkt += 14;
	iph = (struct iphdr *)pkt;
	if(iph->protocol == IPPROTO_TCP)
	{
		size_ip = iph->ihl * 4;
		tcph = (struct tcphdr *)(pkt +size_ip);
		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = iph->saddr;
		memset(&dest, 0, sizeof(dest));
		dest.sin_addr.s_addr = iph->daddr;
		if(tcph->syn == 1 && tcph->ack == 1 /*&& source.sin_addr.s_addr == dest_ip.s_addr */)
		{
			printf("Port %d open \n" , ntohs(tcph->source));
		}
	}
}