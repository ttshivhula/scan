#include "scan.h"

/* Initializes all the ports needed to be scanned and set all values such that we
make an assumption that the port is not open...
*/

void		add_ports(t_results **res, int port)
{
	t_results *tmp;

	if (*res == NULL)
	{
		(*res) = (t_results *)malloc(sizeof(t_results));
		bzero((*res), sizeof(t_results));
		(*res)->port = port;
		(*res)->next = NULL;
		strcpy((*res)->res, "Closed"); 
		strcpy((*res)->s_name, "Unsigned");
		return ;
	}
	tmp = (t_results *)malloc(sizeof(t_results));
	bzero(tmp, sizeof(t_results));
	tmp->next = *res;
	tmp->port = port;
	strcpy(tmp->res, "Closed"); 
	strcpy(tmp->s_name, "Unsigned");
	*res = tmp;
}

/* Open  port by checking if a bitwise operator of a type of scan is set...
*/

void		open_port(t_results **res, int port, int type, int set)
{
	t_results *tmp;
	
	tmp = *res;
	while (tmp)
	{
		if (tmp->port == port)
		{
			if (type == SYN)
				tmp->syn = set;
			if (type == ACK)
				tmp->ack = set;
			if (type == NUL)
				tmp->nul = set;
			if (type == FIN)
				tmp->fin = set;
			if (type == XMS)
				tmp->xms = set;
			if (type == UDP)
				tmp->udp = set;
			return ;
		}
		tmp = tmp->next;
	}
}

void recv_pkt(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt)
{
	struct	iphdr	*iph;
	struct  tcphdr	*tcph;
	int		size_ip;
	struct sockaddr_in source,dest;
	struct servent *serv;
	t_nmap		*nmap;

	nmap = (t_nmap *)args;
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
		if(tcph->syn == 1 && tcph->ack == 1)
		{
			//serv = getservbyport(80, "TCP");
			//printf("Port %d open \n" , ntohs(tcph->source));
			open_port(&nmap->results, ntohs(tcph->source), SYN, 1);
		}
	}
}
