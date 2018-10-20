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

t_results   *get_port(t_results **res, int port)
{
	t_results *tmp;
	
	tmp = *res;
	while (tmp)
	{
		if (tmp->port == port)
            return (tmp);
        tmp = tmp->next;
	}
    return (NULL);
}

void    no_msg(void *pkt, t_scan *scan)
{
    t_results       *res;
   
    (void)pkt;
    res = get_port(&scan->nmap->results, scan->port);
    if (res)
    {
        if (scan->type == SYN)
            res->syn = 3; //filtered
        if (scan->type == ACK)
            res->ack = 3; //filtered
        if (scan->type == NUL)
            res->ack = 5; //open-filtered
        if (scan->type == FIN)
            res->fin = 5; //open-filtered
        if (scan->type == XMS)
            res->xms = 5; //open-filtered
        if (scan->type == UDP)
            res->udp = 5; //open-filtered
    }
}

void    udp_msg(void *pkt, t_scan *scan)
{
	struct udphdr	*udp;
    t_results       *res;

    udp = (struct udphdr *)pkt;
    res = get_port(&scan->nmap->results, scan->port);
    if (res)
    {
        if (scan->type == UDP)
            res->udp = 1; //open
    }
}

void    icmp_msg(void *pkt, t_scan *scan)
{
	struct icmphdr	*icmp;
    t_results       *res;

    icmp = (struct icmphdr *)pkt;
    res = get_port(&scan->nmap->results, scan->port);
    if (res)
    {
        if (scan->type == UDP && icmp->type == 3 && icmp->code == 3)
            res->udp = 2; //closed
        if (scan->type == UDP && icmp->type == 3 && icmp->code != 3)
            res->udp = 3; //filtered
        if (scan->type == SYN && icmp->type == 3)
            res->syn = 3; //filtered
        if (scan->type == NUL && icmp->type == 3)
            res->nul = 3; //filtered
        if (scan->type == ACK && icmp->type == 3)
            res->ack = 3; //filtered
        if (scan->type == XMS && icmp->type == 3)
            res->xms = 3; //filtered
    }
}

void    tcp_msg(void *pkt, t_scan *scan)
{
    struct tcphdr	*tcp;
    t_results       *res;

    tcp = (struct tcphdr *)pkt;
    res = get_port(&scan->nmap->results, scan->port);
    if (res)
    {
        if (scan->type == SYN)
        {
            if (tcp->ack == 1 && tcp->syn == 1)
            {
                res->syn = 1; //open
                //printf("port %d open\n", scan->port);
            }
            if (tcp->ack == 1 && tcp->rst == 1)
                res->syn = 2; //closed
        }
        if (scan->type == NUL && tcp->rst == 1)
            res->nul = 2; //closed
        if (scan->type == FIN && tcp->rst == 1)
            res->fin = 2; //closed
        if (scan->type == XMS && tcp->rst == 1)
            res->xms = 2; //closed
        if (scan->type == ACK && tcp->rst == 1)
            res->ack = 4; //unfiltered
    }
}

void    recv_pkt(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt)
{
    struct ip       *ip;
    t_scan          *scan;
    static  int num = 1;

    pkt += 14;
    ip = (struct ip *)pkt;
    scan = (t_scan *)args;
    //printf("PKT RECEIVED: %d\n", num++);
    if (ip->ip_p == IPPROTO_UDP)
        udp_msg((unsigned char *)pkt + sizeof(struct ip), scan);
    if (ip->ip_p == IPPROTO_TCP)
        tcp_msg((unsigned char *)pkt + sizeof(struct ip), scan);
    if (ip->ip_p == IPPROTO_ICMP)
        icmp_msg((unsigned char *)pkt + sizeof(struct ip), scan);
}
