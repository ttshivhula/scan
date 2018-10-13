#include "scan.h"

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

unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes > 1)
    {
		sum +=*ptr++;
		nbytes -=2;
	}
	if (nbytes == 1)
    {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum +=oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
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