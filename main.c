#include "scan.h"

void	send_packet(t_nmap *);

/*
** basic thread handling
*/

int	value42 = 42;

void	*thread_function(void *arguments)
{
	t_nmap	*nmap;

	nmap = arguments;
	for (nmap->port = 1 ; nmap->port < 1000 ; nmap->port++)
        {
                char    errbuf[PCAP_ERRBUF_SIZE];
                pcap_t  *handle;
                handle = pcap_open_live(nmap->dev, PKT_LEN, 0, 10, errbuf);
                send_packet(nmap);
                int num = pcap_dispatch(handle, -1, recv_pkt, NULL);
          //     printf("num: %d %d\n", num, nmap->port);
                pcap_close(handle);
        }
	if (value42 == 1)
		printf("haha\n");
	else
		value42--;
}


void	threader(t_nmap *args) /*argument for --speedrun number */
{
	pthread_t	*thread_id;
	int		i;

	thread_id = (pthread_t *)malloc(sizeof(pthread_t) * 42);
	/* 42 is just a test number */
	i = 0;
	while (i < 42)
	{
		pthread_create(&thread_id[i], NULL, thread_function,
		(void*)args);
		i++;
	}
	while (i < 42)
	{
		pthread_join(thread_id[i], NULL);
		i++;
	}
	pthread_exit(NULL);
}


void	send_packet(t_nmap *nmap)
{
	int	len;
	char	datagram[4096];

	len = (nmap->type != UDP) ? sizeof(struct tcphdr) : sizeof(struct udphdr);
	memset(datagram, 0, 4096);
	create_pkt(nmap, datagram);
	sendto(nmap->sock_fd, datagram , sizeof(struct iphdr) + len, 0,
		(struct sockaddr *)&nmap->dest, sizeof(nmap->dest));
}

int main(int c, char **v)
{
	t_nmap	nmap;
	int one = 1;
	const int *val = &one;
	
	nmap.sock_fd = socket (AF_INET, SOCK_RAW , IPPROTO_RAW);
	nmap.d_ip = dns_lookup(v[1], &nmap.dest);
	nmap.source_port = 43591;
	get_local(nmap.source_ip, nmap.dev);
	nmap.dest_ip.s_addr = inet_addr(nmap.d_ip); 
	printf("%s (%s) scanning open ports on %s \n" , nmap.source_ip, nmap.dev, nmap.d_ip);
	setsockopt(nmap.sock_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));
	nmap.dest.sin_family = AF_INET;
	nmap.dest.sin_addr.s_addr = nmap.dest_ip.s_addr;
	nmap.type = SYN;
	threader(&nmap);
/*	for (nmap.port = 1 ; nmap.port < 1000 ; nmap.port++)
	{
		char	errbuf[PCAP_ERRBUF_SIZE];
		pcap_t	*handle;
		handle = pcap_open_live(nmap.dev, PKT_LEN, 0, 10, errbuf);
		send_packet(&nmap);
		int num = pcap_dispatch(handle, -1, recv_pkt, NULL);
		//printf("num: %d %d\n", num, port);
		pcap_close(handle);
	} */
	printf("EXITTING...\n");
	return 0;
}
