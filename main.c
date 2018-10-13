#include "scan.h"

char	*dstip;
char	*srcip;
struct	in_addr dest_ip;

int main(int c, char **v)
{

	int s = socket (AF_INET, SOCK_RAW , IPPROTO_TCP);
	char datagram[4096];
	struct sockaddr_in  dest;
	
	char dev[20];
	char *ip = dns_lookup(v[1], &dest);
	srcip = ip;
	int source_port = 43591;
	char source_ip[20];
	get_local(source_ip, dev);
	dstip = source_ip;
	dest_ip.s_addr = inet_addr(ip); 
	printf("%s (%s) scanning open ports on %s \n" , source_ip, dev, ip);
	memset(datagram, 0, 4096);
	int one = 1;
	const int *val = &one;
	setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));
	pthread_t sniffer_thread;
	pthread_create(&sniffer_thread , NULL, receive_ack, NULL);
	int port;
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = dest_ip.s_addr;
	for(port = 1 ; port < 1000 ; port++)
	{
		memset(datagram, 0, 4096);
		create_pkt(source_ip, dest, datagram, source_port, port);
		sendto(s, datagram , sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &dest, sizeof (dest));
	}
	pthread_join( sniffer_thread , NULL);
	return 0;
}

void * receive_ack( void *ptr)
{
	char *dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	char filter_exp[100];
	struct bpf_program fp;
	
	sprintf(filter_exp, "src host %s and dst host %s", srcip, dstip);
	bpf_u_int32 mask;
	bpf_u_int32 net;
	int num_packets = 60000;
	dev = pcap_lookupdev(errbuf);
	pcap_lookupnet(dev, &net, &mask, errbuf);
	handle = pcap_open_live(dev, PKT_LEN, 0, 1000, errbuf);
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);
	pcap_loop(handle, num_packets, recv_pkt, NULL);
	pcap_freecode(&fp);
	pcap_close(handle);
}