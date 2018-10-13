#ifndef SCAN_H
# define SCAN_H

# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <sys/socket.h>
# include <errno.h>
# include <pthread.h>
# include <netdb.h>
# include <arpa/inet.h>
# include <unistd.h>
# include <netinet/tcp.h>
# include <netinet/ip.h>
# include <sys/types.h>
# include <ifaddrs.h>
# include <pcap/pcap.h>

# define PKT_LEN 65536


//used for checksum calculation of tcp
typedef struct	s_pseudo
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcp;
}		t_pseudo;

int				get_local(char *ip, char *device);
void			exit_err(char *s);
char			*dns_lookup(char *addr_host, struct sockaddr_in	*addr_con);
unsigned short	csum(unsigned short *ptr,int nbytes);
void 			recv_pkt(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt);
void    *create_pkt(char *source_ip, struct sockaddr_in  dest, char *buff, int sport, int port);
void * receive_ack( void *ptr);

#endif
