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
# include <netinet/udp.h>
# include <netinet/ip.h>
# include <sys/types.h>
# include <ifaddrs.h>
# include <pcap/pcap.h>
# include <netdb.h>

# define PKT_LEN 65536
# define NUL 0x0
# define SYN 0x1
# define ACK 0x2
# define FIN 0x3
# define UDP 0x4
# define XMS 0x5
# define ALL 0x6

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

typedef	struct			s_nmap
{
	int			type;
	int			port;
	char			source_ip[20];
	char			*d_ip;
	struct sockaddr_in	dest;
	struct	in_addr		dest_ip;
	int			source_port;
	int			sock_fd;
	char			dev[20]; //device used for monitoring //pcap craps
}				t_nmap;

char	*dstip;
char	*srcip;

int				get_local(char *ip, char *device);
void			exit_err(char *s);
char			*dns_lookup(char *addr_host, struct sockaddr_in	*addr_con);
unsigned short	csum(unsigned short *ptr,int nbytes);
void 			recv_pkt(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt);
void    create_pkt(char *source_ip, struct sockaddr_in  dest, char *buff, int sport, int port, int type);
void * receive_ack( void *ptr);

#endif
