/*
 * 实现基于dpdk的tcp和udp简单收发包，没有实现包重组，流量控制和拥塞控制等
 */

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_timer.h>
#include <rte_kni.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_ethdev.h>

#define NUM_MBUFS (4096-1) // 内存池中 mbuf 的数量
#define BURST_SIZE 32
#define RING_SIZE 1024 //The size of the ring
#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
#define TIMER_RESOLUTION_CYCLES 20000000000ULL //10ms * 1000
#define DEFAULT_FD_NUM 3
#define MAX_FD_COUNT 1024
#define UDP_APP_RECV_BUFF_SIZE 128
#define MAX_PACKET_SIZE 4096

#define TCP_PROTO 0
#define UDP_PRORO 1

static unsigned char fd_table[MAX_FD_COUNT/8+1] = {0};

struct localhost *lhost = NULL;

static uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 1, 4);//当前ip，网络字节序

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];

struct rte_kni *global_kni = NULL;

int gDpdkPortId = 0;

struct localhost {
	int fd;

	uint32_t localip;	//网络字节序
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint16_t localport;	//网络字节序
	uint8_t protocol;

	struct rte_ring *sndbuffer;
	struct rte_ring *rcvbuffer;

	struct localhost *prev;
	struct localhost *next;

	pthread_cond_t cond;
	pthread_mutex_t mutex;
};

struct tcp_conn_key {
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
	char proto;
};

struct ng_listen_table {
	int count;
	struct ng_tcp_stream *tcp_set;
};

struct inout_ring {
	struct rte_ring *in;
	struct rte_ring *out;
};

struct offload {
	uint32_t sip;
	uint32_t dip;
	
	uint16_t sport;
	uint16_t dport;
	
	int protocol;

	unsigned char *data;
	uint16_t length;
};

struct ng_tcp_table {
	int count;
	struct ng_tcp_stream *tcp_set;
};

#define TCP_OPTION_LEN 10
#define TCP_MAX_SEQ (((long long)1<<32)-1)
#define TCP_INITIAL_WINDOW 14600

#define ARY_ENTRY_STATUS_DYNAMIC 0
#define ARY_ENTRY_STATUS_STATIC 1

//链表头插法
#define LL_ADD(item, list) do {		\
	item->prev = NULL;				\
	item->next = list;				\
	if (list != NULL) list->prev = item; \
	list = item;					\
}while(0)

//链表删除节点
#define LL_REMOVE(item, list) do { \
	if (item->prev != NULL) item->prev->next = item->next;	\
	if (item->next != NULL) item->next->prev = item->prev;	\
	if (list == item) list = item->next;	\
	item->prev = item->next = NULL;			\
}while(0)


struct arp_entry {
	uint32_t ip;	//网络字节序
	uint8_t hwadder[RTE_ETHER_ADDR_LEN];
	uint8_t type;

	struct arp_entry *next;
	struct arp_entry *prev;
};

struct arp_table {
	struct arp_entry *entries;
	int count;
};

static struct arp_table *arpt = NULL;
//该函数参数中不加void，会告警 function declaration isn’t a prototype(该函数声明不是原型)
static struct arp_table *arp_table_instance(void) {
	if (arpt == NULL) {
		arpt = rte_malloc("arp_table", sizeof(struct arp_table), 0);
		if (arpt == NULL) {
			rte_exit(EXIT_FAILURE, "rte_malloc arp table failed");
		}
		memset(arpt, 0, sizeof(struct arp_table));
	}

	return arpt;
}

// 根据ip查找mac
static uint8_t* ng_get_dst_macaddr(uint32_t dip) {
	struct arp_entry *iter = NULL;
	struct arp_table *table = arp_table_instance();

	for (iter = table->entries; iter != NULL; iter = iter->next) {
		if (dip == iter->ip) {
			return iter->hwadder;
		}
	}
	return NULL;
}

static int ng_arp_entry_insert(uint32_t ip, uint8_t *mac) {
	uint8_t *hwaddr = ng_get_dst_macaddr(ip);
	if (hwaddr == NULL) {
		struct arp_table *table = arp_table_instance();
		struct arp_entry *entry = rte_malloc("arp entry", sizeof(struct arp_entry), 0);
		//如何内存分配失败，进程不退出，后续会重试
		if (entry) {
			memset(entry, 0, sizeof(struct arp_entry));
			entry->ip = ip;
			rte_memcpy(entry->hwadder, mac, RTE_ETHER_ADDR_LEN);
			entry->type = ARY_ENTRY_STATUS_DYNAMIC;
			LL_ADD(entry, table->entries);
			table->count++;
		}
		return 1;
	}

	return 0;
}


//TCP 11个状态
typedef enum _NG_TCP_STATUS {
	NG_TCP_STATUS_CLOSED = 0,
	NG_TCP_STATUS_LISTEN, 
	NG_TCP_STATUS_SYN_RCVD, 
	NG_TCP_STATUS_SYN_SENT, 
	NG_TCP_STATUS_ESTABLISHED,
	
	NG_TCP_STATUS_FIN_WAIT_1, 
	NG_TCP_STATUS_FIN_WAIT_2,
	NG_TCP_STATUS_CLOSING,
	NG_TCP_STATUS_TIME_WAIT,

	NG_TCP_STATUS_CLOSE_WAIT,
	NG_TCP_STATUS_LAST_ACK
} NG_TCP_STATUS;

struct ng_tcp_stream {	//tcp control block
	int fd;			//三次握手完成后accept之后，生成fd
	
	uint32_t sip;
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint16_t sport;
	uint8_t proto;
	
	uint32_t dip;
	uint16_t dport;

	uint32_t snd_next;	//seqnum
	uint32_t rcv_next;	//acknum

	NG_TCP_STATUS status;

	//半连接队列和全连接队列中的stream不存到tcp_table中
	union {
		struct {
			struct ng_tcp_stream *syn_list;		    //半连接队列
			struct ng_tcp_stream *accept_list;	    //全连接队列
		};

		struct {
			struct rte_ring *sndbuffer;
			struct rte_ring *rcvbuffer;
		};
	};

	struct ng_tcp_stream *prev;
	struct ng_tcp_stream *next;

	pthread_cond_t cond;
	pthread_mutex_t mutex;

};

struct ng_tcp_fragment {
	uint16_t sport;  /**< TCP source port. */
	uint16_t dport;  /**< TCP destination port. */
	uint32_t seqnum;  /**< TX data sequence number. */
	uint32_t acknum;  /**< RX data acknowledgement sequence number. */
	uint8_t  hdrlen_off;  /**< Data offset. */
	uint8_t  tcp_flags; /**< TCP flags */
	uint16_t windows;    /**< RX flow control window. */
	uint16_t cksum;     /**< TCP checksum. */
	uint16_t tcp_urp;   /**< TCP urgent pointer, if any. */

	int optlen;
	uint32_t option[TCP_OPTION_LEN];//tcp 头最大为60字节，减去固定20字节，option可以占40理解，
	                               //每个option站4字节，所有最多有10个option
	unsigned char *data;
	size_t length;
};


static struct inout_ring *rInst = NULL;
static struct inout_ring * ringInstance(void) {
	if (rInst == NULL) {
		rInst = rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
		if (rInst == NULL) {
			rte_exit(EXIT_FAILURE, "rte_malloc inout_ring failed");
		}
		memset(rInst, 0, sizeof(struct inout_ring));
	}
	return rInst;
}

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

static int udp_process(struct rte_mbuf *udpmbuf);
struct localhost* get_hostinfo_fromip_port(uint32_t dip, uint16_t sip, uint8_t proto);
int get_fd_frombitmap(void);
static int ng_tcp_out(struct rte_mempool *mbuf_pool);
static int ng_tcp_process(struct rte_mbuf* tcpmbuf);
static struct ng_tcp_table *tcpListenInstance(void);
static int ng_tcp_send_ackpt(struct ng_tcp_stream* stream, struct rte_tcp_hdr *tcphdr);
static int ng_tcp_enqueue_recvbuffer(struct ng_tcp_stream* stream, struct rte_tcp_hdr *tcphdr, int tcplen);
static struct ng_tcp_stream *get_tcp_stream_fromfd(int sockfd);
static struct rte_hash *tcpHashFdInstance(void);
static struct rte_hash *tcpHashTupleInstance(void);



static void ng_init_port(struct rte_mempool *mbuf_pool) {
	//dpdk绑定的网卡数量
	uint16_t nb_sys_ports = rte_eth_dev_count_avail();
	if (nb_sys_ports == 0) {
		rte_exit(EXIT_FAILURE, "not support eth\n");
	}

	struct rte_eth_dev_info dev_info;
	/*获取以太网设备的配置和状态信息。它通常用于初始化网络设备、
	 *配置网络设备或者获取网络设备的状态信息。
	 *这里的端口号和网卡是一一对应的
	 */
	rte_eth_dev_info_get(gDpdkPortId, &dev_info);

	const int num_rx_queues = 1;	//接收队列个数
	const int num_tx_queues = 1;	//发送队列个数
	struct rte_eth_conf port_conf = port_conf_default;
	
	rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);
	// 0是0号接收队列
	// 128是队列长度
	if (rte_eth_rx_queue_setup(gDpdkPortId, 0, 128, rte_eth_dev_socket_id(gDpdkPortId), NULL, mbuf_pool) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
	}

	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	//offloads 成员是一个 64 位无符号整数，每个比特位表示不同的接收功能选项
	txq_conf.offloads = port_conf.rxmode.offloads;
	/* 0是0号发送队列 
	 * 1024是队列长度
	 * 发送队列长度设置太小运行时会报错:Invalid value for nb_tx_desc(=128), should be: <= 4096, >= 512, and a product of 1
	 */
	if (rte_eth_tx_queue_setup(gDpdkPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkPortId), &txq_conf) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
	}

	if (rte_eth_dev_start(gDpdkPortId) < 0) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}

	//开启混杂模式
	//rte_eth_promiscuous_enable(gDpdkPortId);
	

}


static void ng_encode_udp_pkt(uint8_t *msg, uint32_t sip, uint32_t dip, uint16_t sport, 
		uint16_t dport, uint8_t *srcmac, uint8_t *dstmac, unsigned char *data, uint16_t total_len) {

	//设置以太网头
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	//设置ipv4头
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64;
	//dpdk中没有UDP类型的定义，使用内核的协议类型
	ip->next_proto_id = IPPROTO_UDP;
	ip->src_addr = sip;
	ip->dst_addr = dip;
	//计算ip头部校验和时，先把该字段置为0(ip校验和只包括头部)
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	//设置udp头
	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
	udp->src_port = sport;
	udp->dst_port = dport;
	uint16_t udp_len = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
	udp->dgram_len = htons(udp_len);
	memcpy((uint8_t *)(udp + 1), data, udp_len - sizeof(struct rte_udp_hdr));
	//计算udp校验和，udp校验位包括负载数据
	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);
}

static struct rte_mbuf *ng_upd_pkg(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip, uint16_t sport, 
		uint16_t dport, uint8_t *srcmac, uint8_t *dstmac, unsigned char *data, uint16_t length) {

	const unsigned total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + length;
	
	//从内存中申请一个mbuf
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (mbuf == NULL) {
		return NULL;
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	//用于将数据包缓冲区（packet buffer）转换为指定类型的数据指针，也就是mbuf存储数据包的首地址
	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);
	ng_encode_udp_pkt(pktdata, sip, dip, sport, dport, srcmac, dstmac, data, total_len);

	return mbuf;
}

static int udp_process(struct rte_mbuf *udpmbuf) {
	struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(udpmbuf, struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
	struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

	//对于广播的udp报文，直接丢弃
	struct localhost *host = get_hostinfo_fromip_port(iphdr->dst_addr, udphdr->dst_port, iphdr->next_proto_id);
	if (host == NULL) {
        printf("udp_process not found udp server\n");
		return -3;
	}

	struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
	if (ol == NULL) {
		return -1;
	}

	ol->dip = iphdr->dst_addr;
	ol->sip = iphdr->src_addr;
	ol->sport = udphdr->src_port;
	ol->dport = udphdr->dst_port;
	ol->protocol = IPPROTO_UDP;
	ol->length = ntohs(udphdr->dgram_len) - sizeof(struct rte_udp_hdr);

	ol->data = rte_malloc("unsigned char*", ol->length, 0);
	if (ol->data == NULL) {
		rte_pktmbuf_free(udpmbuf);
		rte_free(ol);
		return -2;
	}

	rte_memcpy(ol->data, (char*)(udphdr+1), ol->length);
	rte_ring_mp_enqueue(host->rcvbuffer, ol);

	pthread_mutex_lock(&host->mutex);
	pthread_cond_signal(&host->cond);
	pthread_mutex_unlock(&host->mutex);
	
	//两个字节以上的变量是需要大小端转换
	uint16_t length = ntohs(udphdr->dgram_len);
	*((char*)udphdr + length) = '\0';

	struct in_addr addr;
	addr.s_addr = iphdr->src_addr;
	printf("udp src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));
	addr.s_addr = iphdr->dst_addr;
	printf("dst: %s:%d, %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port), (char *)(udphdr+1));

	return 0;

}

//offload -> mbuf
static void udp_out(struct rte_mempool *mbuf_pool) {
	struct localhost *host = NULL;
	struct inout_ring *ring = ringInstance();
	for (host = lhost; host != NULL; host = host->next) {
		struct offload *ol = NULL;
		int nb_send = rte_ring_mc_dequeue(host->sndbuffer, (void**)&ol);
		if (nb_send < 0) continue;
		uint8_t *dstmac = ng_get_dst_macaddr(ol->dip);
		if (dstmac == NULL) {
			printf("cannot find mac for ip:%x\n", ol->dip);
			continue;
		} else {
			struct rte_mbuf *udpbuf = ng_upd_pkg(mbuf_pool, ol->sip, ol->dip, ol->sport, ol->dport, 
													host->localmac, dstmac, ol->data, ol->length);
			rte_ring_mp_enqueue(ring->out, udpbuf);
			if (ol->data != NULL)
				rte_free(ol->data);
			rte_free(ol);
		}
	}
}

static void print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}


static void burst_free_mbufs(struct rte_mbuf **pkts, unsigned num)
{
	unsigned i;

	if (pkts == NULL)
		return;

	for (i = 0; i < num; i++) {
		rte_pktmbuf_free(pkts[i]);
		pkts[i] = NULL;
	}
}


static int
pkt_process(__attribute__((unused)) void *arg)
{
	puts("pkt_process-----");
	struct rte_mempool *mbuf_pool = (struct rte_mempool*)arg;
	struct inout_ring *ring = ringInstance();

	while(1) {
		struct rte_mbuf *mbufs[BURST_SIZE] = {0};
		unsigned num_recvd = rte_ring_mc_dequeue_burst(ring->in, (void**)mbufs, BURST_SIZE, NULL);

		unsigned int i = 0;
		for (i = 0; i < num_recvd; i++) {
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
			
			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				rte_kni_tx_burst(global_kni, &mbufs[i], 1);
				//rte_kni_handle_request(global_kni);
				continue;
			}
			
			struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
			
			if (iphdr->next_proto_id != IPPROTO_UDP && iphdr->next_proto_id != IPPROTO_TCP) {
				rte_kni_tx_burst(global_kni, &mbufs[i], 1);
				//rte_kni_handle_request(global_kni);
				continue;
			}

			ng_arp_entry_insert(iphdr->src_addr, ehdr->s_addr.addr_bytes);

			if (iphdr->next_proto_id == IPPROTO_UDP) {
				udp_process(mbufs[i]);
			}

			if (iphdr->next_proto_id == IPPROTO_TCP) {
				ng_tcp_process(mbufs[i]);
			}
			rte_pktmbuf_free(mbufs[i]);
		}
		rte_kni_handle_request(global_kni);
		udp_out(mbuf_pool);
		ng_tcp_out(mbuf_pool);

		struct rte_mbuf *pkts_burst[BURST_SIZE];
		unsigned num_rx_recvd = rte_kni_rx_burst(global_kni, pkts_burst, BURST_SIZE);
		if (unlikely(num_rx_recvd > BURST_SIZE)) {
			printf("Error receiving from KNI\n");
			continue;
		}

		rte_eth_tx_burst(gDpdkPortId, 0, pkts_burst, (uint16_t)num_rx_recvd);
		//if (unlikely(nb_tx < num_rx_recvd)) {
		burst_free_mbufs(pkts_burst, num_rx_recvd);
	}

	return 0;
}


//位图，一个字节中每一位表示一个fd
int get_fd_frombitmap(void) {
	int fd = DEFAULT_FD_NUM;
	for (; fd < MAX_FD_COUNT; fd++) {
		if ((fd_table[fd/8] & (0x1 << (fd % 8))) == 0) {
			fd_table[fd/8] |= 0x1 << (fd % 8);
			return fd;
		}
	}
	return -1;
}

static void set_fd_frombitmap(int sockfd) {
	if (sockfd >= MAX_FD_COUNT) {
		return ;
	}
	fd_table[sockfd/8] &= ~(0x1 << (sockfd % 8));
}

static struct localhost* get_hostinfo_fromfd(int sockfd) {
	struct localhost *host = NULL;
	for (host = lhost; host != NULL; host = host->next) {
		if (sockfd == host->fd) {
			return host;
		}
	}
	
	host = (struct localhost*)get_tcp_stream_fromfd(sockfd);
	if (host != NULL)
		return host;

	struct ng_tcp_stream *stream = NULL;
	struct ng_tcp_table *table = tcpListenInstance();
	for (stream = table->tcp_set; stream != NULL; stream = stream->next) {
		if (sockfd == stream->fd) {
			return (struct localhost*)stream;
		}
	}

	return NULL;
		
}

struct localhost* get_hostinfo_fromip_port(uint32_t dip, uint16_t dport, uint8_t proto) {
	struct localhost *host = NULL;
	for (host = lhost; host != NULL; host = host->next) {
		if (dip == host->localip && dport == host->localport && proto == host->protocol) {
			return host;
		}
	}
	return NULL;
}


static int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused)) int protocol) {
	int fd = get_fd_frombitmap();

	printf("fd:%d\n", fd);
	
	if (type == SOCK_DGRAM) {
		struct localhost *host = rte_malloc("localhost", sizeof(struct localhost), 0);
		if (host == NULL)
			return -1;
		host->fd = fd;
		host->protocol = IPPROTO_UDP;

		host->rcvbuffer = rte_ring_create("recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (host->rcvbuffer == NULL) {
			rte_free(host);
			return -1;
		}

		host->sndbuffer = rte_ring_create("send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (host->sndbuffer == NULL) {
			rte_ring_free(host->rcvbuffer);
			rte_free(host);
			return -1;
		}

		pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
		rte_memcpy(&host->cond, &blank_cond, sizeof(blank_cond));

		pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
		rte_memcpy(&host->mutex, &blank_mutex, sizeof(blank_mutex));
		
		LL_ADD(host, lhost);
	}else if (type == SOCK_STREAM) {
		struct ng_tcp_stream *stream = rte_malloc("ng_tcp_stream", sizeof(struct ng_tcp_stream), 0);
		if (stream == NULL)
			return -1;
		memset(stream, 0, sizeof(struct ng_tcp_stream));
		stream->fd = fd;
		stream->proto = IPPROTO_TCP;

		pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
		rte_memcpy(&stream->cond, &blank_cond, sizeof(blank_cond));

		pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
		rte_memcpy(&stream->mutex, &blank_mutex, sizeof(blank_mutex));
		
		struct ng_tcp_table *table = tcpListenInstance();
		LL_ADD(stream, table->tcp_set);
	} 

	
	return fd;
}

static int nbind(int sockfd, const struct sockaddr *addr, __attribute__((unused)) socklen_t addrlen) {
	void *hostinfo = get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) {
		return -1;
	}
	struct localhost *host = (struct localhost *)hostinfo;
	if (host->protocol == IPPROTO_UDP) {
		const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
		host->localport = laddr->sin_port;
		host->localip = laddr->sin_addr.s_addr;
		rte_memcpy(host->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);
	} else if (host->protocol == IPPROTO_TCP) {
		struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
		const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
		stream->dport = laddr->sin_port;
		stream->dip = laddr->sin_addr.s_addr;
		rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);
		stream->status = NG_TCP_STATUS_CLOSED;
	}
	
	return 0;
}

static ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags,
                        struct sockaddr *src_addr, __attribute__((unused)) socklen_t *addrlen) {
	struct localhost *host = get_hostinfo_fromfd(sockfd);
	if (host == NULL) {
		printf("host empty\n");
		return -1;
	}

	struct offload *ol = NULL;
	unsigned char *ptr = NULL;
	ssize_t data_len = 0;

	//接受队列空则阻塞等待
	pthread_mutex_lock(&host->mutex);
	while(rte_ring_mc_dequeue(host->rcvbuffer, (void**)&ol) <0) {
		pthread_cond_wait(&host->cond, &host->mutex);
	}
	pthread_mutex_unlock(&host->mutex);

	struct sockaddr_in *saddr = (struct sockaddr_in*)src_addr;
	saddr->sin_port = ol->sport;
	saddr->sin_addr.s_addr = ol->sip;
	printf("nrecvfrom ol->length:%d len:%ld\n", ol->length, len);

	if (len < ol->length) {
		rte_memcpy(buf, ol->data, len);
		ptr = rte_malloc("unsigned char*", ol->length-len, 0);
		rte_memcpy(ptr, ol->data+len, ol->length-len);
		rte_free(ol->data);
		ol->data = ptr;
		ol->length -= len;
		rte_ring_mp_enqueue(host->rcvbuffer, ol);
		return len;
	} else {
		data_len = ol->length;
		rte_memcpy(buf, ol->data, ol->length);
		rte_free(ol->data);
		rte_free(ol);
		return data_len;
	}
	
}
static ssize_t nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused)) int flags,
                      const struct sockaddr *dest_addr, __attribute__((unused)) socklen_t addrlen) {
    struct localhost *host = get_hostinfo_fromfd(sockfd);
	if (host == NULL) {
		return -1;
	}

	struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
	if (ol == NULL) return -1;

	const struct sockaddr_in *daddr = (const struct sockaddr_in*)dest_addr;

	ol->dip = daddr->sin_addr.s_addr;
	ol->dport = daddr->sin_port;
	ol->sip = host->localip;
	ol->sport = host->localport;
	ol->length = len;
	ol->data = rte_malloc("unsigned char*", len, 0);
	if (ol->data == NULL) {
		rte_free(ol);
		return -1;
	}

	rte_memcpy(ol->data, buf, len);

	rte_ring_mp_enqueue(host->sndbuffer, ol);

	return len;
}

static int nclose(int sockfd) {
	void *hostinfo = get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;

	struct localhost* host = (struct localhost*)hostinfo;
	if (host->protocol == IPPROTO_UDP) {
		LL_REMOVE(host, lhost);
		if (host->rcvbuffer) {
			rte_ring_free(host->rcvbuffer);
		}
		if (host->sndbuffer) {
			rte_ring_free(host->sndbuffer);
		}
		rte_free(host);
	} else if (host->protocol == IPPROTO_TCP) {

		struct ng_tcp_stream *stream = (struct ng_tcp_stream*)hostinfo;

		if (stream->status != NG_TCP_STATUS_LISTEN) {	
	
			struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
			if (fragment == NULL) return -1;

			memset(fragment, 0, sizeof(struct ng_tcp_fragment));

			fragment->sport = stream->dport;
			fragment->dport = stream->sport; 


			//客户端发fin，服务端返ack时，已经更新过stream->snd_next和stream->rcv_next
			//这里服务端发fin，不用更新
			fragment->seqnum = stream->snd_next;
			fragment->acknum = stream->rcv_next;
			fragment->tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
			
			fragment->hdrlen_off = 0x50;
			fragment->windows = TCP_INITIAL_WINDOW;
		
			fragment->data = NULL;
			fragment->length = 0;

			stream->status = NG_TCP_STATUS_LAST_ACK;

			struct rte_hash *table = tcpHashFdInstance();
			if (rte_hash_del_key(table, &sockfd) < 0) {
				printf("nclose tcp rte_hash_del_key fail\n");
				rte_free(fragment);
				return -1;
			}

			rte_ring_mp_enqueue(stream->sndbuffer, fragment);
		}else {
			//释放监听套接字
			LL_REMOVE(stream, tcpListenInstance()->tcp_set);
			rte_free(stream);
		}
	}

	set_fd_frombitmap(sockfd);

	return 0;
}

//这个sockfd是已连接套接字
static ssize_t nsend(int sockfd, const void *buf, size_t len, __attribute__((unused)) int flags) {
	void *hostinfo = get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;
	
	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	ssize_t length = 0;
	if (stream->proto == IPPROTO_TCP) {
		struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
		if (fragment == NULL) return -2;

		memset(fragment, 0, sizeof(struct ng_tcp_fragment));
		fragment->sport = stream->sport;
		fragment->dport = stream->dport;
		
		fragment->seqnum = stream->snd_next;
		fragment->acknum = stream->rcv_next;
		
		fragment->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
		fragment->hdrlen_off = 0x50;
		fragment->windows = TCP_INITIAL_WINDOW;

		//len大于mtu时要分包
		fragment->data = rte_malloc("unsigned char*", len, 0);
		if (fragment->data == NULL) {
			rte_free(fragment);
			return -1;
		}
		memset(fragment->data, 0, len);
		rte_memcpy(fragment->data, buf, len);
		fragment->length = len;
		length = fragment->length;
		//返回值小于0时表示，ring buffer满了，可以做条件等待
		rte_ring_mp_enqueue(stream->sndbuffer, fragment);
	}
	return length;
}

//根据fd从哈希表中查询tcp连接
static struct ng_tcp_stream *get_tcp_stream_fromfd(int sockfd) {
	struct rte_hash *table = tcpHashFdInstance();
	struct ng_tcp_stream *stream = NULL;
	
	if (rte_hash_lookup_data(table, &sockfd, (void**)&stream) < 0) 
		return NULL;
	
	return stream;
}

//这个sockfd是已连接套接字
static ssize_t nrecv(int sockfd, void *buf, size_t len,  __attribute__((unused)) int flags) {
	void *hostinfo = get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;
	
	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	ssize_t length = 0;
	if (stream->proto == IPPROTO_TCP) {
		struct ng_tcp_fragment *fragment = NULL;
		int nb_recv = 0;
		pthread_mutex_lock(&stream->mutex);
		while((nb_recv = rte_ring_mc_dequeue(stream->rcvbuffer, (void**)&fragment)) < 0) {
			pthread_cond_wait(&stream->cond, &stream->mutex);
		}
		pthread_mutex_unlock(&stream->mutex);

		if (fragment->length > len) {
			rte_memcpy(buf, fragment->data, len);
			size_t i = 0;
			for(i = len; i < fragment->length; i++) {
				fragment->data[i-len] = fragment->data[i]; 
			}
			fragment->length = fragment->length - len;
			length = len;
			rte_ring_mp_enqueue(stream->sndbuffer, fragment);
		} else if (fragment->length == 0) {
			rte_free(fragment);
			length = 0;
		} else {
			rte_memcpy(buf, fragment->data, fragment->length);
			length = fragment->length;
			if (fragment->data != NULL) {
				rte_free(fragment->data);
			}
			rte_free(fragment);
		}
	}
	return length;
}

//这个sockfd是监听套接字
static int naccept(int sockfd, struct sockaddr *addr, __attribute__((unused)) socklen_t *addrlen) {
	void *hostinfo = get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;
	
	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->proto == IPPROTO_TCP) {
		struct ng_tcp_stream *apt = NULL;
		pthread_mutex_lock(&stream->mutex);
		while(stream->accept_list == NULL) {
			pthread_cond_wait(&stream->cond, &stream->mutex);
		}
		apt = stream->accept_list;
		LL_REMOVE(apt, stream->accept_list);
		pthread_mutex_unlock(&stream->mutex);
		
		apt->fd = get_fd_frombitmap();
		
		struct sockaddr_in* addr_in = (struct sockaddr_in*)addr;
		addr_in->sin_addr.s_addr = apt->sip;
		addr_in->sin_port = apt->sport;

		struct rte_hash *table = tcpHashFdInstance();
		//存储fd->tcp连接跟踪的映射
		if (rte_hash_add_key_data(table, &apt->fd, apt) < 0)
			return -1;
		
		return apt->fd;
	}

	return -1;
}

static int nlisten(int sockfd, __attribute__((unused)) int backlog) {
	void *hostinfo = get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;
	
	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->proto == IPPROTO_TCP) {
		stream->status = NG_TCP_STATUS_LISTEN;
	}

	return 0;
}

static int udp_server_entry(__attribute__((unused)) void *arg) {
	puts("udp_server-----");

	int connfd = nsocket(AF_INET, SOCK_DGRAM, 0);
	if (connfd == -1) {
		printf("socket failed\n");
		return -1;
	}

	struct sockaddr_in localaddr, clientaddr;
	memset(&localaddr, 0, sizeof(struct sockaddr_in));

	localaddr.sin_port = htons(8889);
	localaddr.sin_family = AF_INET;
	localaddr.sin_addr.s_addr = gLocalIp;
	nbind(connfd, (struct sockaddr*)&localaddr, sizeof(localaddr));

	char buffer[UDP_APP_RECV_BUFF_SIZE] = {0};
	socklen_t addrlen;
	while(1) {
		int ret = nrecvfrom(connfd, buffer, UDP_APP_RECV_BUFF_SIZE, 0, (struct sockaddr*)&clientaddr, &addrlen);
		if (ret < 0) {
			continue;
		} else {
			printf("udp recv from %s:%d, data:%.*s\n", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port), ret, buffer);
			nsendto(connfd, buffer, ret, 0, (struct sockaddr*)&clientaddr, sizeof(struct sockaddr));
		}
	}

	nclose(connfd);
	
}

//存储tcp连接跟踪 fd->连接
static struct rte_hash *tcpHashFdInst= NULL;

static struct rte_hash *tcpHashFdInstance(void) {
	if (tcpHashFdInst == NULL) {
		struct rte_hash_parameters *params = rte_malloc("rte_hash_parameters", sizeof(struct rte_hash_parameters), 0);
		if (!params) return NULL;

		memset(params, 0, sizeof(struct rte_hash_parameters));
		params->name = "tcp_hash_fd_table";
		params->entries = 8192;	//哈希表长度
		params->key_len = sizeof(int);
		params->hash_func = rte_jhash;
		params->hash_func_init_val = 0;	//一般设置为0
		params->socket_id = rte_socket_id();
		
		tcpHashFdInst = rte_hash_create(params);
	}

	return tcpHashFdInst;
}

//存储tcp连接跟踪 五元组->连接
static struct rte_hash *tcpHashTupleInst= NULL;

static struct rte_hash *tcpHashTupleInstance(void) {
	if (tcpHashTupleInst == NULL) {
		struct rte_hash_parameters *params = rte_malloc("rte_hash_parameters", sizeof(struct rte_hash_parameters), 0);
		if (!params) return NULL;

		memset(params, 0, sizeof(struct rte_hash_parameters));
		params->name = "tcp_hash_tuple_table";
		params->entries = 8192;	//哈希表长度
		params->key_len = sizeof(struct tcp_conn_key);
		params->hash_func = rte_jhash;
		params->hash_func_init_val = 0;	//一般设置为0
		params->socket_id = rte_socket_id();
		
		tcpHashTupleInst = rte_hash_create(params);
	}

	return tcpHashTupleInst;
}


//存储监听套接字
static struct ng_tcp_table *tListenInst = NULL;

static struct ng_tcp_table *tcpListenInstance(void) {
	if (tListenInst == NULL) {
		tListenInst = rte_malloc("tcpListenInstance", sizeof(struct ng_tcp_table), 0);
		if (tListenInst == NULL) {
			return NULL;
		}
		memset(tListenInst, 0, sizeof(struct ng_tcp_table));
	}

	return tListenInst;
}

static struct ng_tcp_stream *ng_tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {
	struct ng_tcp_stream *stream = rte_malloc("ng_tcp_stream", sizeof(struct ng_tcp_stream), 0);
	if (stream == NULL) {
        printf("ng_tcp_stream_create rte_malloc ng_tcp_stream fail\n");
		return NULL;
	}

	memset(stream, 0, sizeof(struct ng_tcp_stream));

	stream->sip = sip;
	stream->dip = dip;
	stream->sport = sport;
	stream->dport = dport;
	stream->proto = IPPROTO_TCP;

	stream->status = NG_TCP_STATUS_LISTEN;

	//对于名字相同的ring_buffer无法再次创建
	char bufname[32] = {0};
    sprintf(bufname, "recv-buffer-%d-%d", sip, sport);
	stream->rcvbuffer = rte_ring_create(bufname, RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (stream->rcvbuffer == NULL) {
		rte_free(stream);
		printf("ng_tcp_stream_create:rte_ring_create rcvbuffer fail\n");
		return NULL;
	}
    sprintf(bufname, "snd-buffer-%d-%d", sip, sport);
	stream->sndbuffer = rte_ring_create(bufname, RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (stream->sndbuffer == NULL) {
		rte_ring_free(stream->rcvbuffer);
		rte_free(stream);
		printf("ng_tcp_stream_create:rte_ring_create sndbuffer fail\n");
		return NULL;
	}

	uint32_t next_send = time(NULL);
	// rand_r()是线程安全，rand()非线程安全
	stream->snd_next = rand_r(&next_send) % TCP_MAX_SEQ;

	rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

	pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
	rte_memcpy(&stream->cond, &blank_cond, sizeof(blank_cond));

	pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
	rte_memcpy(&stream->mutex, &blank_mutex, sizeof(blank_mutex));

	return stream;
}

//删除哈希表中五元组->tcp连接
static int ng_tcp_stream_delete(uint32_t sip, uint32_t dip, uint16_t sport, 
											uint16_t dport) {
	struct rte_hash *tcp_hash_tuple_table = tcpHashTupleInstance();
	struct tcp_conn_key conn_key = {0};
	conn_key.sip = sip;
	conn_key.dip = dip;
	conn_key.sport = sport;
	conn_key.dport = dport;
	conn_key.proto = TCP_PROTO;
	
	if (rte_hash_del_key(tcp_hash_tuple_table, &conn_key) < 0) 
		return -1;

	return 0;
}


//往哈希表中插入五元组->tcp连接
static int ng_tcp_stream_insert(uint32_t sip, uint32_t dip, uint16_t sport, 
											uint16_t dport, struct ng_tcp_stream *stream) {
	struct rte_hash *tcp_hash_tuple_table = tcpHashTupleInstance();
	struct tcp_conn_key conn_key = {0};
	conn_key.sip = sip;
	conn_key.dip = dip;
	conn_key.sport = sport;
	conn_key.dport = dport;
	conn_key.proto = TCP_PROTO;
	
	if (rte_hash_add_key_data(tcp_hash_tuple_table, &conn_key, stream) < 0) 
		return -1;

	return 0;
}

static struct ng_tcp_stream *ng_tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {

	struct rte_hash *tcp_hash_tuple_table = tcpHashTupleInstance();
	
	struct tcp_conn_key conn_key = {0};
	conn_key.sip = sip;
	conn_key.dip = dip;
	conn_key.sport = sport;
	conn_key.dport = dport;
	conn_key.proto = TCP_PROTO;
	
	struct ng_tcp_stream *stream = NULL;
	if (rte_hash_lookup_data(tcp_hash_tuple_table, &conn_key, (void**)&stream) >= 0) 
		return stream;

	//查找监听套接字
	struct ng_tcp_table * table = tcpListenInstance();
	struct ng_tcp_stream *iter = NULL;
	for(iter = table->tcp_set; iter != NULL; iter = iter->next) {
		if (iter->dport == dport && iter->status == NG_TCP_STATUS_LISTEN) {
			return iter;
		}
	}
	
	return NULL;
}

static int ng_tcp_handler_established(struct ng_tcp_stream* stream, struct rte_tcp_hdr *tcphdr, int tcplen) {
	puts("ng_tcp_handler_established");
	if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {
		
	}
	if (tcphdr->tcp_flags & RTE_TCP_PSH_FLAG) {
		
		ng_tcp_enqueue_recvbuffer(stream, tcphdr, tcplen);
				
		//ack pkt
		int payloadlen = tcplen - (tcphdr->data_off >> 4) * 4;
		stream->rcv_next = stream->rcv_next + payloadlen;
		stream->snd_next = ntohl(tcphdr->recv_ack); 
		ng_tcp_send_ackpt(stream, tcphdr);
	}
	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {
		
	}
	if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {
		stream->status = NG_TCP_STATUS_CLOSE_WAIT;
		
		ng_tcp_enqueue_recvbuffer(stream, tcphdr, tcplen);

		//ack pkt
		stream->rcv_next = stream->rcv_next + 1;
		stream->snd_next = ntohl(tcphdr->recv_ack);
		ng_tcp_send_ackpt(stream, tcphdr);
	}
	
	return 0;
}

static int ng_tcp_enqueue_recvbuffer(struct ng_tcp_stream* stream, struct rte_tcp_hdr *tcphdr, int tcplen) {
	struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
	if (fragment == NULL) return -1;
	memset(fragment, 0, sizeof(struct ng_tcp_fragment));

	//这个端口给应用层用，所以转下
	fragment->dport = ntohs(tcphdr->dst_port);
	fragment->sport = ntohs(tcphdr->src_port);

	uint8_t hdrlen = tcphdr->data_off >> 4;
	int payloadlen = tcplen - hdrlen * 4;
	if (payloadlen > 0) {
		uint8_t *payload = (uint8_t *)tcphdr + hdrlen * 4;
		fragment->data = rte_malloc("unsigned char*", payloadlen, 0);
		if (fragment->data == NULL) {
			rte_free(fragment);
			return -1;
		}
		memset(fragment->data, 0, payloadlen);
		rte_memcpy(fragment->data, payload, payloadlen);
		fragment->length = payloadlen;
		
		printf("tcp: %.*s\n", payloadlen, payload);
	}
	
	rte_ring_mp_enqueue(stream->rcvbuffer, fragment);

	pthread_mutex_lock(&stream->mutex);
	pthread_cond_signal(&stream->cond);
	pthread_mutex_unlock(&stream->mutex);

	return 0;
}

static int ng_tcp_send_ackpt(struct ng_tcp_stream* stream, struct rte_tcp_hdr *tcphdr) {
	//ack pkt
	struct ng_tcp_fragment *ackfrag = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
	if (ackfrag == NULL) return -1;
	memset(ackfrag, 0, sizeof(struct ng_tcp_fragment));
	
	ackfrag->sport = tcphdr->dst_port;
	ackfrag->dport = tcphdr->src_port; 
	
	ackfrag->seqnum = stream->snd_next;
	ackfrag->acknum = stream->rcv_next;

	ackfrag->tcp_flags = RTE_TCP_ACK_FLAG;
	ackfrag->hdrlen_off = 0x50;
	ackfrag->windows = TCP_INITIAL_WINDOW;

	ackfrag->data = NULL;
	ackfrag->length = 0;

	//tcp_out从stream->sndbuffer中取数据发送
	rte_ring_mp_enqueue(stream->sndbuffer, ackfrag);

	return 0;
}

static int ng_tcp_handle_lask_ack(struct ng_tcp_stream* stream, struct rte_tcp_hdr *tcphdr) {
	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {
		if (stream->status == NG_TCP_STATUS_LAST_ACK) {
			stream->status = NG_TCP_STATUS_CLOSED;

			if (ng_tcp_stream_delete(stream->sip, stream->dip, stream->sport, stream->dport) <  0) {
				return -1;
			}

			rte_ring_free(stream->rcvbuffer);
			rte_ring_free(stream->sndbuffer);

			rte_free(stream);
		}
	}
	
	return 0;	
}


static int ng_tcp_handler_syn_rcvd(struct ng_tcp_stream* stream, struct rte_tcp_hdr *tcphdr) {
	puts("ng_tcp_handler_syn_rcvd");
	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {
		if (stream->status == NG_TCP_STATUS_SYN_RCVD) {
			uint32_t acknum = ntohl(tcphdr->recv_ack);
			if (stream->snd_next + 1 == acknum) {
				struct ng_tcp_stream *listener = ng_tcp_stream_search(0, 0, 0, stream->dport);
				if (listener == NULL) {
					//这里失败，tcp服务端协程就卡住了，工作不了，所以整个进程退出
					rte_exit(EXIT_FAILURE, "g_tcp_stream_search listener failed\n");
					return -1;
				}
				stream->status = NG_TCP_STATUS_ESTABLISHED;
				LL_REMOVE(stream, listener->syn_list);
				
				//naccept阻塞返回
				pthread_mutex_lock(&listener->mutex);
				LL_ADD(stream, listener->accept_list);
				pthread_cond_signal(&listener->cond);
				pthread_mutex_unlock(&listener->mutex);
			}
		}
	}

	return 0;
}


static int ng_tcp_handler_listen(struct ng_tcp_stream* stream, struct rte_tcp_hdr *tcphdr, struct rte_ipv4_hdr *iphdr) {
	puts("ng_tcp_handler_listen");
	if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {
		if (stream->status == NG_TCP_STATUS_LISTEN) {
			struct ng_tcp_stream *syn = ng_tcp_stream_create(iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port);
			if (syn == NULL) return -1;
			syn->fd = -1;
			
			struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
			if (fragment == NULL) return -1;
			memset(fragment, 0, sizeof(struct ng_tcp_fragment));

			fragment->sport = tcphdr->dst_port;
			fragment->dport = tcphdr->src_port;

			fragment->seqnum = syn->snd_next;
			syn->rcv_next =  ntohl(tcphdr->sent_seq) + 1;
			fragment->acknum = syn->rcv_next;

			fragment->tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
			fragment->hdrlen_off = 0x50;
			fragment->windows = TCP_INITIAL_WINDOW;

			fragment->data = NULL;
			fragment->length = 0;

			//ng_tcp_out从stream->sndbuffer中取数据发送
			rte_ring_mp_enqueue(syn->sndbuffer, fragment);
			
			syn->status = NG_TCP_STATUS_SYN_RCVD;

			ng_tcp_stream_insert(iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port, syn);
			struct ng_tcp_stream *listener = ng_tcp_stream_search(0, 0, 0, stream->dport);
			//加入半连接队列
			LL_ADD(syn, listener->syn_list);
		}
	}
	return 0;
}

static void ng_encode_tcp_pkt(uint8_t *msg, uint32_t sip, uint32_t dip, uint16_t sport, 
		uint16_t dport, uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment, 
																	const unsigned total_len) {

	//设置以太网头
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	//设置ipv4头
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64;
	//dpdk中没有UDP类型的定义，使用内核的协议类型
	ip->next_proto_id = IPPROTO_TCP;
	ip->src_addr = sip;
	ip->dst_addr = dip;
	//计算ip头部校验和时，先把该字段置为0(ip校验和只包括头部)
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	//设置tcp头
	struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
	tcp->src_port = sport;
	tcp->dst_port = dport;
	tcp->sent_seq = htonl(fragment->seqnum);
	tcp->recv_ack = htonl(fragment->acknum);
	tcp->data_off = fragment->hdrlen_off;
	tcp->rx_win = fragment->windows;
	tcp->tcp_urp = fragment->tcp_urp;
	tcp->tcp_flags = fragment->tcp_flags;
	
	memcpy((uint8_t* )(tcp+1) + fragment->optlen*sizeof(uint32_t), fragment->data, fragment->length);
	//计算tcp校验和，tcp校验位包括负载数据
	tcp->cksum = 0;
	tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);
}

static struct rte_mbuf *ng_tcp_pkg(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip, uint16_t sport, 
		uint16_t dport, uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment) {

	const unsigned total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + 
		sizeof(struct rte_tcp_hdr) + fragment->length + fragment->optlen * sizeof(uint32_t);
	
	//从内存中申请一个mbuf
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (mbuf == NULL) {
		return NULL;
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	//用于将数据包缓冲区（packet buffer）转换为指定类型的数据指针，也就是mbuf存储数据包的首地址
	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);
	ng_encode_tcp_pkt(pktdata, sip, dip, sport, dport, srcmac, dstmac, fragment, total_len);

	return mbuf;
}


static int ng_tcp_out(struct rte_mempool *mbuf_pool) {
	struct ng_tcp_stream *stream = NULL;
	struct inout_ring *ring = ringInstance();
	struct rte_hash *table = tcpHashTupleInstance();
	struct tcp_conn_key *key = NULL;
	uint32_t next = 0;
 
	//遍历所有哈希节点
	while(rte_hash_iterate(table, (const void**)&key, (void**)&stream, &next) >= 0) {
		if (stream->status == NG_TCP_STATUS_LISTEN)
			continue;
		struct ng_tcp_fragment *fragment = NULL;
		int nb_send = rte_ring_mc_dequeue(stream->sndbuffer, (void**)&fragment);
		if (nb_send < 0) continue;
		uint8_t *dstmac = ng_get_dst_macaddr(stream->sip);
		if (dstmac == NULL) {
			printf("cannot find mac for ip:%x\n", stream->sip);
			continue;
		} else {
			struct rte_mbuf *tcpbuf = ng_tcp_pkg(mbuf_pool, stream->dip, stream->sip, stream->dport, stream->sport, 
													stream->localmac, dstmac, fragment);
			rte_ring_mp_enqueue(ring->out, tcpbuf);
			if (fragment->data != NULL)
				rte_free(fragment->data);
			rte_free(fragment);
		}
		
	}
	return 0;
}

static int ng_tcp_process(struct rte_mbuf* tcpmbuf) {
	struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(tcpmbuf, struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
	struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(iphdr + 1);	

	struct in_addr addr;
	addr.s_addr = iphdr->src_addr;
	printf("tcp src: %s:%d, ", inet_ntoa(addr), ntohs(tcphdr->src_port));
	addr.s_addr = iphdr->dst_addr;
	printf("dst: %s:%d\n", inet_ntoa(addr), ntohs(tcphdr->dst_port));

	uint16_t tcpcksum = tcphdr->cksum;
	tcphdr->cksum = 0;
	uint16_t cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);
	if (cksum != tcpcksum) {
		printf("ng_tcp_process cksum check fail\n");
		return -1;
	}

	struct ng_tcp_stream *stream = ng_tcp_stream_search(iphdr->src_addr, iphdr->dst_addr, 
										tcphdr->src_port, tcphdr->dst_port);
	
	//匹配不上已有的五元组以及当前tcp监听套接字
	if (stream == NULL) {
		printf("ng_tcp_process: ng_tcp_stream_search get stream is NULL\n");
		return -2;
	}

	switch(stream->status) {
		case NG_TCP_STATUS_CLOSED:		//client
			break;
		case NG_TCP_STATUS_LISTEN:		//server
			//如果连续来两次syn报文，第一次取出的是监听套接字的stream，
			//第二次取的是处于半连接状态的stream
			ng_tcp_handler_listen(stream, tcphdr, iphdr);
			break;
		case NG_TCP_STATUS_SYN_RCVD:	//server
			ng_tcp_handler_syn_rcvd(stream, tcphdr);
			break;
		case NG_TCP_STATUS_SYN_SENT:	//client
			break;
		case NG_TCP_STATUS_ESTABLISHED: {	//server | client
			int tcplen = ntohs(iphdr->total_length) - ((iphdr->version_ihl) & 0x0F) * 4;
			ng_tcp_handler_established(stream, tcphdr, tcplen);
			break;
		}
		case NG_TCP_STATUS_FIN_WAIT_1:	//~client
			break;
		case NG_TCP_STATUS_FIN_WAIT_2:	//~clinet
			break;
		case NG_TCP_STATUS_CLOSING:		//~client
			break;
		case NG_TCP_STATUS_TIME_WAIT:	//~client
			break;
		case NG_TCP_STATUS_CLOSE_WAIT:	//~server
			break;
		case NG_TCP_STATUS_LAST_ACK:	//~client
			ng_tcp_handle_lask_ack(stream, tcphdr);
			break;
	}
	

	return 0;
}

#define BUFFER_SIZE 1024
static int tcp_server_entry(__attribute__((unused)) void *arg) {
	puts("tcp_server-----");

	int listenfd = nsocket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1) {
		printf("socket failed\n");
		return -1;
	}

	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(struct sockaddr_in));

	servaddr.sin_port = htons(8889);
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = gLocalIp;

	if (nbind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
		puts("tcp_server_entry nbind fail");
		return -1;
	}

	nlisten(listenfd, 10);

	while(1) {
		struct sockaddr_in clientaddr;
		socklen_t len = sizeof(clientaddr);
		int sockfd = naccept(listenfd,(struct sockaddr*)&clientaddr,  &len);

		char buffer[BUFFER_SIZE] = {0};
		
		while(1) {
			int n = nrecv(sockfd , buffer, BUFFER_SIZE, 0); //block
			if (n > 0) {
				nsend(sockfd, buffer, n, 0);
			} else if (n == 0) {
				nclose(sockfd);
				break;
			}
		}
	}

	nclose(listenfd);

	return 0;
}

// ifconfig vEth0 up 和 ifconfig vEth0 down 都走这个函数
static int ng_config_network_if(uint16_t port_id, uint8_t if_up) {

	//判断port_id是否合法
	if (!rte_eth_dev_is_valid_port(port_id)) {
		//EINVAL是一个常见的错误代码，表示传递给函数的参数无效或不合法
		return -EINVAL;
	}

	int ret = 0;
	
	if (if_up) {
		//为什么要停止
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
	} else {
		rte_eth_dev_stop(port_id);
	}

	if (ret < 0) {
		printf("failed to start port:%d\n", port_id);
	}

	return 0;
}


static struct rte_kni *ng_alloc_kni(struct rte_mempool *mbuf_pool) {
	struct rte_kni *kni_handle = NULL;

	struct rte_kni_conf conf = {0};
	snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%d", gDpdkPortId);
	conf.group_id = gDpdkPortId;
	conf.mbuf_size = MAX_PACKET_SIZE;
	rte_memcpy(conf.mac_addr, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_eth_dev_get_mtu(gDpdkPortId, &conf.mtu);
	
	struct rte_kni_ops ops = {0};
	ops.port_id = gDpdkPortId;
	ops.config_network_if = ng_config_network_if;

	kni_handle = rte_kni_alloc(mbuf_pool, &conf, &ops);

	if (kni_handle == NULL) {
		rte_exit(EXIT_FAILURE, "Failed to create kni for port:%d\n", gDpdkPortId);
	}

	return kni_handle;
}

static void
log_link_state(struct rte_kni *kni, int prev, struct rte_eth_link *link)
{
	if (kni == NULL || link == NULL)
		return;

	if (prev == ETH_LINK_DOWN && link->link_status == ETH_LINK_UP) {
		printf( "%s NIC Link is Up %d Mbps %s %s.\n",
			rte_kni_get_name(kni),
			link->link_speed,
			link->link_autoneg ?  "(AutoNeg)" : "(Fixed)",
			link->link_duplex ?  "Full Duplex" : "Half Duplex");
	} else if (prev == ETH_LINK_UP && link->link_status == ETH_LINK_DOWN) {
		printf( "%s NIC Link is Down.\n",
			rte_kni_get_name(kni));
	}
}



static void *
monitor_all_ports_link_status(void *arg)
{
	struct rte_eth_link link;
	
	int prev;
	(void) arg;

	while (1) {
		rte_delay_ms(500);
			
		memset(&link, 0, sizeof(link));
		rte_eth_link_get_nowait(gDpdkPortId, &link);
			
		prev = rte_kni_update_link(global_kni, link.link_status);
		log_link_state(global_kni, prev, &link);
	}
	return NULL;
}


int main(int argc, char *argv[]) {
	/*dpdk初始化资源
	 *用于初始化 Environment Abstraction Layer (EAL)。EAL 是 DPDK 的一个核心组件，
	 *负责抽象和管理硬件和操作系统依赖性，使得上层应用可以在不同的硬件和操作系统上
	 *以统一的方式运行。
	 */
	if (rte_eal_init(argc, argv) < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	}

	//内存池，接收的数据存在该内存池中
	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NUM_MBUFS,
			0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
	}

	//初始化kni, 该函数参数没有用，填什么值都可以
	if (-1 == rte_kni_init(gDpdkPortId)) {
		rte_exit(EXIT_FAILURE, "kni ini failed\n");
	}

	//获取dpdk绑定的网卡源mac
	rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac);

	//kni_alloc
	global_kni = ng_alloc_kni(mbuf_pool);

	ng_init_port(mbuf_pool);


	struct inout_ring *ring = ringInstance();
	if (ring->in == NULL) {
		ring->in = rte_ring_create("in_ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}
	if (ring->out == NULL) {
		ring->out = rte_ring_create("out_ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}

	//该线程是绑核的，获取下一个可以用的核(rte_get_next_lcore)，如果核不够的话多线程起不来
	unsigned now_thread_id = rte_lcore_id();
	printf("now_thread_id:%d\n", now_thread_id);

	unsigned udp_thread_id = rte_get_next_lcore(now_thread_id, 1, 0);
	printf("udp_server_id:%d\n", udp_thread_id);
	rte_eal_remote_launch(udp_server_entry, mbuf_pool, udp_thread_id);

	unsigned tcp_thread_id = rte_get_next_lcore(udp_thread_id, 1, 0);
	printf("tcp_thread_id:%d\n", tcp_thread_id);
	rte_eal_remote_launch(tcp_server_entry, mbuf_pool, tcp_thread_id);

	unsigned pkg_thread_id = rte_get_next_lcore(tcp_thread_id, 1, 0);
	printf("pkg_thread_id:%d\n", pkg_thread_id);
	rte_eal_remote_launch(pkt_process, mbuf_pool, pkg_thread_id);	

	pthread_t kni_link_tid;
	int ret = rte_ctrl_thread_create(&kni_link_tid,
				     "KNI link status check", NULL,
				     monitor_all_ports_link_status, NULL);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"Could not create link status thread!\n");
	
	while(1) {

		//rx
		struct rte_mbuf *rx[BURST_SIZE] = {0};
		unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, rx, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receive from eth\n");
		} else if (num_recvd > 0) {
			rte_ring_sp_enqueue_burst(ring->in, (void**)rx, num_recvd, NULL);
		}

		//tx
		struct rte_mbuf *tx[BURST_SIZE] = {0};
		unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void**)tx, BURST_SIZE, NULL);
		if (nb_tx > 0) {
			rte_eth_tx_burst(gDpdkPortId, 0, tx, nb_tx);
			unsigned i = 0;
			for (i = 0; i < nb_tx; i++) {
				rte_pktmbuf_free(tx[i]);
			}
		}
		
	}
	
	return 0;
}

