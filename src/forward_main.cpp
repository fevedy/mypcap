#include <stdio.h>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <unistd.h>

#include <pcap.h>
#include <json/json.h>

#include "CPSocketUtils.h"
#include "forward.h"

using namespace std;

typedef struct tag_client_info
{
    int tcpfd;
    time_t lastUpdataTime;
}ClientInfo_T;

typedef map< string, ClientInfo_T> Client_Map;
typedef void *(*thread_entry_ptr_t)(void *);

static string m_serverIp;
static string m_serDominName;
static int m_serverPort = 0;
string m_netCardName;
static char m_filter_exp[ 128] = { 0};
static Client_Map m_client_map;
static bool is_pthread_exit = false;
static pthread_mutex_t m_data_lock;
static pthread_mutex_t m_map_lock;

//函数声明
int Create_normal_thread(thread_entry_ptr_t entry, void *pPara, pthread_t *pPid, int stacksize);
static void sleep_ms(unsigned const int millisecond);
void *thread_entry( void * param);
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);
int get_tcp_fd( char* src_ip, int ip_len);
int make_new_tcp_fd( char* src_ip, int ip_len);
void del_tcp_fd( char* src_ip, int ip_len);
void update_tcp_fd( char* src_ip, int ip_len);
void update_fd_map();
void payload_handler( char* src_ip, int ip_len, u_char* payload, int payload_len);
void my_packet_handler( u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet);
int init_tcp_fd();

//stacksize 单位为kb
int Create_normal_thread(thread_entry_ptr_t entry, void *pPara, pthread_t *pPid, int stacksize)
{
	pthread_t thread_id;
	pthread_attr_t thread_attr;

	pthread_attr_init(&thread_attr);
	pthread_attr_setscope(&thread_attr, PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize( &thread_attr, stacksize * 1024);
	if(pthread_create(&thread_id, &thread_attr, entry, pPara) == 0)
	{
		pthread_attr_destroy(&thread_attr);
		if(pPid != NULL)
		{
			*pPid = thread_id;
		}

		return 0;
	}

	pthread_attr_destroy(&thread_attr);

	return -1;
}

static void sleep_ms(unsigned const int millisecond) 
{
    struct timeval tval;
    tval.tv_sec = millisecond / 1000;
    tval.tv_usec = millisecond % 1000 * 1000;
    select( 0, NULL, NULL, NULL, &tval);
}

void *thread_entry( void * param)
{
    time_t last_update_time = time( NULL);
    while( !is_pthread_exit)
    {
        time_t now_time = time( NULL);
        if( now_time - last_update_time >= 60)
        {
            update_fd_map();
            last_update_time = now_time;
        }
        else
        {
            sleep_ms( 30000);
        }
    }
    return NULL;
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header)
{
    //printf("Packet capture length: %d\n", packet_header.caplen);
    //printf("Packet total length %d\n", packet_header.len);
}

int get_tcp_fd( char* src_ip, int ip_len)
{
    int tcp_fd = -1;
    Client_Map::iterator it;
    pthread_mutex_lock( &m_map_lock);  
    it = m_client_map.find( src_ip);
    if( it != m_client_map.end())
    {
        tcp_fd = ( *it).second.tcpfd;
        ( *it).second.lastUpdataTime = time( NULL);
	//printf("zys::get: id %s, fd %d\n", src_ip, tcp_fd);
        //这里为了减少搜索的次数，搜索出来后直接更新发送时间了
        pthread_mutex_unlock( &m_map_lock);  
    }
    else
    {
        pthread_mutex_unlock( &m_map_lock);  
        tcp_fd = make_new_tcp_fd( src_ip, ip_len);
    }

    return tcp_fd;
}

int make_new_tcp_fd( char* src_ip, int ip_len)
{
    ClientInfo_T client;
    memset( &client, 0, sizeof( ClientInfo_T));

    int tcp_fd = -1;
    tcp_fd = init_tcp_fd();

    if( tcp_fd >= 0)
    {
        client.tcpfd = tcp_fd;
        client.lastUpdataTime = time( NULL);
        pthread_mutex_lock( &m_map_lock);  
        m_client_map.insert(std::make_pair( src_ip, client));
	//printf("zys::make new: id %s, fd %d\n", src_ip, tcp_fd);
        pthread_mutex_unlock( &m_map_lock);  
    }

    return tcp_fd;
}

void del_tcp_fd( char* src_ip, int ip_len)
{
    Client_Map::iterator it;
    pthread_mutex_lock( &m_map_lock);  
    it = m_client_map.find( src_ip);
    if( it != m_client_map.end())
    {
        CPSocketUtils::CloseSocket( it->second.tcpfd);
	//printf("zys::del: id %s, fd %d\n", src_ip, it->second.tcpfd);
        m_client_map.erase( it->first);
    }
    pthread_mutex_unlock( &m_map_lock);  
}

void update_tcp_fd( char* src_ip, int ip_len)
{
    Client_Map::iterator it;
    pthread_mutex_lock( &m_map_lock);  
    it = m_client_map.find( src_ip);
    if( it != m_client_map.end())
    {
        ( *it).second.lastUpdataTime = time(NULL);
	//printf("zys::update: id %s, fd %d\n", src_ip, it->second.tcpfd);

    }
    pthread_mutex_unlock( &m_map_lock);  
}

void update_fd_map()
{
    time_t now_time = time( NULL);
    Client_Map::iterator it;

    pthread_mutex_lock( &m_map_lock);  
    for( it = m_client_map.begin(); it != m_client_map.end(); ++it)
    {
        if( now_time - it->second.lastUpdataTime > 180)
        {
	    //printf("zys::remove: id %s, fd %d\n", (it->first).c_str(), it->second.tcpfd);
            CPSocketUtils::CloseSocket( it->second.tcpfd);
            m_client_map.erase( it->first);
        }
	else
        {
	    //printf("zys::still alive: id %s, fd %d\n",(it->first).c_str(), it->second.tcpfd);
	}
    }
    pthread_mutex_unlock( &m_map_lock);  
}

void payload_handler( char* src_ip, int ip_len, u_char* payload, int payload_len)
{
    
    int tcp_fd = -1;
    tcp_fd = get_tcp_fd( src_ip, ip_len);

    if( tcp_fd >= 0)
    {
        pthread_mutex_lock( &m_data_lock);  
        int send_len = CPSocketUtils::Send( tcp_fd, ( char*)payload, payload_len);
        pthread_mutex_unlock( &m_data_lock);

        if( send_len != payload_len)
        {
            //printf("send failed %d, sent %d\n",payload_len, send_len);
            del_tcp_fd( src_ip, ip_len);
        }
        else
        {
            //update_tcp_fd( src_ip, ip_len);  
            //为了避免从map中再查询一遍，在第一次查询tcp-fd时就更新了时间
        }
    }
}

void my_packet_handler( u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet)
{
    //print_packet_info(packet_body, *packet_header);
    
    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet;
    if( ntohs( eth_header->ether_type) != ETHERTYPE_IP) 
    {
        //printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;
    char source_ip[ 16] = { 0};

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;

    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);

    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    //printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) 
    {
        //printf("Not a TCP packet. Skipping...\n\n");
        return;
    }

    snprintf( source_ip, sizeof( source_ip), "%d.%d.%d.%d", 
            *(ip_header + 12), *(ip_header + 13), *(ip_header + 14), *(ip_header + 15));
    //假如源地址是服务器地址，直接丢了
    if ( 0 == strncmp( source_ip, m_serverIp.c_str(), sizeof( source_ip))) 
    {
        //printf("this is server to client, skipping\n");
        return;
    }

    tcp_header = packet + ethernet_header_length + ip_header_length;
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    tcp_header_length = tcp_header_length * 4;
    //printf("TCP header length in bytes: %d\n", tcp_header_length);

 /* Add up all the header sizes to find the payload offset */
    int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
    //printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = packet_header->caplen - total_headers_size;
    //printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    //printf("Memory address where payload begins: %p\n\n", payload);
    if( payload_length <= 0)
    {
        //printf("zys::payload size is %d\n", payload_length);
        return ;
    }

    payload_handler( source_ip, sizeof( source_ip), ( u_char*)payload, payload_length);
}

int get_config()
{
    Json::Value root; 
    int port_count = 0;
    int ret = -1;
    int pos = 0;
    ret = access("./config.json", F_OK);
    if( ret < 0)
    {
        //printf("config file is not exist\n");
        exit(1);
    }

    ret = access("./config.json", R_OK);
    if( ret < 0)
    {
        printf("config file cannot be read\n");
        exit(1);
    }

    std::ifstream config_doc("config.json", std::ifstream::binary);
    config_doc >> root;
  
    if( !root.isMember("LOCAL") ||!root.isMember("PIXEL"))
    {
        printf("config has no LOCAL or PIXEL\n");
        exit(1);
    }

    if( root["LOCAL"].isMember("NET_CARD_NAME") && root["LOCAL"]["NET_CARD_NAME"].isString())
    {
        m_netCardName = root["LOCAL"]["NET_CARD_NAME"].asString();
    }
    else
    {
        printf("config has no LOCAL NET_CARD_NAME\n");
        exit(1);
    }

    if( root["LOCAL"].isMember("LOCAL_PROT") && root["LOCAL"]["LOCAL_PROT"].isArray())
    {
        port_count = root["LOCAL"]["LOCAL_PROT"].size();
        if( port_count <= 0)
        {
            printf("config LOCAL_PROT size is less than 1\n");
            exit(1);
        }
        pos = snprintf( m_filter_exp, sizeof( m_filter_exp), "tcp and (dst port %d", root["LOCAL"]["LOCAL_PROT"][ 0u].asInt());
        for( int index = 1; index < port_count; index++)//index从1开始，index 0已经拼接完成
        {
            pos += snprintf( m_filter_exp + pos, sizeof( m_filter_exp) - pos, " or %d", root["LOCAL"]["LOCAL_PROT"][ index].asInt());
        }
        snprintf( m_filter_exp + pos, sizeof( m_filter_exp) - pos, ")");
        //printf("cmd is %s\n", m_filter_exp);
    }
    else
    {
        printf("config has no LOCAL LOCAL_PROT\n");
        exit(1);
    }

//SERVER info
    if( root["PIXEL"].isMember("SERVER_ADDR") && root["PIXEL"]["SERVER_ADDR"].isString())
    {
        m_serDominName = root["PIXEL"]["SERVER_ADDR"].asString();
    }
    else
    {
        printf("config has no PIXEL SERVER_ADDR\n");
        exit(1);
    }

    if( root["PIXEL"].isMember("SERVER_PORT") && root["PIXEL"]["SERVER_PORT"].isInt())
    {
        m_serverPort = root["PIXEL"]["SERVER_PORT"].asInt();    
    }
    else
    {
        printf("config has no PIXEL SERVER_PORT\n");
        exit(1);
    }

    std::cout <<"locat network card card name :" << m_netCardName <<endl;
    std::cout << "pixel server :" << m_serDominName <<endl;
    std::cout << "pixel port :" << m_serverPort <<endl;
    //printf("filter cmd is : %s\n", m_filter_exp);
    return 0;
}

int init_tcp_fd()
{
    char serverIp[ 16] ={ 0}; 
    int ret = -1;
    int fd = -1;

    if( m_serDominName.empty())
    {
        printf("m_serDominName is null\n");
        return -1;
    }

    ret = CPSocketUtils::GetIpFromDomain( m_serDominName.c_str(), serverIp, sizeof( serverIp));
    if( ret < 0)
    {
        printf("Domain to IP failed\n");
        return -1;
    }
    m_serverIp = serverIp;
    //printf("socket server is %s\n", m_serverIp.c_str());

    fd = CPSocketUtils::OpenTcpSocket();
    if( fd < 0)
    {
        printf("socket open failed\n");
        return -1;
    }
    
    ret = CPSocketUtils::ConnectTcpSocket( fd, m_serverIp.c_str(), m_serverPort);
    if( ret != 0)
    {
        printf("connect server [fd=%d] failed!!\n", fd); 
        CPSocketUtils::CloseSocket( fd);
        fd = -1;
    }
    else
    {
        //printf("connect platform success, fd=%d\n",fd); 
    }

    return fd;
}

int main(int argc, char **argv)
{
    int ret = -1;

    pthread_mutex_init( &m_map_lock, NULL);
    pthread_mutex_init( &m_data_lock, NULL);

    ret = get_config();
    if( ret < 0)
    {
        printf("get config error\n");
        return 0;
    }

    //pcap_if_t *devs;
    pcap_t *handle;
    char error_buffer[ PCAP_ERRBUF_SIZE] = { 0};
    struct bpf_program filter;
    bpf_u_int32 subnet_mask, ip;

    Create_normal_thread( thread_entry, NULL, NULL, 4096);

#if 0
    //TODO:也许可以不配置，当配置文件中的网卡名为空时也可以动态获取
    int ret = pcap_findalldevs( &devs, error_buffer);
    if ( ret != 0)
    {
        printf("Error finding device: %s\n", error_buffer);
        return 0;
    }
    //后面网卡可以使用devs->name，或者devs[0].name
#endif

    if( m_netCardName.empty())
    {
        printf("local net card name is empty\n");
        return 0;
    }
    if ( pcap_lookupnet( m_netCardName.c_str(), &ip, &subnet_mask, error_buffer) == -1)
    {
        printf("Could not get information for device: %s\n", m_netCardName.c_str());
        ip = 0;
        subnet_mask = 0;
    }

    handle = pcap_open_live( m_netCardName.c_str(), BUFSIZ, 1, 1000, error_buffer);
    if ( handle == NULL)
    {
        printf("Could not open %s - %s\n", m_netCardName.c_str(), error_buffer);
        return 0;
    }

    if ( pcap_compile( handle, &filter, m_filter_exp, 0, ip) == -1)
    {
        printf("Bad filter - %s\n", pcap_geterr( handle));
        return 0;
    }

    if ( pcap_setfilter( handle, &filter) == -1)
    {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return 0;
    }

    /* pcap_next() or pcap_loop() to get packets from device now */
    /* Only packets over port 80 will be returned. */ 
    pcap_loop( handle, 0, my_packet_handler, NULL);
    
    is_pthread_exit = true;
    pcap_close( handle);
    pthread_mutex_destroy( &m_data_lock);
    pthread_mutex_destroy( &m_map_lock);
    return 0;
}
