#include <stdio.h>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <unistd.h>

#include <pcap.h>
#include <json/json.h>

#include "CPSocketUtils.h"

using namespace std;

static string m_serverIp;
static string m_serDominName;
static int m_serverPort = 0;
static int m_tcpSocketFd = -1;

string m_netCardName;
static char filterCmd[ 64] = { 0};

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header)
{
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}

void my_packet_handler( u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body)
{
    print_packet_info(packet_body, *packet_header);
    if( m_tcpSocketFd >= 0)
    {
        int sendLen = CPSocketUtils::Send( m_tcpSocketFd, (char*)packet_body, packet_header->caplen);
        if( sendLen != packet_header->caplen)
        {
            printf("send failed %d, sent %d\n", packet_header->caplen, sendLen);
            CPSocketUtils::CloseSocket( m_tcpSocketFd);
            m_tcpSocketFd = -1;
        }
    }
}

int get_config()
{
    Json::Value root; 
    int port_count = 0;
    int ret = -1;

    ret = access("./config.json", F_OK);
    if( ret < 0)
    {
        printf("config file is not exist\n");
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

    //TODO:这里是不是要拼凑起来过滤条件
    if( root["LOCAL"].isMember("LOCAL_PROT") && root["LOCAL"]["LOCAL_PROT"].isArray())
    {
        port_count = root["LOCAL"]["LOCAL_PROT"].size();
        if( port_count <= 0)
        {
            printf("config LOCAL_PROT size is less than 1\n");
            exit(1);
        }
        printf("port:\n");
        for( int i = 0; i < port_count; i++)
        {
            std::cout << root["LOCAL"]["LOCAL_PROT"][ i].asInt() <<endl;
        }
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

    std::cout << m_netCardName <<endl;
    std::cout << m_serDominName <<endl;
    std::cout << m_serverPort <<endl;

    //TODO:拼接过滤器
    return 0;
}

void InitTcp()
{
    if( m_tcpSocketFd >= 0)
    {
        return;
    }
	
    char serverIp[ 16] ={ 0}; 

    m_tcpSocketFd = CPSocketUtils::OpenTcpSocket();
    if( m_tcpSocketFd < 0)
    {
        printf("socket open failed\n");
        return;
    }
    
    //TODO:动态获取域名
    int ret = CPSocketUtils::GetIpFromDomain( m_serDominName.c_str(), serverIp, sizeof( serverIp));
    if( ret < 0)
    {
        printf("Domain to IP failed\n");
        return ;
    }
    m_serverIp = serverIp;
    printf("socket server is %s\n", m_serverIp.c_str());

    //TODO:使用像素的服务器地址和端口号
    ret = CPSocketUtils::ConnectTcpSocket( m_tcpSocketFd, m_serverIp.c_str(), m_serverPort);
    if( ret != 0)
    {
        printf("connect server [fd=%d] failed!!\n", m_tcpSocketFd); 
        CPSocketUtils::CloseSocket( m_tcpSocketFd);
        m_tcpSocketFd = -1;
    }
    else
    {
        printf("connect platform success, fd=%d\n",m_tcpSocketFd); 
    }
}

/* For information on what filters are available
   use the man page for pcap-filter
   $ man pcap-filter
*/
int main(int argc, char **argv)
{
    while( 1)
    {
        if( 0 == get_config())
        {
            break;
        }
        else
        {
            sleep( 1);
        }
    }

    pcap_if_t *devs;
    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE] = { 0};
    struct bpf_program filter;
    char filter_exp[] = "port 80";
    bpf_u_int32 subnet_mask, ip;

    //device = pcap_lookupdev(error_buffer);
    int ret = pcap_findalldevs(&devs, error_buffer);
    if ( ret != 0) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    if (pcap_lookupnet(devs->name, &ip, &subnet_mask, error_buffer) == -1) {
        printf("Could not get information for device: %s\n", devs->name);
        ip = 0;
        subnet_mask = 0;
    }

    handle = pcap_open_live(devs->name, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        printf("Could not open %s - %s\n", devs->name, error_buffer);
        return 2;
    }

    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    /* pcap_next() or pcap_loop() to get packets from device now */
    /* Only packets over port 80 will be returned. */ 
    pcap_loop(handle, 0, my_packet_handler, NULL);
    
    pcap_close( handle);
    return 0;
}
