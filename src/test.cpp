#include <stdio.h>
#include <iostream>
#include <fstream>
#include <unistd.h>

#include <pcap.h>
#include <json/json.h>

#include "CPSocketUtils.h"

using namespace std;

static int m_tcpSocketFd = -1;
static string m_serverIp;

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}


void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_body
)
{
    print_packet_info(packet_body, *packet_header);

    int m_tcpSocketFd = 0;//TODO

    if( m_tcpSocketFd >= 0)
        {

            #if 0
            picLen += TIMESTAMP_LEN;//先发送长度值，长度值等于8字节时间戳长度+图片长度
            sendData[ pos++] = ( picLen >> 24) & 0xFF;
            sendData[ pos++] = ( picLen >> 16) & 0xFF;
            sendData[ pos++] = ( picLen >> 8) & 0xFF;
            sendData[ pos++] = ( picLen >> 0) & 0xFF;
            #endif

            int sendLen = CPSocketUtils::Send( m_tcpSocketFd, (char*)packet_body, packet_header->caplen);
            if( sendLen != packet_header->caplen)
            {
                printf("send failed %d, sent %d\n", packet_header->caplen, sendLen);
                CPSocketUtils::CloseSocket( m_tcpSocketFd);
                m_tcpSocketFd = -1;
            }
        }
}


void get_config()
{
    Json::Value root; 
    string net_card_name;
    int port_count = 0;
    string server_addr;
    int server_port = 0;

    std::ifstream config_doc("config.json", std::ifstream::binary);
    config_doc >> root;
    net_card_name = root["LOCAL"]["NET_CARD_NAME"].asString();
    
    port_count = root["LOCAL"]["LOCAL_PROT"].size();
    if( port_count <= 0)
    {
        printf("error\n");
    }
     printf("port:\n");
    for( int i = 0; i < port_count; i++)
    {
        std::cout << root["LOCAL"]["LOCAL_PROT"][ i].asInt() <<endl;
    }

    server_addr = root["PIXEL"]["SERVER_ADDR"].asString();
    server_port = root["PIXEL"]["SERVER_PORT"].asInt();

    std::cout << net_card_name <<endl;

    std::cout << server_addr <<endl;
    std::cout << server_port <<endl;
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
    int ret = CPSocketUtils::GetIpFromDomain( serverIp, serverIp, sizeof( serverIp));
    if( ret < 0)
    {
        printf("Domain to IP failed\n");
        return ;
    }
    m_serverIp = serverIp;
    printf("socket server is %s\n", m_serverIp.c_str());

    //TODO:使用像素的服务器地址和端口号
    ret = CPSocketUtils::ConnectTcpSocket( m_tcpSocketFd, "192", 192);
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
int main(int argc, char **argv) {

    get_config();

    sleep(1);
    return 0;

    //char dev[] = "eth0";
    pcap_if_t *devs;
    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
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
    return 0;
}
