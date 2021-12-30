#include <stdio.h>
#include <iostream>
#include <fstream>
#include <unistd.h>

#include <pcap.h>
#include <json/json.h>

using namespace std;

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
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

void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *packet_header,
    const u_char *packet_body
)
{
    print_packet_info(packet_body, *packet_header);
    return;
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
