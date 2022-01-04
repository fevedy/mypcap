#ifndef FORWARD_DATA_H_
#define FORWARD_DATA_H_

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);
void my_packet_handler( u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body);
int get_config();
void InitTcp();

#endif

