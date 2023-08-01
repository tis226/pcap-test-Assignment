#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

#define ETHER_ADDR_LEN 6
struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN]; 
    u_int8_t  ether_shost[ETHER_ADDR_LEN]; 
    u_int16_t ether_type;       
};

struct libnet_ipv4_hdr
{
    u_int8_t ip_vhl;       
    u_int8_t ip_tos;       
    u_int16_t ip_len;     
    u_int16_t ip_id;       
    u_int16_t ip_off;      
    u_int8_t ip_ttl;      
    u_int8_t ip_p;    
    u_int16_t ip_sum;     
    struct in_addr ip_src, ip_dst; 
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;
    u_int16_t th_dport;  
    u_int32_t th_seq; 
    u_int32_t th_ack;    
    u_int8_t th_offx2;  
    u_int8_t th_flags;
    u_int16_t th_win;   
    u_int16_t th_sum;    
    u_int16_t th_urp;    
};

void print_mac(uint8_t *m){
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        printf("%u bytes captured\n", header->caplen);

        struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *)packet;
        printf("smac ");
        print_mac(eth_hdr->ether_shost);
        printf("\n");
        printf("dmac ");
        print_mac(eth_hdr->ether_dhost);
        printf("\n");

        if(ntohs(eth_hdr->ether_type) != 0x0800)
            continue;

        struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *)(packet + 14);
        printf("sip %s\n", inet_ntoa(ip_hdr->ip_src));
        printf("dip %s\n", inet_ntoa(ip_hdr->ip_dst));

        if(ip_hdr->ip_p != IPPROTO_TCP)
            continue;

        uint8_t ip_hdr_len = ((ip_hdr->ip_vhl) & 0x0F) * 4;
        struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)(packet + 14 + ip_hdr_len);
        printf("sport %d\n", ntohs(tcp_hdr->th_sport));
        printf("dport %d\n", ntohs(tcp_hdr->th_dport));

        uint8_t tcp_hdr_len = ((tcp_hdr->th_offx2) >> 4) * 4;
        uint8_t *data = (uint8_t *)(packet + 14 + ip_hdr_len + tcp_hdr_len);
        int data_len = ntohs(ip_hdr->ip_len) - ip_hdr_len - tcp_hdr_len;
        data_len = data_len > 10 ? 10 : data_len;
        printf("data ");
        for(int i = 0; i < data_len; i++) {
            printf("%02x ", data[i]);
        }
        printf("\n");
        printf("---------------------------------------------\n");
    }

    pcap_close(pcap);
}
