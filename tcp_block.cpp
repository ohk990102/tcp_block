#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>

#define ASSERT(cond, msg)\
if(!(cond)) {\
    fprintf(stderr, "ASSERT FAILED [%s:%d]: %s\n", __FILE__, __LINE__, (msg));\
    exit(-1);\
}

#ifdef DEBUG
#define DASSERT(cond, msg)\
if(!(cond)) {\
    fprintf(stderr, "DASSERT FAILED [%s:%d]: %s\n", __FILE__, __LINE__, (msg));\
    exit(-1);\
}

#define DEBUG_PRINT(fmt, ...) printf("DEBUG PRINT [%s:%d]: " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define DASSERT(...) {}
#define DEBUG_PRINT(...) {}
#endif

#define MIN_HTTP_REQUEST_SIZE   24
#define MAX_ITER                20

#pragma pack(push, 1)
struct attack_packet {
    struct libnet_ethernet_hdr ether;
    struct libnet_ipv4_hdr ip;
    struct libnet_tcp_hdr tcp;
};

struct tcp_pseudo_hdr {
    struct in_addr ip_src, ip_dst;
    uint8_t reserved;
    uint8_t ip_p;
    uint16_t tcp_len;
};

#pragma pack(pop)

char *HTTP_METHODS[] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};

inline void checksum(struct attack_packet *packet) {
    // TCP Checksum
    uint32_t th_sum = 0;
    packet->tcp.th_sum = 0;

    struct tcp_pseudo_hdr pseudo_hdr;
    pseudo_hdr.ip_src = packet->ip.ip_src;
    pseudo_hdr.ip_dst = packet->ip.ip_dst;
    pseudo_hdr.reserved = 0;
    pseudo_hdr.ip_p = packet->ip.ip_p;
    pseudo_hdr.tcp_len = htons(sizeof(struct libnet_tcp_hdr));

    uint16_t *short_view = (uint16_t *) &pseudo_hdr;    
    for (int i = 0; i < sizeof(pseudo_hdr) / sizeof(uint16_t); i++) {
        th_sum += ntohs(short_view[i]);
    }
    short_view = (uint16_t *) &packet->tcp;    
    for (int i = 0; i < packet->tcp.th_off * sizeof(uint32_t) / sizeof(uint16_t); i++) {
        th_sum += ntohs(short_view[i]);
    }
    while (th_sum >> 16)
        th_sum = (th_sum & 0xFFFF) + (th_sum >> 16);
    packet->tcp.th_sum = ~htons(th_sum);

    // IP Checksum
    uint32_t ip_sum = 0;
    packet->ip.ip_sum = 0;
    
    short_view = (uint16_t *) &packet->ip; 
    for (int i = 0; i < packet->ip.ip_hl * sizeof(uint32_t) / sizeof(uint16_t); i++) {
        ip_sum += ntohs(short_view[i]);
    }
    while (ip_sum >> 16)
        ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
    
    packet->ip.ip_sum = ~htons(ip_sum);
}

inline void packet_builder(struct attack_packet *new_packet, struct attack_packet *old_packet, bool forward, uint8_t th_flags) {
    // Ether
    if (forward) {
        memcpy(new_packet->ether.ether_dhost, old_packet->ether.ether_dhost, ETHER_ADDR_LEN);
        memcpy(new_packet->ether.ether_shost, old_packet->ether.ether_shost, ETHER_ADDR_LEN);
    }
    else {
        memcpy(new_packet->ether.ether_dhost, old_packet->ether.ether_shost, ETHER_ADDR_LEN);
        memcpy(new_packet->ether.ether_shost, old_packet->ether.ether_dhost, ETHER_ADDR_LEN);
    }
    new_packet->ether.ether_type = old_packet->ether.ether_type;

    // IPv4
    new_packet->ip.ip_v = old_packet->ip.ip_v;
    new_packet->ip.ip_hl = sizeof(struct libnet_ipv4_hdr) / sizeof(uint32_t);
    new_packet->ip.ip_tos = old_packet->ip.ip_tos;
    new_packet->ip.ip_len = htons(sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));
    new_packet->ip.ip_id = old_packet->ip.ip_id;
    new_packet->ip.ip_off = old_packet->ip.ip_off;
    new_packet->ip.ip_ttl = old_packet->ip.ip_ttl;
    new_packet->ip.ip_p = old_packet->ip.ip_p;
    new_packet->ip.ip_sum = 0;

    if (forward) {
        new_packet->ip.ip_src = old_packet->ip.ip_src;
        new_packet->ip.ip_dst = old_packet->ip.ip_dst;
    }
    else {
        new_packet->ip.ip_src = old_packet->ip.ip_dst;
        new_packet->ip.ip_dst = old_packet->ip.ip_src;
    }

    // TCP
    if (forward) {
        uint32_t old_data_length = ntohs(old_packet->ip.ip_len) - (old_packet->ip.ip_hl * sizeof(uint32_t)) - (old_packet->tcp.th_off * sizeof(uint32_t));
        new_packet->tcp.th_sport = old_packet->tcp.th_sport;
        new_packet->tcp.th_dport = old_packet->tcp.th_dport;
        new_packet->tcp.th_seq = htonl(ntohl(old_packet->tcp.th_seq) + old_data_length);
        new_packet->tcp.th_ack = old_packet->tcp.th_ack;
    }
    else {
        new_packet->tcp.th_sport = old_packet->tcp.th_dport;
        new_packet->tcp.th_dport = old_packet->tcp.th_sport;
        new_packet->tcp.th_ack = new_packet->tcp.th_seq = old_packet->tcp.th_ack;
    }
    new_packet->tcp.th_off = sizeof(struct libnet_tcp_hdr) / sizeof(uint32_t);
    // TODO: Endian check
    new_packet->tcp.th_flags = th_flags;
    new_packet->tcp.th_win = old_packet->tcp.th_win;
    new_packet->tcp.th_sum = 0;
    new_packet->tcp.th_urp = old_packet->tcp.th_urp;

    checksum(new_packet);
}

bool handler(struct attack_packet *new_packet, struct pcap_pkthdr *header, const u_char *packet, char *block_address) {
    const int32_t total_length = header->caplen;
    int32_t parsed_length = 0;
    // DEBUG_PRINT("Total Length: %d\n", total_length);
    if(total_length - parsed_length < sizeof(struct libnet_ethernet_hdr)) 
        return false;
    // Parse ethernet packet
    struct libnet_ethernet_hdr *view_ethernet = (struct libnet_ethernet_hdr *) packet;
    if (ntohs(view_ethernet->ether_type) != ETHERTYPE_IP)
        return false;

    // IPv4 packet size check 1
    parsed_length += sizeof(struct libnet_ethernet_hdr);
    if (total_length - parsed_length < sizeof(struct libnet_ipv4_hdr))
        return false;

    // Parse IPv4 packet
    struct libnet_ipv4_hdr *view_ip = (struct libnet_ipv4_hdr *) (packet + parsed_length);

    if (view_ip->ip_p != IPPROTO_TCP)
        return false;
    
    // IPv4 packet size check 2
    if (total_length - parsed_length < ntohs(view_ip->ip_len) || total_length - parsed_length < ((view_ip->ip_hl) * sizeof(uint32_t)))
        return false;

    parsed_length += (view_ip->ip_hl) * sizeof(uint32_t);
    // TCP packet size check 1
    if (total_length - parsed_length < sizeof(struct libnet_tcp_hdr))
        return false;
    
    struct libnet_tcp_hdr *view_tcp = (struct libnet_tcp_hdr *) (packet + parsed_length);
    if (view_tcp->th_dport != htons(80))
        return false;
    
    if (total_length - parsed_length < (view_tcp->th_off * sizeof(uint32_t))) 
        return false;
    
    parsed_length += view_tcp->th_off * sizeof(uint32_t);
    char *http_req = (char *) (packet + parsed_length);

    bool found = false;
    if(total_length - parsed_length < MIN_HTTP_REQUEST_SIZE)
        return false;
    
    for(int i = 0; i < sizeof(HTTP_METHODS); i++) {
        if(memcmp(http_req, HTTP_METHODS[i], strlen(HTTP_METHODS[i])) == 0) {
            found = true;
            break;
        }
    }
    if(!found)
        return false;
    
    char * pos = http_req;
    size_t length = total_length - parsed_length;
    found = false;
    
    for(int i = 0; i < MAX_ITER; i++) {
        char *end =  (char *)memchr(pos, '\n', length);
        if(end == NULL)
            break;
        if(end - pos < 5)
            break;
        if(strncasecmp((const char *)pos, "Host", 4) == 0) {
            char *cu = pos +4;
            if (*cu == ':') {
                cu++;
                while(*cu == ' ' && cu < end)
                    cu++;
                if(cu < end) {
                    char *address = cu;
                    address[end - cu] = '\x00';
                    size_t idx = end - cu - 1;
                    while(idx != 0 && (address[idx] == ' ' || address[idx] == '\n' || address[idx] == '\r'))
                        idx--;
                    address[idx + 1] = '\x00';
                    if (strncmp(block_address, address, strlen(block_address)) == 0) {
                        printf("Block: %s\n", address);
                        memcpy(&new_packet->ether, view_ethernet, sizeof(new_packet->ether));
                        memcpy(&new_packet->ip, view_ip, sizeof(new_packet->ip));
                        memcpy(&new_packet->tcp, view_tcp, sizeof(new_packet->tcp));
                        return true;
                    }
                }
            }
        }
        length -= end - pos + 1;
        pos = end + 1;
    }
    return false;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s [Interface] [Host]\n", argv[0]);
        printf("Sample: %s enp0s5 test.gilgil.net\n", argv[0]);
        return 1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    ASSERT(handle != NULL, errbuf);

    while (true) {
        struct pcap_pkthdr *header;
        struct attack_packet parsed_packet;
        struct attack_packet new_packet;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        if(handler(&parsed_packet, header, packet, argv[2])) {
            packet_builder(&new_packet, &parsed_packet, true, TH_RST | TH_ACK);
            pcap_inject(handle, &new_packet, sizeof(new_packet));
            packet_builder(&new_packet, &parsed_packet, false, TH_FIN | TH_ACK);
            pcap_inject(handle, &new_packet, sizeof(new_packet));
        }
    }

    return 0;
}