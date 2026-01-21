#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

struct node_data { int p; char* pr; char* st; };
struct node_data results_db[5000]; 
int total_found = 0;
int max_p = 0;
int global_flag = 1;

unsigned short checksum_func(unsigned short *ptr, int nbytes) {
    long s = 0;
    while(nbytes > 1) { s += *ptr++; nbytes -= 2; }
    if(nbytes == 1) s += *(unsigned char*)ptr;
    s = (s >> 16) + (s & 0xffff);
    s += (s >> 16);
    return (unsigned short)~s;
}

struct p_hdr {
    u_int32_t s; u_int32_t d;
    u_int8_t z; u_int8_t p;
    u_int16_t l;
};

void p_bar(int n, int m) {
    float r = (float)n / m;
    int k = 30;
    printf("\r[%d/%d] [", n, m);
    for(int i=0; i<k; i++) (i < r*k) ? printf("=") : printf("-");
    printf("] %d%%", (int)(r*100));
    fflush(stdout);
}

void* sniffer_loop(void* arg) {
    char *net_dev = (char*)arg;
    char err_buf[256];
    pcap_t* handle = pcap_open_live(net_dev, 1500, 1, 10, err_buf);
    struct pcap_pkthdr h;
    const u_char* p;

    while (global_flag) {
        p = pcap_next(handle, &h);
        if (!p) continue;
        struct ip* iph = (struct ip*)(p + 14);
        if (iph->ip_p == 6) {
            struct tcphdr* th = (struct tcphdr*)(p + 14 + (iph->ip_hl * 4));
            if ((th->th_flags & 0x12) == 0x12) {
                results_db[total_found].p = ntohs(th->th_sport);
                results_db[total_found].pr = "tcp";
                results_db[total_found].st = "open";
                total_found++;
                printf("\n[!] found open: %d\n", ntohs(th->th_sport));
            }
        }
    }
    return NULL;
}

void send_raw(int s, char* t_ip, int p, uint32_t s_ip) {
    char packet[1024];
    struct iphdr *iph = (struct iphdr*) packet;
    struct tcphdr *tcph = (struct tcphdr*) (packet + sizeof(struct iphdr));
    struct sockaddr_in addr;
    struct p_hdr ph;

    memset(packet, 0, 1024);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(p);
    addr.sin_addr.s_addr = inet_addr(t_ip);

    iph->ihl = 5; iph->version = 4;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->ttl = 64; iph->protocol = 6;
    iph->saddr = s_ip;
    iph->daddr = addr.sin_addr.s_addr;

    tcph->source = htons(40000 + (rand()%5000));
    tcph->dest = htons(p);
    tcph->doff = 5; tcph->syn = 1;
    tcph->window = htons(1024); tcph->check = 0;

    ph.s = iph->saddr; ph.d = iph->daddr; ph.z = 0;
    ph.p = 6; ph.l = htons(20);
    
    char *tmp = malloc(32);
    memcpy(tmp, &ph, 12);
    memcpy(tmp + 12, tcph, 20);
    tcph->check = checksum_func((unsigned short*)tmp, 32);
    free(tmp);
    
    sendto(s, packet, 40, 0, (struct sockaddr*)&addr, 16);
}

int main(int argc, char** argv) {
    if(argc < 4) {
        printf("usage: %s <target> <ports> <iface>\n", argv[0]);
        exit(0);
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, argv[3], IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    uint32_t my_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    close(fd);

    printf("[*] local ip: %s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    int s = socket(2, 3, 6);
    int o = 1;
    setsockopt(s, 0, 3, &o, 4);
    
    pthread_t t1;
    pthread_create(&t1, NULL, sniffer_loop, argv[3]);
    sleep(1);

    max_p = atoi(argv[2]);
    for(int i=1; i<=max_p; i++) {
        send_raw(s, argv[1], i, my_ip);
        if (i % 10 == 0) p_bar(i, max_p);
        usleep(1500); 
    }

    global_flag = 0;
    printf("\n\n--- results ---\n");
    for(int j=0; j<total_found; j++) {
        printf("port %d is open\n", results_db[j].p);
    }
    return 0;
}