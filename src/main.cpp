#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "pcap.h"
#include "spdlog/fmt/bundled/core.h"
#include "spdlog/spdlog.h"
#include "spdlog/fmt/fmt.h"
#include "spdlog/fmt/bundled/color.h"

void print_eth_header(const ethhdr* eth) {
	fmt::print("\n");
	fmt::print(fg(fmt::terminal_color::yellow), "Ethernet Header:\n");
	fmt::print(fg(fmt::terminal_color::yellow), "   |-Destination Address : {:x}-{:x}-{:x}-{:x}-{:x}-{:x} \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fmt::print(fg(fmt::terminal_color::yellow), "   |-Source Address      : {:x}-{:x}-{:x}-{:x}-{:x}-{:x} \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fmt::print(fg(fmt::terminal_color::yellow), "   |-Protocol            : {} \n",(unsigned short)eth->h_proto);
}

void print_ip_header(const iphdr* iph) {
	sockaddr_in source; 
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	sockaddr_in dest;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	fmt::print("\n");
	fmt::print(fg(fmt::terminal_color::yellow), "IP Header\n");
	fmt::print(fg(fmt::terminal_color::yellow), "   |-IP Version        : {}\n",(unsigned int)iph->version);
	fmt::print(fg(fmt::terminal_color::yellow), "   |-IP Header Length  : {} DWORDS or {} Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fmt::print(fg(fmt::terminal_color::yellow), "   |-Type Of Service   : {}\n",(unsigned int)iph->tos);
	fmt::print(fg(fmt::terminal_color::yellow), "   |-IP Total Length   : {}  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fmt::print(fg(fmt::terminal_color::yellow), "   |-Identification    : {}\n",ntohs(iph->id));
	fmt::print(fg(fmt::terminal_color::yellow), "   |-TTL               : {}\n",(unsigned int)iph->ttl);
	fmt::print(fg(fmt::terminal_color::yellow), "   |-Protocol          : {}\n",(unsigned int)iph->protocol);
	fmt::print(fg(fmt::terminal_color::yellow), "   |-Checksum          : {}\n",ntohs(iph->check));
	fmt::print(fg(fmt::terminal_color::yellow), "   |-Source IP         : {}\n" , inet_ntoa(source.sin_addr) );
	fmt::print(fg(fmt::terminal_color::yellow), "   |-Destination IP    : {}\n" , inet_ntoa(dest.sin_addr) );
}

void print_icmp_header(const icmphdr* icmph) {
	fmt::print("\n\n***********************ICMP Packet*************************\n");	
	fmt::print("\n");
	fmt::print(fg(fmt::terminal_color::green), "ICMP Header\n");
	fmt::print(fg(fmt::terminal_color::green), "   |-Type : {}",(unsigned int)(icmph->type));
	if((unsigned int)(icmph->type) == 11) {
		fmt::print("  (TTL Expired)\n");
	} else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY) {
		fmt::print("  (ICMP Echo Reply)\n");
	} else {
		fmt::print("\n");
	}
	fmt::print(fg(fmt::terminal_color::green), "   |-Code : {}\n",(unsigned int)(icmph->code));
	fmt::print(fg(fmt::terminal_color::green), "   |-Checksum : {}\n",ntohs(icmph->checksum));
	fmt::print("\n");
};

int main(int argc, char** argv) {
	char error_buffer[PCAP_ERRBUF_SIZE];
	int res = 0;

	pcap_t* device_handle = nullptr;
	pcap_if_t* devices_list = nullptr;

	res = pcap_findalldevs(&devices_list, error_buffer);
	if(res == PCAP_ERROR) {
		spdlog::error("Can't find all devices: {} \nerror code: {}", error_buffer, res);
		return 1;
	}

	pcap_if_t* iter = devices_list;
	while(iter != nullptr) {
		fmt::print("Device: {} \n", iter[0].name);
		iter = iter->next;
	}

	char* device_name = devices_list[0].name;

	bpf_u_int32 netmask;
	bpf_u_int32 srcip;

	res = pcap_lookupnet(devices_list[0].name, &srcip, &netmask, error_buffer);
	if(res == PCAP_ERROR) {
		spdlog::error("Can't get src ip or net mask: {}\n error code: {}", error_buffer, res);
		return 1;
	}

	device_handle = pcap_open_live(device_name, BUFSIZ, 1, 1000, error_buffer);
	if(device_handle == NULL) {
		spdlog::error("Can't open {}", error_buffer);
		return 1;
	}

	bpf_program bpf;
	res = pcap_compile(device_handle, &bpf, argv[1], 0, netmask);
	if(res == PCAP_ERROR) {
		spdlog::error("Can't compile filter: {}\n error code: {}", pcap_geterr(device_handle), res);
		spdlog::info("Filter: {}", argv[1]);
		return 1;
	}

	res = pcap_setfilter(device_handle, &bpf);
	if(res == PCAP_ERROR) {
		spdlog::error("Can't set filter: {}\n error code: {}", pcap_geterr(device_handle), res);
		spdlog::info("Filter: {}", *argv);
		return 1;
	}
	
	int linktype;
	int linkhddr_len;

	// Determine the datalink layer type.
	linktype = pcap_datalink(device_handle);
	if (linktype == PCAP_ERROR) {
		spdlog::error("Datalink error: {}\n error code: {}", pcap_geterr(device_handle), res);
		return 1;
	}

	// Set the datalink layer header size.
	switch (linktype) {
	case DLT_NULL:
		linkhddr_len = 4;
		break;
	
	case DLT_EN10MB:
		linkhddr_len = 14;
		break;
	
	case DLT_SLIP:
	case DLT_PPP:
		linkhddr_len = 24;
		break;
	
	default:
		spdlog::error("Unsuported datalink type");
		return 1;
	};

	const u_char* data_buffer;
	pcap_pkthdr* header;

	while(true) {
		res = pcap_next_ex(device_handle, &header, &data_buffer);
		if(res == PCAP_ERROR) {
			spdlog::error("Can't retrive the next packet: {}", pcap_geterr(device_handle));
			return 1;
		}

		fmt::print("\n=======================================================");

		int size = header->len;

		ethhdr *eth = (ethhdr *)data_buffer;
		print_eth_header(eth);

		iphdr *iph = (iphdr*)(data_buffer + linkhddr_len);
		u_int iphddr_len = iph->ihl * 4;
		print_ip_header(iph);
		
		switch (iph->protocol) {
			case 1: { 
				//ICMP Protocol
				icmphdr *icmph = (icmphdr *)(data_buffer + iphddr_len  + linkhddr_len);
				print_icmp_header(icmph);
				break;
			}
			
			case 2:  //IGMP Protocol
				break;
			
			case 6:  //TCP Protocol
				break;
			
			case 17: //UDP Protocol
				break;
			
			default: //Some Other Protocol like ARP etc.
				break;
		}
	}
}


