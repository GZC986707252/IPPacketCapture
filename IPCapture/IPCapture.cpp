#include<stdio.h>
#include<WinSock2.h>
#include<pcap.h>
#include<string.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wpcap.lib")

#define _CRT_SECURE_NO_WARNINGS

//定义4字节的ip地址结构体
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct ethernet_header
{
	u_char ether_dhost[6];  /*目的以太地址*/
	u_char ether_shost[6];  /*源以太网地址*/
	u_short ether_type;      /*以太网类型*/
}ethernet_header;


/* 定义ip首部结构 */
typedef struct ip_header
{
	u_char	ver_ihl;		// 版本 Version (4 bits) + IP首部长度 Header Length(4 bits)
	u_char	tos;			// 服务类型 Type of service 
	u_short tlen;			// IP包总长度 Total length 
	u_short identification; // 标识 Identification
	u_short flags_fo;		// 标记 Flags (3 bits) + 片偏移Fragment offset (13 bits)
	u_char	ttl;			// 生存时间 Time to live
	u_char	protocol;			// 协议 Protocol
	u_short hchecksum;			// 首部检验和 Header checksum
	ip_address	saddr;		// 源IP地址 Source address
	ip_address	daddr;		// 目的IP地址 Destination address
}ip_header;

static int packet_num = 0;
FILE* file = NULL;

//IP数据报解析
void ip_packet_parse(FILE* file, const u_char* pkt_data) {
	ip_header* ipHeader;
	/* 获得IP数据包头部的位置 */
	ipHeader = (ip_header*)(pkt_data + 14); //14是以太网帧的首部长度
	u_short flag;
	char protocol_name[10];
	//获取标记flag字段值
	flag = ntohs(ipHeader->flags_fo) >> 13;
	switch (ipHeader->protocol)
	{
	case 1:
		strcpy(protocol_name, "ICMP");
		break;
	case 2:
		strcpy(protocol_name, "IGMP");
		break;
	case 4:
		strcpy(protocol_name, "IP");
		break;
	case 6:
		strcpy(protocol_name, "TCP");
		break;
	case 8:
		strcpy(protocol_name, "EGP");
		break;
	case 9:
		strcpy(protocol_name, "IGP");
		break;
	case 17:
		strcpy(protocol_name, "UDP");
		break;
	case 41:
		strcpy(protocol_name, "IPv6");
		break;
	case 50:
		strcpy(protocol_name, "ESP");
		break;
	case 89:
		strcpy(protocol_name, "OSPF");
		break;
	default:
		strcpy(protocol_name, "Unknown");
		break;
	}
	fprintf(file, "\t\t\t==========捕获第 %d 个IP数据包==========\n\n", ++packet_num);
	fprintf(file, "IP版本:\t\tIPv%d\n", (ipHeader->ver_ihl >> 4));
	fprintf(file, "IP协议首部长度:\t%d\n", (ipHeader->ver_ihl & 0x0f) * 4);
	fprintf(file, "服务类型:\t%d\n", ipHeader->tos);
	fprintf(file, "总长度:\t\t%d\n", ntohs(ipHeader->tlen));
	fprintf(file, "标识:\t\t%d\n", ntohs(ipHeader->identification));
	fprintf(file, "标记:\t\tMF=%d，DF=%d\n", flag >> 1, flag & 0x0001);
	fprintf(file, "片偏移:\t\t%d\n", (ipHeader->flags_fo & 0x1fff) * 8);
	fprintf(file, "生存时间:\t%d\n", ipHeader->ttl);
	fprintf(file, "首部检验和:\t%d\n", ntohs(ipHeader->hchecksum));
	fprintf(file, "源IP地址:\t%d.%d.%d.%d\n", ipHeader->saddr.byte1, ipHeader->saddr.byte2, ipHeader->saddr.byte3, ipHeader->saddr.byte4);
	fprintf(file, "目的IP地址:\t%d.%d.%d.%d\n", ipHeader->daddr.byte1, ipHeader->daddr.byte2, ipHeader->daddr.byte3, ipHeader->daddr.byte4);
	fprintf(file, "协议:\t\t%d  (%s)\n\n", ipHeader->protocol, protocol_name);
}


void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	ethernet_header* ethernet_protocol;
	u_short ethernet_type;

	//获得以太网帧
	ethernet_protocol = (struct ethernet_header*) pkt_data;
	//获取以太网类型
	ethernet_type = ntohs(ethernet_protocol->ether_type);
	//printf("%04x\n", ethernet_type);
	switch (ethernet_type)
	{
	case 0x0800:
		/*如果上层是IPv4ip协议,就调用分析ip协议的函数对ip包进行分析*/
		ip_packet_parse(stdout, pkt_data);
		packet_num--;
		ip_packet_parse(file, pkt_data);   //写入文件
		break;
	default:
		printf("\n丢弃非IP协议数据包！\n");
		break;
	}
}

int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	file = fopen("ip_packet_log.txt", "a+");

	/* 获得网络适配器列表 */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	printf("\t\t\t==========解析IP数据包==========\n\n");
	/*打印列表 */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("\n【请输入接口编号 (1-%d)】：", i);
	scanf("%d", &inum);

	/*判断输入编号是否合法 */
	if (inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");

		/* 释放网络适配器*/
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳到指定的网络适配器*/
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/*打开网络适配器监听*/
	if ((adhandle = pcap_open_live(d->name,	// 设备名
		65536,			//要捕捉的数据包的部分 
							// 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		1,					// 混杂模式
		1000,			// 读取超时时间
		errbuf			// 错误缓冲池
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 释放所有设备列表 */
	pcap_freealldevs(alldevs);

	int num = -1;
	while (1) {
		printf("\n请输入要捕获的数据包个数【退出捕获输入-1，一直监听输入0】：");
		scanf("%d", &num);
		if (num == -1)
			break;
		printf("\n正在监听 %s...\n", d->description);
		/* 开始捕获数据 */
		pcap_loop(adhandle, num, packet_handler, NULL);
	}
	fclose(file);
	return 0;
}