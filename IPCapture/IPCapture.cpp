#include<stdio.h>
#include<WinSock2.h>
#include<pcap.h>
#include<string.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wpcap.lib")

#define _CRT_SECURE_NO_WARNINGS

//����4�ֽڵ�ip��ַ�ṹ��
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct ethernet_header
{
	u_char ether_dhost[6];  /*Ŀ����̫��ַ*/
	u_char ether_shost[6];  /*Դ��̫����ַ*/
	u_short ether_type;      /*��̫������*/
}ethernet_header;


/* ����ip�ײ��ṹ */
typedef struct ip_header
{
	u_char	ver_ihl;		// �汾 Version (4 bits) + IP�ײ����� Header Length(4 bits)
	u_char	tos;			// �������� Type of service 
	u_short tlen;			// IP���ܳ��� Total length 
	u_short identification; // ��ʶ Identification
	u_short flags_fo;		// ��� Flags (3 bits) + Ƭƫ��Fragment offset (13 bits)
	u_char	ttl;			// ����ʱ�� Time to live
	u_char	protocol;			// Э�� Protocol
	u_short hchecksum;			// �ײ������ Header checksum
	ip_address	saddr;		// ԴIP��ַ Source address
	ip_address	daddr;		// Ŀ��IP��ַ Destination address
}ip_header;

static int packet_num = 0;
FILE* file = NULL;

//IP���ݱ�����
void ip_packet_parse(FILE* file, const u_char* pkt_data) {
	ip_header* ipHeader;
	/* ���IP���ݰ�ͷ����λ�� */
	ipHeader = (ip_header*)(pkt_data + 14); //14����̫��֡���ײ�����
	u_short flag;
	char protocol_name[10];
	//��ȡ���flag�ֶ�ֵ
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
	fprintf(file, "\t\t\t==========����� %d ��IP���ݰ�==========\n\n", ++packet_num);
	fprintf(file, "IP�汾:\t\tIPv%d\n", (ipHeader->ver_ihl >> 4));
	fprintf(file, "IPЭ���ײ�����:\t%d\n", (ipHeader->ver_ihl & 0x0f) * 4);
	fprintf(file, "��������:\t%d\n", ipHeader->tos);
	fprintf(file, "�ܳ���:\t\t%d\n", ntohs(ipHeader->tlen));
	fprintf(file, "��ʶ:\t\t%d\n", ntohs(ipHeader->identification));
	fprintf(file, "���:\t\tMF=%d��DF=%d\n", flag >> 1, flag & 0x0001);
	fprintf(file, "Ƭƫ��:\t\t%d\n", (ipHeader->flags_fo & 0x1fff) * 8);
	fprintf(file, "����ʱ��:\t%d\n", ipHeader->ttl);
	fprintf(file, "�ײ������:\t%d\n", ntohs(ipHeader->hchecksum));
	fprintf(file, "ԴIP��ַ:\t%d.%d.%d.%d\n", ipHeader->saddr.byte1, ipHeader->saddr.byte2, ipHeader->saddr.byte3, ipHeader->saddr.byte4);
	fprintf(file, "Ŀ��IP��ַ:\t%d.%d.%d.%d\n", ipHeader->daddr.byte1, ipHeader->daddr.byte2, ipHeader->daddr.byte3, ipHeader->daddr.byte4);
	fprintf(file, "Э��:\t\t%d  (%s)\n\n", ipHeader->protocol, protocol_name);
}


void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	ethernet_header* ethernet_protocol;
	u_short ethernet_type;

	//�����̫��֡
	ethernet_protocol = (struct ethernet_header*) pkt_data;
	//��ȡ��̫������
	ethernet_type = ntohs(ethernet_protocol->ether_type);
	//printf("%04x\n", ethernet_type);
	switch (ethernet_type)
	{
	case 0x0800:
		/*����ϲ���IPv4ipЭ��,�͵��÷���ipЭ��ĺ�����ip�����з���*/
		ip_packet_parse(stdout, pkt_data);
		packet_num--;
		ip_packet_parse(file, pkt_data);   //д���ļ�
		break;
	default:
		printf("\n������IPЭ�����ݰ���\n");
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

	/* ��������������б� */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	printf("\t\t\t==========����IP���ݰ�==========\n\n");
	/*��ӡ�б� */
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

	printf("\n��������ӿڱ�� (1-%d)����", i);
	scanf("%d", &inum);

	/*�ж��������Ƿ�Ϸ� */
	if (inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");

		/* �ͷ�����������*/
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ����ָ��������������*/
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/*����������������*/
	if ((adhandle = pcap_open_live(d->name,	// �豸��
		65536,			//Ҫ��׽�����ݰ��Ĳ��� 
							// 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		1,					// ����ģʽ
		1000,			// ��ȡ��ʱʱ��
		errbuf			// ���󻺳��
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* �ͷ������豸�б� */
	pcap_freealldevs(alldevs);

	int num = -1;
	while (1) {
		printf("\n������Ҫ��������ݰ��������˳���������-1��һֱ��������0����");
		scanf("%d", &num);
		if (num == -1)
			break;
		printf("\n���ڼ��� %s...\n", d->description);
		/* ��ʼ�������� */
		pcap_loop(adhandle, num, packet_handler, NULL);
	}
	fclose(file);
	return 0;
}