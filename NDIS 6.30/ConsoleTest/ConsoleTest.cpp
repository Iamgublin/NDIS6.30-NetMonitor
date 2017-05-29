// ConsoleTest.cpp : 定义控制台应用程序的入口点。
//
#include "stdafx.h"
#include"..\NdisCoreApi\NdisCoreApi.h"
#include"..\RawPacketAnalysis\RawPacketAnalysis.h"
#pragma comment(lib,"..\\lib\\RawPacketAnalysis.lib")
#pragma comment(lib,"..\\lib\\NdisCoreApi.lib")
#include<locale.h>
HANDLE hF = NULL;
char pro[14][8] = {"UNKNOWN","ARP","RARP","TCP","UDP","ICMP","IGMP","HTTP","NAT","DHCP","IPv6","QICQ","NTP","SSDPv4"};
BOOL WINAPI HandleConsole(DWORD dwCtrlType)
{
	switch (dwCtrlType)
	{
	case CTRL_CLOSE_EVENT:
		Net_StopFilter(hF, NULL);
		return TRUE;
	default:
		return FALSE;
		break;
	}
}
void SetConsole()
{
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	COORD size;
	size.X = 2000;
	size.Y = 2000;
	SetConsoleScreenBufferSize(hOut, size);     //设置控制台大小
	SetConsoleCtrlHandler(HandleConsole, TRUE); //设置控制台退出回调
}
int main()
{
	SetConsole();
	setlocale(LC_ALL, "chs");
	hF = Net_OpenFilter();
	printf("%p\n", hF);
	PIO_Packet Output = (PIO_Packet)malloc(sizeof(IO_Packet));
	PacketInfo Info = { 0 };
	Net_StartFilter(hF, NULL);          //NULL表示打开所有过滤器
	Net_ShowAdapter(hF, Output);
	printf("0x%x\n", GetLastError());
	printf("Adapter Num:%d\n", Output->Packet.ShowAdapter.Num);
	for (int i = 0; i < Output->Packet.ShowAdapter.Num; i++)
	{
		wprintf(TEXT("Adapter Name%d:%s\n"),i, Output->Packet.ShowAdapter.AdapterInfo[i].DevName);
		wprintf(TEXT("Adapter Path%d:%s\n"),i, Output->Packet.ShowAdapter.AdapterInfo[i].DevPathName);
		wprintf(TEXT("Is Filtering:%s\n"), Output->Packet.ShowAdapter.AdapterInfo[i].isFiltering ? TEXT("TRUE") : TEXT("FALSE"));
		PUCHAR Mac = Output->Packet.ShowAdapter.AdapterInfo[i].MacAddress;
		printf("Mac Address:%02x-%02x-%02x-%02x-%02x-%02x\n", Mac[0], Mac[1], Mac[2], Mac[3], Mac[4], Mac[5]);
	}
	int a = 0;
	while (1)
	{
		Sleep(100);
		if (Net_GetRawPacket(hF, Output, a))
		{
			Info = { 0 };
			AnalysePacket(Output, &Info);
			if (Info.Type == INFO_IPv6 || Info.Type == INFO_UNKNOWN)
			{
				if (Info.Type == INFO_UNKNOWN)
				{
					printf("Unknown protocol:%02x%02x\n", Info.RawPacket[20],Info.RawPacket[21]);
				}
				else
				{
					printf("IPv6\n");
				}
				continue;
			}
			if (Info.Type == INFO_ARP)
			{
				UCHAR* saddr = Info.protocol.Arp.saddr;
				UCHAR* daddr = Info.protocol.Arp.daddr;
				if ((Info.Mac.dst[0] == 0xff) || (Info.Mac.dst[1] == 0xff))
				{
					printf("%03d.%03d.%03d.%03d\tBOARDCAST\t%4d\t%5s\t", saddr[0], saddr[1], saddr[2], saddr[3],Info.Size, pro[Info.Type]);
				}
				else
				{
					printf("%03d.%03d.%03d.%03d\t%03d.%03d.%03d.%03d\t%4d\t%5s\t", saddr[0], saddr[1], saddr[2], saddr[3], daddr[0], daddr[1], daddr[2], daddr[3], Info.Size, pro[Info.Type]);
				}
				if (Tranverse16(Info.protocol.Arp.opcode) == ARP_REQUEST)
				{
					printf("who has ip %03d.%03d.%03d.%03d? tell %03d.%03d.%03d.%03d\n", Info.protocol.Arp.daddr[0],
						Info.protocol.Arp.daddr[1], Info.protocol.Arp.daddr[2], Info.protocol.Arp.daddr[3], Info.protocol.Arp.saddr[0],
						Info.protocol.Arp.saddr[1], Info.protocol.Arp.saddr[2], Info.protocol.Arp.saddr[3]);
				}
				else if (Tranverse16(Info.protocol.Arp.opcode) == ARP_REPLY)
				{
					printf("%03d.%03d.%03d.%03d is in mac %02x-%02x-%02x-%02x-%02x-%02x\n", Info.protocol.Arp.saddr[0], Info.protocol.Arp.saddr[1],
						Info.protocol.Arp.saddr[2], Info.protocol.Arp.saddr[3], Info.protocol.Arp.smac[0], Info.protocol.Arp.smac[1],
						Info.protocol.Arp.smac[2], Info.protocol.Arp.smac[3], Info.protocol.Arp.smac[4], Info.protocol.Arp.smac[5]);
				}
			}
			else
			{
				UCHAR* saddr = Info.protocol.Ip.ipSource;
				UCHAR* daddr = Info.protocol.Ip.ipDestination;
				printf("%03d.%03d.%03d.%03d\t%03d.%03d.%03d.%03d\t%4d\t%5s\t", saddr[0], saddr[1], saddr[2], saddr[3], daddr[0], daddr[1], daddr[2], daddr[3], Info.Size, pro[Info.Type]);
				if (Info.Type == INFO_TCP)
				{
					printf("window:%5d port:%d->%d ack:%d syn:%d fin:%d dataoffset:%d\n", Tranverse16(Info.protocol1.Tcp.windows), Tranverse16(Info.protocol1.Tcp.sourcePort), Tranverse16(Info.protocol1.Tcp.destinationPort), TCP_TEST_ACK(Info.protocol1.Tcp.flagsOffset),
					TCP_TEST_SYN(Info.protocol1.Tcp.flagsOffset), TCP_TEST_FIN(Info.protocol1.Tcp.flagsOffset),(TCP_GETDATAOFFSET(Info.protocol1.Tcp.flagsOffset))*4);
				}
				else if (Info.Type == INFO_ICMP)
				{
					printf("type:%02d code:%02d checksum:%d\n", Info.protocol1.Icmp.icmp_type, Info.protocol1.Icmp.icmp_code, Info.protocol1.Icmp.icmp_checksum);
				}
				else if (Info.Type == INFO_HTTP)
				{
					/*char http[60] = { 0 };
					int len = sizeof(MAC) + (Info.protocol.Ip.iphVerLen & 0x0f) * 4 + (TCP_GETDATAOFFSET(Info.protocol1.Tcp.flagsOffset) * 4)+1;
					memcpy(http, Info.RawPacket + len, sizeof(http)-1);
					for (int i = 0; i < 60; i++)
					{
						printf("%c", http[i]);
					}*/
					printf("\n");
				}
				else if (Info.Type == INFO_UDP)
				{
					printf("port:%d->%d\n", Tranverse16(Info.protocol1.Udp.sourcePort), Tranverse16(Info.protocol1.Udp.destinationPort));
				}
				else if (Info.Type == INFO_SSDPv4)
				{
					int len = sizeof(MAC) + (Info.protocol.Ip.iphVerLen & 0x0f) * 4 + sizeof(UDPPacket);
					for (int i = len; i < len + 30; i++)
					{
						if (Info.RawPacket[i] == '\n')
						{
							printf("\t");
							continue;
						}
						printf("%c",Info.RawPacket[i]);
					}
					printf("\n");
				}
				else
				{
					printf("\n");
				}
			}
		}
	}
	Sleep(INFINITE);
	return 0;
}

