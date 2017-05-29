#pragma once
#include<stdio.h>
#include"..\RawPacketAnalysis\Networks_User.h"
#define SYM_NAME L"\\\\.\\Zlz Ndis6.30 Filter SymbolLink"
#define PATH_MAX 255
#define IO_BUF 2000

//Net_StartStop_Filter->Reserved
#define START_ALL 99
#define STOP_ALL 99

///IO_PACKET->type
#define PACKET_TYPE_ADAPTERINFO 1
#define PACKET_TYPE_NETPACKET 2


#define IOCTL_SHOWADAPTER (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x911,METHOD_BUFFERED,FILE_WRITE_DATA|FILE_READ_DATA)
#define IOCTL_GETRAWDATA (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x912,METHOD_BUFFERED,FILE_WRITE_DATA|FILE_READ_DATA)
#define IOCTL_STARTFILTER (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x913,METHOD_BUFFERED,FILE_WRITE_DATA|FILE_READ_DATA)
#define IOCTL_STOPFILTER (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x914,METHOD_BUFFERED,FILE_WRITE_DATA|FILE_READ_DATA)
#define IOCTL_SENDPACKET (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x915,METHOD_BUFFERED,FILE_WRITE_DATA|FILE_READ_DATA)

typedef struct _AdapterInfo
{
	BOOLEAN isFiltering;
	WCHAR DevPathName[PATH_MAX];
	WCHAR DevName[PATH_MAX];
	UCHAR MacAddress[32];
}AdapterInfo, *PAdapterInfo;
typedef struct _IO_Packet
{
	int Type;
	union
	{
		struct
		{
			int Num;
			AdapterInfo AdapterInfo[20];
		}ShowAdapter;
		struct
		{
			int Size;
			UCHAR Buffer[IO_BUF];         //MTU<=1500 
			BOOLEAN IsSendPacket;
		}Net_Packet_Output;
		struct
		{
			int Reserved;
		}Net_Packet_InPut;
		struct
		{
			int Reserved;
		}Net_StartStop_Filter;
		unsigned u;
	}Packet;
}IO_Packet, *PIO_Packet;

#pragma pack(push,1)
typedef struct _RawPacket
{
	union
	{
		struct
		{
			MAC Mac;      //数据链路层
			union
			{
				IPPacket Ip;
				ARPPacket Arp;
			}protocol;    //网络层
			union
			{
				TCPPacket Tcp;
				UDPPacket Udp;
				ICMPPacket Icmp;
				IGMPPacket Igmp;
			}protocol1;  //传输层
			union
			{
				QICQPacket Qicq;
				DHCPPacket Dhcp;
			}protocol2;
		}Osi;
		UCHAR RawPacket[2000];     //原始的包数据（MTU<=1500）
	};
	int Reserved;
	int Reserved1;
}RawPacket, *PRawPacket;
#pragma pack(pop)