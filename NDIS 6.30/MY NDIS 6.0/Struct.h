#pragma once
#pragma warning(disable:4201)
#pragma warning(disable:4100)
#define NDIS_WDM
#define NDIS630
#include<wdm.h>
#include<ndis.h>
#include<ntstrsafe.h>
#include"Networks_Kernel.h"

#define Tranverse16(X)   ((((UINT16)(X) & 0xff00) >> 8) |(((UINT16)(X) & 0x00ff) << 8))  //用于USHORT大端小端转化

/*#define RECV_POOL_MAX 300*/
#define PACKET_DATA_MAX 1518
#define FILTER_MAJOR_NDIS_VERSION   NDIS_FILTER_MAJOR_VERSION
#define FILTER_MINOR_NDIS_VERSION   NDIS_FILTER_MINOR_VERSION
#define NETCFGGUID L"{5cbf81bd-5055-47cd-9055-a76b2b4e3697}"
#define SERVICENAME L"ZlzNdisLwf"
#define DEVICE_NAME L"\\Device\\Zlz Ndis6.30 Filter Kernel-Mode Device"
#define REG_NETWORKTCPIPCONFIG_PATH L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\"
#define SYM_NAME L"\\??\\Zlz Ndis6.30 Filter SymbolLink"
#define PATH_MAX 255
#define IO_BUF 2000
#define START_ALL 99
#define STOP_ALL 99

#define IOCTL_SHOWADAPTER (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x911,METHOD_BUFFERED,FILE_WRITE_DATA|FILE_READ_DATA) 
#define IOCTL_GETRAWDATA (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x912,METHOD_BUFFERED,FILE_WRITE_DATA|FILE_READ_DATA) 
#define IOCTL_STARTFILTER (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x913,METHOD_BUFFERED,FILE_WRITE_DATA|FILE_READ_DATA)
#define IOCTL_STOPFILTER (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x914,METHOD_BUFFERED,FILE_WRITE_DATA|FILE_READ_DATA)
#define IOCTL_SENDPACKET (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x915,METHOD_BUFFERED,FILE_WRITE_DATA|FILE_READ_DATA)

#define PACKET_TYPE_ADAPTERINFO 1
#define PACKET_TYPE_NETPACKET 2

PDRIVER_DISPATCH devcon;
typedef struct _AdapterInfo
{
	BOOLEAN isFiltering;
	WCHAR DevPathName[PATH_MAX];
	WCHAR DevName[PATH_MAX];
	UCHAR MacAddress[32];
}AdapterInfo, *PAdapterInfo;
typedef struct _IO_Packet                  //r0 r3 I/O用
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
			int ContextNum;
		}Net_Packet_InPut;
		struct
		{
			int Index;
		}Net_StartStop_Filter;
		unsigned u;
	}Packet;
}IO_Packet,*PIO_Packet;
typedef struct _S_PACKET
{
	LIST_ENTRY PacketList;
	int size;
	int MdlNumber;
	BOOLEAN IsSendPacket;
	PNET_BUFFER_LIST buffer;                    //解链以后的NBL
	PMDL *mdllist;
}S_PACKET, *PS_PACKET;
typedef struct _DEVINCE_INFO
{
	NDIS_STRING DevPathName;                    //设备路径名
	NDIS_STRING DevName;                        //设备名字
	UCHAR MacAddress[32];                       //Mac地址
}DEVICE_INFO,*PDEVINCE_INFO;
typedef struct _FILTER_CONTEXT
{
	char magic[8];
	DEVICE_INFO DevInfo;
	NDIS_HANDLE FilterHandle;                   //过滤设备区别句柄
	NDIS_HANDLE NetBufferPool;                  //包池句柄
	BOOLEAN IsRunning;                          //该过滤器是否处于运行中
	BOOLEAN IsFiltering;                        //该过滤器是否对数据包进行过滤
	int FliterIndex;                            //过滤句柄在GLOBAL.context中的索引数
	int CurrentRecvNum;                         //当前接收链表存在的包数
	LIST_ENTRY PacketRecvList;                  //接收链表
	KSPIN_LOCK NetBufferListLock;               //链表同步访问锁
}FILTER_CONTEXT, *PFILTER_CONTEXT;
typedef struct _GLOBAL
{
	NDIS_HANDLE DriverHandle;          //注册过滤设备后获得的句柄
	int contextnum;                    //绑定设备数
	PFILTER_CONTEXT context[20];       //绑定设备上下文
	PDEVICE_OBJECT FilterDev;          //R3 R0 I/O传输设备
	UNICODE_STRING symname;            //链接符号名
	int RecvPoolMax;                   //包池最大大小
}GLOBAL, *PGLOBAL;
GLOBAL Global;

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
	int AdapterIndex;
	int SendSize;
}RawPacket, *PRawPacket;
#pragma pack(pop)

typedef struct _MY_NET_Buffer_Context
{
	char Magic[5];
	PVOID VirAddress;
	PMDL Mdl;
}MY_NET_Buffer_Context, *PMY_NET_Buffer_Context;