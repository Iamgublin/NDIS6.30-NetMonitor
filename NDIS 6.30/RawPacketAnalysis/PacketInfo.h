#pragma once
#include<Windows.h>
#include"Networks_User.h"
//用到的宏
#define Tranverse16(X)   ((((UINT16)(X) & 0xff00) >> 8) |(((UINT16)(X) & 0x00ff) << 8))    //用于USHORT大端小端转化
#define SET_INFO_TYPE(A,B) (A->Type=B)

//PacketInfo->type
#define INFO_UNKNOWN 0
#define INFO_ARP     1
#define INFO_RARP    2
#define INFO_TCP     3
#define INFO_UDP     4
#define INFO_ICMP    5
#define INFO_IGMP    6
#define INFO_HTTP    7
#define INFO_NAT     8
#define INFO_DHCP    9
#define INFO_IPv6    10
#define INFO_QICQ    11
#define INFO_NTP     12
#define INFO_SSDPv4  13 
#define INFO_DNS     14

//ARP->opcode
#define ARP_REQUEST  1
#define ARP_REPLY    2

//DHCP->messageType
#define DHCP_REQUEST 1
#define DHCP_REPLY   2  

//TCP->flagsOffset  X为flagsOffset
#define TCP_TEST_FIN(X)       Tranverse16(X) & 0x1
#define TCP_TEST_SYN(X)       Tranverse16(X) >> 1 & 0x1
#define TCP_TEST_RST(X)		  Tranverse16(X) >> 2 & 0x1
#define TCP_TEST_PSH(X)		  Tranverse16(X) >> 3 & 0x1
#define TCP_TEST_ACK(X)		  Tranverse16(X) >> 4 & 0x1
#define TCP_TEST_URG(X)		  Tranverse16(X) >> 5 & 0x1
#define TCP_GETDATAOFFSET(X)  Tranverse16(X) >> 12

//DNS->queryorres
#define DNS_REQUEST  0
#define DNS_RESPONSE 1

//DNS->opcode
#define DNS_QUERY_NORMAL  0 //标准查询
#define DNS_QUERT_REVERSE 1 //反转查询
#define DNS_QUERT_STATUS  2 //服务器状态查询

//DNS->responsecode
#define DNS_STATUS_SUCCESS            0   //没有错误条件
#define DNS_STATUS_FORMATERROR        1   //请求格式有误，服务器无法解析请求
#define DNS_STATUS_SERVERERROR        2   //服务器出错
#define DNS_STATUS_NAMEERROR          3   //只在权威DNS服务器的响应中有意义，表示请求中的域名不存在
#define DNS_STATUS_NOTIMPLEMENTED     4   //服务器不支持该请求类型
#define DNS_STATUS_REFUSED            5   //服务器拒绝执行请求操作

typedef struct _PacketInfo
{
    int Type;     //数据包类型 （INFO_XXX）
    int Size;     //数据包大小
    BOOLEAN IsSendPacket;
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
            DNSPacket  Dns;
        }protocol2;
    }Osi;
    UCHAR RawPacket[2000];     //原始的包数据（MTU<=1500）
}PacketInfo, *PPacketInfo;