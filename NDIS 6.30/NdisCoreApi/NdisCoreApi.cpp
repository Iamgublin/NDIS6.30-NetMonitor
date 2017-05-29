// NdisCoreApi.cpp : 定义 DLL 应用程序的导出函数。
//
//注：所有的参数校检都在内核中进行
#include "NdisCoreApi.h"
#include"define.h"
NDISCOREAPI_API
HANDLE
WINAPI
Net_OpenFilter(
	void
)
{
	return CreateFile(SYM_NAME, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, NULL);
}

NDISCOREAPI_API
int
WINAPI
Net_ShowAdapter(
	_In_ HANDLE FilterHandle,
	_Out_ PIO_Packet Packet
)
{
	DWORD ByteRet = 0;
	return DeviceIoControl(FilterHandle, IOCTL_SHOWADAPTER, NULL, NULL, Packet, sizeof(IO_Packet), &ByteRet, NULL);
}
NDISCOREAPI_API
int
WINAPI
Net_GetRawPacket(
	_In_ HANDLE FilterHandle,
	_Out_ PIO_Packet Packet,
	_In_ int AdapterIndex
)
{
	IO_Packet PacketInput = { 0 };
	PacketInput.Packet.Net_Packet_InPut.Reserved = AdapterIndex;
	DWORD ByteRet = 0;
	return DeviceIoControl(FilterHandle, IOCTL_GETRAWDATA, &PacketInput, sizeof(IO_Packet), Packet, sizeof(IO_Packet), &ByteRet, NULL);
}

NDISCOREAPI_API
int
WINAPI
Net_StartFilter(
	_In_ HANDLE FilterHandle,
	_In_opt_ int *StartFileterIndex
	)
{
	DWORD ByteRet = 0;
	IO_Packet PacketInput = { 0 };

	if (StartFileterIndex==NULL)
	{
		PacketInput.Packet.Net_StartStop_Filter.Reserved = START_ALL;
	}
	else
	{
		PacketInput.Packet.Net_StartStop_Filter.Reserved = *StartFileterIndex;
	}	
	return DeviceIoControl(FilterHandle, IOCTL_STARTFILTER, &PacketInput, sizeof(IO_Packet), NULL, NULL, &ByteRet, NULL);
}

NDISCOREAPI_API
int
WINAPI
Net_StopFilter(
	_In_ HANDLE FilterHandle,
	_In_opt_ int *StopFileterIndex
)
{
	DWORD ByteRet = 0;
	IO_Packet PacketInput = { 0 };
	if (StopFileterIndex == NULL)
	{
		PacketInput.Packet.Net_StartStop_Filter.Reserved = STOP_ALL;
	}
	else
	{
		PacketInput.Packet.Net_StartStop_Filter.Reserved = *StopFileterIndex;
	}
	return DeviceIoControl(FilterHandle, IOCTL_STOPFILTER, &PacketInput, sizeof(IO_Packet), NULL, NULL, &ByteRet, NULL);
}

NDISCOREAPI_API
int
WINAPI
Net_SendRawPacket(
	_In_ HANDLE FilterHandle,
	_In_ RawPacket *RawPacketToSend,
	_In_ int size,
	_In_ int AdapterIndex
)
{
	DWORD ByteRet = 0;
	RawPacketToSend->Reserved = AdapterIndex;
	RawPacketToSend->Reserved1 = size;
	return DeviceIoControl(FilterHandle, IOCTL_SENDPACKET, RawPacketToSend, sizeof(RawPacket), NULL, NULL, &ByteRet, NULL);
}