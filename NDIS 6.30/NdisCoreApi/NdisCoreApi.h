/********************************************************************************
*                                                                               *
* NdisCoreApi.h -- ApiSet Contract for ZlzNdis Kernel-Mode Driver               *
*                                                                               *
* Copyright (c) Arch-Vile. All rights reserved.                     *
*                                                                               *
********************************************************************************/
#ifdef _MSC_VER
#pragma once
#endif // _MSC_VER

#ifndef _APICORENDIS_
#define _APICORENDIS_
#include<Windows.h>
#include"define.h"
#include"..\RawPacketAnalysis\PacketInfo.h"
#ifdef NDISCOREAPI_EXPORTS
#define NDISCOREAPI_API __declspec(dllexport)
#else
#define NDISCOREAPI_API __declspec(dllimport)
#endif


NDISCOREAPI_API 
int 
WINAPI 
Net_ShowAdapter(
	_In_ HANDLE FilterHandle,
	_Out_ PIO_Packet Packet
);

NDISCOREAPI_API 
HANDLE 
WINAPI 
Net_OpenFilter(
	void
);

NDISCOREAPI_API 
int 
WINAPI 
Net_GetRawPacket(
	_In_ HANDLE FilterHandle,
	_Out_ PIO_Packet Packet,
	_In_ int AdapterIndex
);

NDISCOREAPI_API
int
WINAPI
Net_StartFilter(
	_In_ HANDLE FilterHandle,
	_In_opt_ int *StartFileterIndex
);

NDISCOREAPI_API
int
WINAPI
Net_StopFilter(
	_In_ HANDLE FilterHandle,
	_In_opt_ int *StopFileterIndex
);

NDISCOREAPI_API
int
WINAPI
Net_SendRawPacket(
	_In_ HANDLE FilterHandle,
	_In_ RawPacket *RawPacketToSend,
	_In_ int SendSize,
	_In_ int AdapterIndex
);
#endif //_APICORENDIS_