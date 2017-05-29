/********************************************************************************
*                                                                               *
* RawPacketAnalysis.h --  Raw Packet Analyse                                    *
*                                                                               *
* Copyright (c) Arch-Vile. All rights reserved.                     *
*                                                                               *
********************************************************************************/
#pragma once

#ifndef _APIRAWANA_
#define _APIRAWANA_
#include<Windows.h>
#include"../NdisCoreApi/define.h"
#include"PacketInfo.h"
#ifdef RAWPACKETANALYSIS_EXPORTS
#define RAWPACKETANALYSIS_API __declspec(dllexport)
#else
#define RAWPACKETANALYSIS_API __declspec(dllimport)
#endif

RAWPACKETANALYSIS_API
int
AnalysePacket(
	_In_ PIO_Packet Packet,
	_Inout_ PPacketInfo Info
);
#endif //_APIRAWANA_
