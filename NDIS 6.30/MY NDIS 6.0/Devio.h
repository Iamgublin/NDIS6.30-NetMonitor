#pragma once
/********************************************************************************
*                                                                               *
* devio.h --  Handle zlzndislwf Driver I/O With R3                              *
*                                                                               *
* Copyright Arch-Vile. All rights reserved.                                     *
*                                                                               *
********************************************************************************/
#include"Struct.h"


extern NTSTATUS ZlzRemoveListHead(PFILTER_CONTEXT Context);
extern VOID analysis(PS_PACKET Packet);
extern NTSTATUS ZlzCleanList(PFILTER_CONTEXT Context);

NTSTATUS ZlzSendRawPacket(PRawPacket Packet)
{
	int AdapterIndex = Packet->AdapterIndex;
	NTSTATUS Sta = STATUS_UNSUCCESSFUL;
	PVOID VirAddress = NULL;
	if (Packet->SendSize < 0 || Packet->SendSize>1500)
	{
		return STATUS_UNSUCCESSFUL;
	}
	if (AdapterIndex >= Global.contextnum || AdapterIndex < 0 || Global.context[AdapterIndex]==NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	if (Global.context[AdapterIndex]->IsRunning == FALSE)
	{
		return STATUS_UNSUCCESSFUL;
	}
	Sta = NdisAllocateMemoryWithTag(&VirAddress, Packet->SendSize, 'u');
	if (!NT_SUCCESS(Sta))
	{
		return STATUS_UNSUCCESSFUL;
	}
	RtlCopyMemory(VirAddress, Packet->RawPacket, Packet->SendSize);
	PMDL Mdl = NdisAllocateMdl(Global.context[AdapterIndex]->FilterHandle, VirAddress, Packet->SendSize);
	if (Mdl == NULL)
	{
		NdisFreeMemoryWithTag(VirAddress, 'u');
		return STATUS_UNSUCCESSFUL;
	}

	PNET_BUFFER_LIST NbL = NdisAllocateNetBufferAndNetBufferList(Global.context[AdapterIndex]->NetBufferPool, sizeof(MY_NET_Buffer_Context), 0, Mdl, 0, Packet->SendSize);
	if (NbL == NULL)
	{
		NdisFreeMdl(Mdl);
		NdisFreeMemoryWithTag(VirAddress, 'u');
		return STATUS_UNSUCCESSFUL;
	}
	PMY_NET_Buffer_Context Context = (PMY_NET_Buffer_Context)NET_BUFFER_LIST_CONTEXT_DATA_START(NbL);
	RtlZeroMemory(Context, sizeof(MY_NET_Buffer_Context));
	RtlCopyMemory(Context->Magic, "zlz", sizeof(Context->Magic));
	Context->Mdl = Mdl;
	Context->VirAddress = VirAddress;
	NdisFSendNetBufferLists(Global.context[AdapterIndex]->FilterHandle, NbL, 0, 0);
	return STATUS_SUCCESS;
}
VOID ZlzInitShowAdapterPacket(PIO_Packet IoPacket)
{
	IoPacket->Packet.ShowAdapter.Num = Global.contextnum;
	IoPacket->Type = PACKET_TYPE_ADAPTERINFO;
	for (int i = 0; i < Global.contextnum; i++)
	{
		IoPacket->Packet.ShowAdapter.AdapterInfo[i].isFiltering = Global.context[i]->IsFiltering;
		RtlCopyMemory(IoPacket->Packet.ShowAdapter.AdapterInfo[i].DevName, Global.context[i]->DevInfo.DevName.Buffer, Global.context[i]->DevInfo.DevName.Length);
		RtlCopyMemory(IoPacket->Packet.ShowAdapter.AdapterInfo[i].DevPathName, Global.context[i]->DevInfo.DevPathName.Buffer, Global.context[i]->DevInfo.DevPathName.Length);
		RtlCopyMemory(IoPacket->Packet.ShowAdapter.AdapterInfo[i].MacAddress, Global.context[i]->DevInfo.MacAddress, 32);
	}
}
/*VOID CopyNetBuffer(PIO_Packet Packet)
{
	int offset = 0;
	Packet->Type = PACKET_TYPE_NETPACKET;
	for (int i = 0; i < Global.contextnum; i++)
	{
		if (Global.context[i]->CurrentRecvNum != 0)
		{
			KIRQL irql;
			KeAcquireSpinLock(&Global.context[i]->NetBufferPoolLock, &irql);
			Packet->Packet.Net_Packet.Num = Global.context[i]->CurrentRecvNum;
			for (int a = 0; a < Global.context[i]->CurrentRecvNum; a++)
			{
				int mdlnum = Global.context[i]->PacketRecvPool[a]->MdlNumber;
				for (int temp = 0; temp < mdlnum; temp++)
				{
					PVOID Buf = MmGetSystemAddressForMdlSafe(Global.context[i]->PacketRecvPool[a]->mdllist[temp], IoPriorityNormal);
					int size = MmGetMdlByteCount(Global.context[i]->PacketRecvPool[a]->mdllist[temp]);
					if (offset + size > 2000)
					{
						break;
					}
					RtlCopyMemory(Packet->Packet.Net_Packet.Buffer[0]+offset, Buf, size);
					offset += size;
				}
				offset = 0;
			}
			ZlzCleanPool(Global.context[i]);
			KeReleaseSpinLock(&Global.context[i]->NetBufferPoolLock, irql);
		}
	}
}*/
NTSTATUS CopyNetBuffer(PIO_Packet Packet, int i)
{
	Packet->Type = PACKET_TYPE_NETPACKET;
	if (i >= Global.contextnum || i < 0)
	{
		return STATUS_UNSUCCESSFUL;
	}
	if (Global.context[i] == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	if (Global.context[i]->IsRunning == FALSE)
	{
		return STATUS_UNSUCCESSFUL;
	}
	if (Global.context[i]->CurrentRecvNum != 0)
	{
		KIRQL irql;
		int TotalSize = 0;
		int MdlHasCopied = 0;
		KeAcquireSpinLock(&Global.context[i]->NetBufferListLock, &irql);
		PS_PACKET PacketUsed = (PS_PACKET)Global.context[i]->PacketRecvList.Flink;
		RtlZeroMemory(Packet->Packet.Net_Packet_Output.Buffer, sizeof(Packet->Packet.Net_Packet_Output.Buffer));
		while (MdlHasCopied != PacketUsed->MdlNumber)
		{
			PMDL MdlUsed = NULL;
			MdlUsed = PacketUsed->mdllist[MdlHasCopied];
			PVOID Buf = MmGetSystemAddressForMdlSafe(MdlUsed, IoPriorityNormal);
			if (Buf == NULL)
			{
				return STATUS_UNSUCCESSFUL;
			}
			int size = MmGetMdlByteCount(MdlUsed);
			if (TotalSize + size > IO_BUF)
			{
				DbgPrint("Buf is too small!\n");
				break;
			}
			RtlCopyMemory(&Packet->Packet.Net_Packet_Output.Buffer[TotalSize], Buf, size);
			MdlHasCopied++;
			TotalSize += size;
		}
		/*ULONG DataOff = PacketUsed->buffer->FirstNetBuffer->DataOffset;

		if (DataOff != 0)           //可能NB会有Backfill Space（填充区段）,把该区段丢弃
		{
			if (DataOff == PacketUsed->buffer->FirstNetBuffer->CurrentMdlOffset)
			{
				RtlMoveMemory(Packet->Packet.Net_Packet_Output.Buffer, Packet->Packet.Net_Packet_Output.Buffer + DataOff, TotalSize);   //内存重叠,千万不能用RtlCopyMemory
			}
			else
			{
				RtlMoveMemory(Packet->Packet.Net_Packet_Output.Buffer, Packet->Packet.Net_Packet_Output.Buffer + PacketUsed->buffer->FirstNetBuffer->CurrentMdlOffset, TotalSize);   //内存重叠,千万不能用RtlCopyMemory
			}
		}*/  //NdisAllocateCloneNetBufferList调用后新包会去除填充区段
		Packet->Packet.Net_Packet_Output.IsSendPacket = PacketUsed->IsSendPacket;
		Packet->Packet.Net_Packet_Output.Size = TotalSize;
		ZlzRemoveListHead(Global.context[i]);
		KeReleaseSpinLock(&Global.context[i]->NetBufferListLock, irql);
	}
	else
	{
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}
NTSTATUS ZlzStartFilter(int StartNum)
{
	if (Global.contextnum == 0)
	{
		return STATUS_UNSUCCESSFUL;
	}
	if(StartNum==START_ALL)
	{ 
		for (int i = 0; i < Global.contextnum; i++)
		{
			if (Global.context[i]->IsFiltering == TRUE)
			{
				continue;
			}
			else
			{
				KIRQL irql;
				KeAcquireSpinLock(&Global.context[i]->NetBufferListLock, &irql);
				ZlzCleanList(Global.context[i]);
				KeReleaseSpinLock(&Global.context[i]->NetBufferListLock, irql);
				Global.context[i]->IsFiltering = TRUE;
			}
		}
	}
	else 
	{
		if (StartNum >= Global.contextnum || StartNum < 0)
		{
			return STATUS_UNSUCCESSFUL;
		}
		if (Global.context[StartNum]->IsFiltering == TRUE)
		{
			return STATUS_SUCCESS;
		}
		else
		{
			KIRQL irql;
			KeAcquireSpinLock(&Global.context[StartNum]->NetBufferListLock, &irql);
			ZlzCleanList(Global.context[StartNum]);
			KeReleaseSpinLock(&Global.context[StartNum]->NetBufferListLock, irql);
			Global.context[StartNum]->IsFiltering = TRUE;
		}
	}
	return STATUS_SUCCESS;
}
NTSTATUS ZlzStopFilter(int StopNum)
{
	if (Global.contextnum == 0)
	{
		return STATUS_UNSUCCESSFUL;
	}
	if (StopNum == STOP_ALL)
	{
		for (int i = 0; i < Global.contextnum; i++)
		{
			if (Global.context[i]->IsFiltering == FALSE)
			{
				continue;
			}
			else
			{
				Global.context[i]->IsFiltering = FALSE;
			}
		}
	}
	else 
	{
		if (StopNum >= Global.contextnum || StopNum < 0)
		{
			return STATUS_UNSUCCESSFUL;
		}
		if (Global.context[StopNum]->IsFiltering == FALSE)
		{
			return STATUS_SUCCESS;
		}
		else
		{
			Global.context[StopNum]->IsFiltering = FALSE;
		}
	}
	return STATUS_SUCCESS;
}
NTSTATUS Create(PDEVICE_OBJECT dev, PIRP irp)
{
	return STATUS_SUCCESS;
}
NTSTATUS Close(PDEVICE_OBJECT dev, PIRP irp)
{
	return STATUS_SUCCESS;
}
NTSTATUS CleanUp(PDEVICE_OBJECT dev, PIRP irp)
{
	return STATUS_SUCCESS;
}
NTSTATUS MyDeviceIoControl(PDEVICE_OBJECT dev, PIRP irp)
{
	if (dev == Global.FilterDev)
	{
		PIO_Packet Packet = (PIO_Packet)ExAllocatePool(NonPagedPool, sizeof(IO_Packet));
		if (Packet == NULL)
		{
			return STATUS_UNSUCCESSFUL;
		}
		NdisZeroMemory(Packet, sizeof(IO_Packet));
		PIO_STACK_LOCATION sa = IoGetCurrentIrpStackLocation(irp);
		PVOID buffer = irp->AssociatedIrp.SystemBuffer;
		switch (sa->Parameters.DeviceIoControl.IoControlCode)
		{
		case IOCTL_SHOWADAPTER:
			irp->IoStatus.Information = sizeof(IO_Packet);
			irp->IoStatus.Status = STATUS_SUCCESS;
			ZlzInitShowAdapterPacket(Packet);
			RtlCopyMemory(buffer, Packet, sizeof(IO_Packet));
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			break;
		case IOCTL_GETRAWDATA:
			irp->IoStatus.Information = sizeof(IO_Packet);
			irp->IoStatus.Status = STATUS_SUCCESS;
			if (sa->Parameters.DeviceIoControl.InputBufferLength)
			{
				PIO_Packet PacketInput = irp->AssociatedIrp.SystemBuffer;
				int ContextNum = PacketInput->Packet.Net_Packet_InPut.ContextNum;
				irp->IoStatus.Status = CopyNetBuffer(Packet, ContextNum);
				RtlCopyMemory(buffer, Packet, sizeof(IO_Packet));
			}
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			break;
		case IOCTL_STARTFILTER:
			irp->IoStatus.Information = 0;
			if (sa->Parameters.DeviceIoControl.InputBufferLength)
			{
				PIO_Packet PacketInput = irp->AssociatedIrp.SystemBuffer;
				int StartNum = PacketInput->Packet.Net_StartStop_Filter.Index;
				irp->IoStatus.Status = ZlzStartFilter(StartNum);
			}
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			break;
		case IOCTL_STOPFILTER:
			irp->IoStatus.Information = 0;
			if (sa->Parameters.DeviceIoControl.InputBufferLength)
			{
				PIO_Packet PacketInput = (PIO_Packet)irp->AssociatedIrp.SystemBuffer;
				int StopNum = PacketInput->Packet.Net_StartStop_Filter.Index;
				irp->IoStatus.Status = ZlzStopFilter(StopNum);
			}
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			break;
		case IOCTL_SENDPACKET:
			if (sa->Parameters.DeviceIoControl.InputBufferLength)
			{
				PRawPacket RawPack = (PRawPacket)irp->AssociatedIrp.SystemBuffer;
				irp->IoStatus.Status = ZlzSendRawPacket(RawPack);
			}
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			break;
		default:
			break;
		}
		ExFreePool(Packet);
		return irp->IoStatus.Status;
	}
	else
	{
		return devcon(dev, irp);
	}
}
