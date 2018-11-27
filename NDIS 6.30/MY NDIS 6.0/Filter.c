#include"Filter.h"
#include "Packetcpy.h"
_Use_decl_annotations_
NDIS_STATUS FilterNetPnPEvent(
	_In_ NDIS_HANDLE                 FilterModuleContext,
	_In_ PNET_PNP_EVENT_NOTIFICATION NetPnPEvent
)
{
	/*DbgBreakPoint();*/
	NDIS_STATUS sta;
	PFILTER_CONTEXT Context = FilterModuleContext;
	DbgPrint("NetEvent:0x%x\n", NetPnPEvent->NetPnPEvent.NetEvent);
	if (NetPnPEvent->NetPnPEvent.NetEvent == NetEventRestart)
	{
		PNDIS_PROTOCOL_RESTART_PARAMETERS para = (PNDIS_PROTOCOL_RESTART_PARAMETERS)NetPnPEvent->NetPnPEvent.Buffer;
		para;
		DbgPrint("Ready to runing\n");
	}
	sta = NdisFNetPnPEvent(Context->FilterHandle, NetPnPEvent);
	return sta;
}

_Use_decl_annotations_
VOID FilterReturnNetBufferLists(                               //����С�˿ڷ���Ľ���NBL��ʹ��Ȩ����С�˿ڲ��ͷ�
	_In_ NDIS_HANDLE      FilterModuleContext,
	_In_ PNET_BUFFER_LIST NetBufferLists,
	_In_ ULONG            ReturnFlags
)
{
	/*DbgBreakPoint();*/
	PFILTER_CONTEXT context = FilterModuleContext;
	if (NdisGetPoolFromNetBufferList(NetBufferLists) != context->NetBufferPool)    //��Э��� С�˿ڲ����ģ�dispatch����Ϣ
	{
		NDIS_SET_RETURN_FLAG(ReturnFlags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
		NdisFReturnNetBufferLists(context->FilterHandle, NetBufferLists, ReturnFlags);
	}
}

//Note  NdisFReturnNetBufferLists should not be called for NBLs indicated with 
//NDIS_RECEIVE_FLAGS_RESOURCES flag set in a corresponding FilterReceiveNetBufferLists call.
//Such NBLs are returned to NDIS synchronously by returning from the FilterReceiveNetBufferLists routine.
_Use_decl_annotations_
VOID FilterReceiveNetBufferLists(
	_In_ NDIS_HANDLE      FilterModuleContext,
	_In_ PNET_BUFFER_LIST NetBufferLists,
	_In_ NDIS_PORT_NUMBER PortNumber,
	_In_ ULONG            NumberOfNetBufferLists,
	_In_ ULONG            ReceiveFlags
)
{
	/*DbgBreakPoint();*/
	PFILTER_CONTEXT context = FilterModuleContext;
	if (!context->IsRunning)
	{
		ULONG               ReturnFlags;
		ReturnFlags = 0;
		if (NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags))
		{
			NDIS_SET_RETURN_FLAG(ReturnFlags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
		}
		//��NDIS_RECEIVE_FLAGS_RESOURCES��־ʱ return ���ͷ�,����Ҫ����NdisFReturnNetBufferLists
		if (!NDIS_TEST_RECEIVE_CANNOT_PEND(ReceiveFlags))   
		{
			NdisFReturnNetBufferLists(context->FilterHandle, NetBufferLists, ReturnFlags);
		}
		return;
	}
	if (context->IsFiltering)
	{
		ZlzCopyNdlToBufferAndInsert(context, NetBufferLists,FALSE);
	}
	NdisFIndicateReceiveNetBufferLists(context->FilterHandle, NetBufferLists, PortNumber, NumberOfNetBufferLists, ReceiveFlags);
}

_Use_decl_annotations_
VOID FilterCancelSendNetBufferLists(
	_In_ NDIS_HANDLE FilterModuleContext,
	_In_ PVOID       CancelId
)
{
	/*DbgBreakPoint();*/
	PFILTER_CONTEXT context = FilterModuleContext;
	NdisFCancelSendNetBufferLists(context->FilterHandle, CancelId);
}

//If an overlying driver initiated the send request, the filter driver should call the NdisFSendNetBufferListsComplete function to complete the send request.
//If the filter driver originated the send request, FilterSendNetBufferListsComplete can either release the NET_BUFFER_LIST structures and associated data or prepare them for reuse in a subsequent call to NdisFSendNetBufferLists.
//Note  A filter driver should keep track of send requests that it initiates and make sure that it does not call NdisFSendNetBufferListsComplete when NDIS calls FilterSendNetBufferListsComplete for such requests.
_Use_decl_annotations_
VOID FilterSendNetBufferListsComplete(
	_In_ NDIS_HANDLE      FilterModuleContext,
	_In_ PNET_BUFFER_LIST NetBufferLists,
	_In_ ULONG            SendCompleteFlags
)
{
	/*DbgBreakPoint();*/
	//�����Filter���͵İ�����Ӧ�õ���NdisFSendNetBufferListsComplete��ֱ���ͷ���Դ
	PFILTER_CONTEXT context = FilterModuleContext;
	if (NetBufferLists->Context)
	{
        NDIS_HANDLE hPoolHandle = NdisGetPoolFromNetBufferList(NetBufferLists);
		if (NET_BUFFER_LIST_CONTEXT_DATA_SIZE(NetBufferLists) == sizeof(MY_NET_Buffer_Context))
		{
			PMY_NET_Buffer_Context NetContext = (PMY_NET_Buffer_Context)NET_BUFFER_LIST_CONTEXT_DATA_START(NetBufferLists);
            if (hPoolHandle == context->NetBufferPool ||
                strcmp(NetContext->Magic, "zlz") == 0)
            {
                NdisFreeMdl(NetContext->Mdl);
                NdisFreeMemoryWithTag(NetContext->VirAddress, 'u');
                NdisFreeNetBufferList(NetBufferLists);
                return;
            }

		}
	}
	NdisFSendNetBufferListsComplete(context->FilterHandle, NetBufferLists, SendCompleteFlags);
}

//�Զ��巢�Ͱ��� NET_BUFFER_LIST->sourcehandle����Ϊcontext->FilterHandle
_Use_decl_annotations_
VOID FilterSendNetBufferLists(
	_In_ NDIS_HANDLE      FilterModuleContext,
	_In_ PNET_BUFFER_LIST NetBufferLists,
	_In_ NDIS_PORT_NUMBER PortNumber,
	_In_ ULONG            SendFlags
)
{
	/*DbgBreakPoint();*/
	PFILTER_CONTEXT context = FilterModuleContext;
	if (!context->IsRunning)
	{
		ULONG SendCompleteFlags = 0;
		NDIS_SET_SEND_COMPLETE_FLAG(SendCompleteFlags, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
		PNET_BUFFER_LIST temp = NetBufferLists;
		do                                           //�������а�ͷ״̬ΪNDIS_STATUS_PAUSED
		{
			NBL_SET_FLAG(temp, NDIS_STATUS_PAUSED);
			temp = NET_BUFFER_LIST_NEXT_NBL(temp);
		} while (temp != NULL);
		NdisFSendNetBufferListsComplete(context->FilterHandle, NetBufferLists, SendCompleteFlags);
		return;
	}
	if (context->IsFiltering)
	{
		ZlzCopyNdlToBufferAndInsert(context, NetBufferLists, TRUE);
	}
	NdisFSendNetBufferLists(context->FilterHandle, NetBufferLists, PortNumber, SendFlags);
}

_Use_decl_annotations_
NDIS_STATUS FilterPause(
	_In_ NDIS_HANDLE                   FilterModuleContext,
	_In_ PNDIS_FILTER_PAUSE_PARAMETERS FilterPauseParameters
)
{
	/*DbgBreakPoint();*/
	
	PFILTER_CONTEXT context = FilterModuleContext;
	context->IsRunning = FALSE;
	return STATUS_SUCCESS;
}

_Use_decl_annotations_
NDIS_STATUS FilterRestart(
	_In_ NDIS_HANDLE                     FilterModuleContext,
	_In_ PNDIS_FILTER_RESTART_PARAMETERS FilterRestartParameters
)
{
	/*DbgBreakPoint();*/
	PFILTER_CONTEXT context = FilterModuleContext;
	context->IsRunning = TRUE;
	return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID FilterDetach(
	_In_ NDIS_HANDLE FilterModuleContext
)
{
	/*DbgBreakPoint();*/
	PFILTER_CONTEXT context = FilterModuleContext;
	ZlzCleanList(context);                                          //�������
	context->IsFiltering = FALSE;                                    
	context->IsRunning = FALSE;                                     //���ù���״̬
	NdisFreeNetBufferListPool(context->NetBufferPool);				//��հ���ռ�õ�ϵͳ�ڴ�
	Global.context[context->FliterIndex] = NULL;					//��������Ϊ��
	ExFreePool(context);											//���������Ŀռ�
	Global.contextnum--;
}

_Use_decl_annotations_
NDIS_STATUS FilterAttach(
	_In_ NDIS_HANDLE                    NdisFilterHandle,
	_In_ NDIS_HANDLE                    FilterDriverContext,
	_In_ PNDIS_FILTER_ATTACH_PARAMETERS AttachParameters         //������ʼ��������������ʱ�������
)
{
	/*DbgBreakPoint();*/
	NDIS_STATUS sta;
	NDIS_FILTER_ATTRIBUTES FilterAttributes;
#ifndef DBG
	DbgPrint("BaseMiniportName:%wZ\n", AttachParameters->BaseMiniportName);
	DbgPrint("BaseMiniportInstanceName:%wZ\n", AttachParameters->BaseMiniportInstanceName);
#endif

	//��ʼ��context��
	PFILTER_CONTEXT context = (PFILTER_CONTEXT)ExAllocatePool(NonPagedPool, sizeof(FILTER_CONTEXT));
	if (context == NULL)
	{
		KeBugCheckEx(NO_EXCEPTION_HANDLING_SUPPORT, 0, 0, 0, 1);
	}
	memmove(context->magic, "zlzndis", sizeof(context->magic));

	//��ʼ������
	NET_BUFFER_LIST_POOL_PARAMETERS para;
	para.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
	para.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
	para.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
	para.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
	para.fAllocateNetBuffer = TRUE;
	para.ContextSize = 0;
	para.DataSize = 0;
	para.PoolTag = 0;
	NDIS_HANDLE PoolHandle = NdisAllocateNetBufferListPool(NdisFilterHandle, &para);
	if (PoolHandle == NULL)
	{
		KeBugCheckEx(NO_EXCEPTION_HANDLING_SUPPORT, 0, 0, 0, 0);
	}
	
	//����������
	NdisZeroMemory(&FilterAttributes, sizeof(NDIS_FILTER_ATTRIBUTES));
	FilterAttributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
	FilterAttributes.Header.Size = sizeof(NDIS_FILTER_ATTRIBUTES);
	FilterAttributes.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
	FilterAttributes.Flags = 0;
	sta = NdisFSetAttributes(NdisFilterHandle,
		context,
		&FilterAttributes);

	//����context�ĸ������ֵĳ�ʼֵ
	//�����豸��Ϣ
	KeInitializeSpinLock(&context->NetBufferListLock);
	RtlInitUnicodeString(&context->DevInfo.DevName, AttachParameters->BaseMiniportInstanceName->Buffer);
	RtlInitUnicodeString(&context->DevInfo.DevPathName, AttachParameters->BaseMiniportName->Buffer);
	RtlCopyMemory(context->DevInfo.MacAddress,
		AttachParameters->CurrentMacAddress,
		sizeof(AttachParameters->CurrentMacAddress));
	ZlzGetNetworkAdapterInformation(context);
	//��ʼ������
	InitializeListHead(&context->PacketRecvList);
	context->NetBufferPool = PoolHandle;
	context->FilterHandle = NdisFilterHandle;
	context->CurrentRecvNum = 0;
	context->IsFiltering = FALSE;               //������޸�
    for (int contextinsert = 0; contextinsert < NETCARD_DEFAULT_MAX; contextinsert++)
    {
        if (Global.context[contextinsert] == NULL)
        {
            Global.context[contextinsert] = context;     //Ѱ�ҿ�λ�ò���
            context->FliterIndex = contextinsert;
            break;
        }
        if (contextinsert == NETCARD_DEFAULT_MAX - 1)
        {
            return STATUS_UNSUCCESSFUL;     //����20������
        }
    }
	Global.contextnum++;
	return STATUS_SUCCESS;
}

_Use_decl_annotations_                  //NdisSetOptionalHandlers
NDIS_STATUS FilterSetOptions(
	_In_ NDIS_HANDLE NdisDriverHandle,
	_In_ NDIS_HANDLE DriverContext
)
{
	/*DbgBreakPoint();*/
	return STATUS_SUCCESS;
}

_Use_decl_annotations_               //����ָ�����豸�ĺ����ҹ�(NdisFRestartFilter���ú����)
NDIS_STATUS FilterSetModuleOptions(
	_In_ NDIS_HANDLE FilterModuleContext
)
{
	/*DbgBreakPoint();*/
	return STATUS_SUCCESS;
}
_Use_decl_annotations_
VOID FilterStatus(
	_In_ NDIS_HANDLE             FilterModuleContext,
	_In_ PNDIS_STATUS_INDICATION StatusIndication
)
{
	PFILTER_CONTEXT Context = (PFILTER_CONTEXT)FilterModuleContext;
	NdisFIndicateStatus(Context->FilterHandle, StatusIndication);
}

