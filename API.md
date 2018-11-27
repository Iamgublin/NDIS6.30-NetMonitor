#NdisCoreApi(NdisCoreApi.dll)

##HeaderFile:NdisCoreApi.h

##Lib:NdisCoreApi.lib

```
NDISCOREAPI_API 
int 
WINAPI 
Net_ShowAdapter(
	_In_ HANDLE FilterHandle,
	_Out_ PIO_Packet Packet
);
```
Show The NetWork Adapter In This Computer
*input: 
FilterHandle:FilterObject Handle Returned By Net_OpenFilter
Packet:PIO_Packet struct 
*output:success 1  failed 0


```
NDISCOREAPI_API 
HANDLE 
WINAPI 
Net_OpenFilter(
	void
);
```
Return The FilterObject Handle
*input:NO
*output:FilterObject Handle 

```
NDISCOREAPI_API 
int 
WINAPI 
Net_GetRawPacket(
	_In_ HANDLE FilterHandle,
	_Out_ PIO_Packet Packet,
	_In_ int AdapterIndex
);
```
Get a Packet Store In The NDIS Driver
*input:
FilterHandle:FilterObject Handle Returned By Net_OpenFilter
Packet: PIO_Packet struct
AdapterIndex: The Adapter Get the Packet
*output:success 1  failed 0

```
NDISCOREAPI_API
int
WINAPI
Net_StartFilter(
	_In_ HANDLE FilterHandle,
	_In_opt_ int *StartFileterIndex
);
```
Start The Adapter to Filter the Network
*input:
FilterHandle:FilterObject Handle Returned By Net_OpenFilter
StartFileterIndex:The Filter Index You want to Start if is NULL, will start all
*output:success 1  failed 0

```
NDISCOREAPI_API
int
WINAPI
Net_StopFilter(
	_In_ HANDLE FilterHandle,
	_In_opt_ int *StopFileterIndex
);
```
Stop The Adapter to Filter the Network
*input:
FilterHandle:FilterObject Handle Returned By Net_OpenFilter
StopFileterIndex:The Filter Index You want to Stop if is NULL, will stop all
*output:success 1  failed 0

```
NDISCOREAPI_API
int
WINAPI
Net_SendRawPacket(
	_In_ HANDLE FilterHandle,
	_In_ RawPacket *RawPacketToSend,
	_In_ int SendSize,
	_In_ int AdapterIndex
);
```
Send Packet Use Ndis,Not across the WFP And TDI
*input:
FilterHandle:FilterObject Handle Returned By Net_OpenFilter
RawPacketToSend:RawPacket struct
SendSize:the Packet Length
AdapterIndex:The Adapter Index To Start
*output:success 1  failed 0

```
NDISCOREAPI_API
int
WINAPI
Net_SetPacketPoolMax(
    _In_ HANDLE FilterHandle,
    _In_ int PoolMax
);
```
Set the NDIS Driver Packet Pool Max
*input:
FilterHandle:FilterObject Handle Returned By Net_OpenFilter
PoolMax:RawPacket struct
SendSize:the Pool Max Length
*output:success 1  failed 0


#RawPacketAnalysis(RawPacketAnalysis.dll)

##HeaderFile:RawPacketAnalysis.h

##Lib:RawPacketAnalysis.lib

```
RAWPACKETANALYSIS_API
int
AnalysePacket(
	_In_ PIO_Packet Packet,
	_Inout_ PPacketInfo Info
);
```
Analyse The RawPacket Return By  Net_GetRawPacket
*input:
Packet:The Packet want to Analyse
Info:The Analysis Info
*output:success 1  failed 0