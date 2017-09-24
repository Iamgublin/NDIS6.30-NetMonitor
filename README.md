NDIS6.30-NetMonitor
=============
主要内容
---------------
1. [NDIS 6.30](https://github.com/Iamgublin/C-and-assemble/tree/master/NDIS%206.30)：一个基于NDIS 6.30的数据包过滤函数库,支持数据包过滤分析以及自定义数据包API（尚未文档化），包括基于NDIS 6.30核心代码(MY NDIS 6.0)，数据分析(RawPacketAnalysis)，以及驱动控制的API（NdisCoreApi）。ConsoleTest为控制台形式的示例程序。`NDIS 6.30的驱动只能够在win8和以上的操作系统运行！`</br>

从左到右分别为：源地址，目的地址，包大小，协议类型，详细信息
![效果图](https://github.com/Iamgublin/NDIS6.30-NetMonitor/blob/master/NDIS%206.30/效果图.png)

2017年4月17日更新：设计了GUI界面
![效果图](https://github.com/Iamgublin/NDIS6.30-NetMonitor/blob/master/NDIS%206.30/GUl效果图.png)


2017年4月30日更新：支持内网扫描与ARP攻击
![效果图](https://github.com/Iamgublin/NDIS6.30-NetMonitor/blob/master/NDIS%206.30/内网扫描与攻击.png)

2017年5月25日：修复了IP扫描BUG


2017年9月24日：修改了PacketInfo的结构，与底层的结构统一了，同时修复了一个驱动bug