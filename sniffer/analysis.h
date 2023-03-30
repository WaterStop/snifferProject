#ifndef _ANALYSIS_H
#define _ANALYSIS_H
#include <pcap.h>
#include "protocol.h"
#include "snifferDlg.h"
#include "RuleFilter.h"
#include<atlconv.h>
using namespace std;
#pragma warning(disable:4996)
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void GetDataInfo(CEdit& edit, packet* pkt);

// 返回包含所有网卡设备信息的链表结构体
pcap_if_t* GetAllAdapter() {
	pcap_if_t* alldevs = new pcap_if_t();
	char* errbuf = new char[256];
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}
	return alldevs;
}
// Cstring 转化成const char*
const char* CStrToChar(CString strSrc)
{
#ifdef UNICODE
	DWORD dwNum = WideCharToMultiByte(CP_OEMCP, NULL, strSrc.GetBuffer(0), -1, NULL, 0, NULL, FALSE);
	char* psText;
	psText = new char[dwNum];
	if (!psText)
		delete[]psText;
	WideCharToMultiByte(CP_OEMCP, NULL, strSrc.GetBuffer(0), -1, psText, dwNum, NULL, FALSE);
	return (const char*)psText;
#else
	return (LPCTSRT)strSrc;
#endif
}



CString filterName;// 子窗口的规则字符串
// 获取一个数据帧
DWORD WINAPI setFilterRule(LPVOID param) { // adhandle句柄，alldevsHead设备链表
	pcap_if_t* devsHead = (pcap_if_t*)param;
	char* errbuf = new char[256];
	pcap_t* adhandle;// 句柄
	// AdapterName = alldevs->name;
	// 打开设备，建立嗅探会话
	if ((adhandle = pcap_open(devsHead->name,          // 设备名
		65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", devsHead->name);
		// 出错释放设备列表   
		pcap_freealldevs(devsHead);
		return -1;

	}

	// 将过滤规则编译，过滤引擎集成到数据包驱动中的低级字节码
	pcap_if_t* d = devsHead;
	u_int netmask;
	if (d->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;
	struct bpf_program fp;//存放编译后的bpf，应用过来规则时需要使用这个指针

	
	//****************CString转化为char*
	if (pcap_compile(adhandle, &fp, CStrToChar(filterName), 1, netmask) < 0)// 第三个参数是过滤规则，最后一个参数是指定本地网络的网络掩码，不需要时可写0
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		// 释放设备列表 
		pcap_freealldevs(devsHead);
		return -1;
	}

	// 把一个过滤器与核心驱动抓包会话关联起来
	if (pcap_setfilter(adhandle, &fp) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		// 释放设备列表 
		pcap_freealldevs(devsHead);
		return -1;
	}
	pcap_loop(adhandle, 0, packet_handler, NULL);
	//释放设备
	pcap_freealldevs(devsHead);

	return 0;
}

/* 回调函数，当收到每一个数据包时会被libpcap所调用 */
// 获取一个消息并放进消息队列中
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	// 获取主框架的指针
	CWnd* mainWnd = theApp.GetMainWnd();
	CsnifferDlg* dlg = (CsnifferDlg*)mainWnd;
	static HWND hDlgHandle = dlg->GetSafeHwnd();

	pcap_pkthdr* header2 = new pcap_pkthdr;
	u_char* pkt_data2 = new u_char[header->len];

	memcpy(header2, header, sizeof(pcap_pkthdr));
	memcpy(pkt_data2, pkt_data, header->len);


	//PostMessage 只是把消息放入队列，不管其他程序是否处理都返回，然后立即返回执行 
	//而 SendMessage 必须等待其他程序处理消息后才返回，继续执行
	::PostMessage(hDlgHandle, M_MESSAGEWINPCAP, (WPARAM)header2, (LPARAM)pkt_data2);
}



#endif // !1
