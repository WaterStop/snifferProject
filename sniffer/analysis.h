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

// ���ذ������������豸��Ϣ������ṹ��
pcap_if_t* GetAllAdapter() {
	pcap_if_t* alldevs = new pcap_if_t();
	char* errbuf = new char[256];
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}
	return alldevs;
}
// Cstring ת����const char*
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



CString filterName;// �Ӵ��ڵĹ����ַ���
// ��ȡһ������֡
DWORD WINAPI setFilterRule(LPVOID param) { // adhandle�����alldevsHead�豸����
	pcap_if_t* devsHead = (pcap_if_t*)param;
	char* errbuf = new char[256];
	pcap_t* adhandle;// ���
	// AdapterName = alldevs->name;
	// ���豸��������̽�Ự
	if ((adhandle = pcap_open(devsHead->name,          // �豸��
		65536,            // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
		1000,             // ��ȡ��ʱʱ��
		NULL,             // Զ�̻�����֤
		errbuf            // ���󻺳��
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", devsHead->name);
		// �����ͷ��豸�б�   
		pcap_freealldevs(devsHead);
		return -1;

	}

	// �����˹�����룬�������漯�ɵ����ݰ������еĵͼ��ֽ���
	pcap_if_t* d = devsHead;
	u_int netmask;
	if (d->addresses != NULL)
		/* ��ýӿڵ�һ����ַ������ */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* ����ӿ�û�е�ַ����ô���Ǽ���һ��C������� */
		netmask = 0xffffff;
	struct bpf_program fp;//��ű�����bpf��Ӧ�ù�������ʱ��Ҫʹ�����ָ��

	
	//****************CStringת��Ϊchar*
	if (pcap_compile(adhandle, &fp, CStrToChar(filterName), 1, netmask) < 0)// �����������ǹ��˹������һ��������ָ������������������룬����Ҫʱ��д0
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		// �ͷ��豸�б� 
		pcap_freealldevs(devsHead);
		return -1;
	}

	// ��һ�����������������ץ���Ự��������
	if (pcap_setfilter(adhandle, &fp) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		// �ͷ��豸�б� 
		pcap_freealldevs(devsHead);
		return -1;
	}
	pcap_loop(adhandle, 0, packet_handler, NULL);
	//�ͷ��豸
	pcap_freealldevs(devsHead);

	return 0;
}

/* �ص����������յ�ÿһ�����ݰ�ʱ�ᱻlibpcap������ */
// ��ȡһ����Ϣ���Ž���Ϣ������
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	// ��ȡ����ܵ�ָ��
	CWnd* mainWnd = theApp.GetMainWnd();
	CsnifferDlg* dlg = (CsnifferDlg*)mainWnd;
	static HWND hDlgHandle = dlg->GetSafeHwnd();

	pcap_pkthdr* header2 = new pcap_pkthdr;
	u_char* pkt_data2 = new u_char[header->len];

	memcpy(header2, header, sizeof(pcap_pkthdr));
	memcpy(pkt_data2, pkt_data, header->len);


	//PostMessage ֻ�ǰ���Ϣ������У��������������Ƿ������أ�Ȼ����������ִ�� 
	//�� SendMessage ����ȴ�������������Ϣ��ŷ��أ�����ִ��
	::PostMessage(hDlgHandle, M_MESSAGEWINPCAP, (WPARAM)header2, (LPARAM)pkt_data2);
}



#endif // !1
