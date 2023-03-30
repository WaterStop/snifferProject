#include "StdAfx.h"
#include "MyWinPcap.h"
#include <afxwin.h>


// file process
MyWinPcap::MyWinPcap(void) :m_iCurNo(0)
{
	//使用GetModuleFileName获取应用程序路径
	TCHAR szModuleName[MAX_PATH];
	::GetModuleFileName(NULL, szModuleName, MAX_PATH);
	CString strDir = szModuleName;
	strDir = strDir.Left(strDir.ReverseFind(TEXT('\\'))); // Left() -> Extracts the leftmost nCount characters from this CStringT object and returns a copy of the extracted substring

	CString fileData;
	fileData.Format(TEXT("%s\\packet.dmp"), strDir);
	m_pfileData = new CFile(fileData, CFile::modeCreate | CFile::modeReadWrite); //create or write data(packet) file

	CString fileIndex;
	fileIndex.Format(TEXT("%s\\packet.idx"), strDir);
	m_pfileIndex = new CFile(fileIndex, CFile::modeCreate | CFile::modeReadWrite); //create or write index(packet) file
}

MyWinPcap::~MyWinPcap(void)
{
	if (m_pfileData)
	{
		m_pfileData->Close();
		delete m_pfileData;
		m_pfileData = NULL; // safer
	}
	if (m_pfileIndex)
	{
		m_pfileIndex->Close();
		delete m_pfileIndex;
		m_pfileIndex = NULL;
	}
}

// Append packet
void MyWinPcap::AppendPacket(packet* pkt)
{
	const pcap_pkthdr* header = pkt->header;
	const u_char* data = pkt->pkt_data;
	++m_iCurNo;

	packet_index index;
	index.no = m_iCurNo;
	index.pos = m_pfileData->GetPosition();
	index.len = sizeof(pcap_pkthdr) + header->len;

	m_pfileIndex->SeekToEnd();
	m_pfileIndex->Write(&index, sizeof(packet_index));

	m_pfileData->SeekToEnd();
	m_pfileData->Write(header, sizeof(pcap_pkthdr));
	m_pfileData->Write(data, header->len);

	m_pfileIndex->Flush(); // write from memory to disk immediatly
	m_pfileData->Flush();
}

// Get packet
packet* MyWinPcap::GetPacket(int m_iNo)
{
	int iPos = (m_iNo - 1) * sizeof(packet_index);
	packet_index pIndex;

	m_pfileIndex->Seek(iPos, CFile::begin);
	m_pfileIndex->Read(&pIndex, sizeof(packet_index));

	m_pfileData->Seek(pIndex.pos, CFile::begin);
	byte* buffer = new byte[pIndex.len];
	m_pfileData->Read(buffer, pIndex.len);

	packet* pkt = new packet();
	pkt->header = (pcap_pkthdr*)buffer;
	pkt->pkt_data = (u_char*)(buffer + sizeof(pcap_pkthdr));

	return pkt;
}


// ============= self function =============
// 返回本机所有的网卡
pcap_if_t* MyWinPcap::GetAdapterList(void)
{
	/* Retrieve the device list from the local machine */
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t* m_alldevs = new pcap_if_t();  // ?????? allocate memory to sava temp all-devs ?????
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &m_alldevs, errbuf) == -1) // if error
	{
		CString errmsg;
		USES_CONVERSION;
		errmsg.Format(TEXT("Error in cap_finalldevs_ex(): %s\n"), A2W(errbuf));
		AfxMessageBox(errmsg);

		return NULL;
	}
	else if (NULL == m_alldevs)
	{
		AfxMessageBox(TEXT("No interfaces found! Make sure WinPcap is installed..."));
		return NULL;
	}
	else
		return m_alldevs;
}

