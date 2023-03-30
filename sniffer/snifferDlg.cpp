
// snifferDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "sniffer.h"
#include "snifferDlg.h"
#include "afxdialogex.h" 
#include "RuleFilter.h"
#include <tchar.h>
#include "analysis.h"
#include "protocol.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#include <vector>



#pragma comment(lib,"iphlpapi.lib")




// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};
// 构造函数
CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CsnifferDlg 对话框



CsnifferDlg::CsnifferDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_SNIFFER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CsnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, combox1);
	DDX_Control(pDX, IDC_LIST1, list1);
	DDX_Control(pDX, IDC_EDIT9, edit);
	DDX_Control(pDX, IDC_TREE1, m_treeDetailInfo);
}

BEGIN_MESSAGE_MAP(CsnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()

	ON_MESSAGE(M_MESSAGEWINPCAP, OnMessageWinPcap)// 参数是用户自定义的消息和处理消息的函数

	ON_CBN_SELCHANGE(ID_WINDOW_TILE_VERT, &CsnifferDlg::OnCbnSelchangeWindowTileVert)
	ON_BN_CLICKED(IDC_BUTTON1, &CsnifferDlg::OnBnClickedButton1)
	ON_NOTIFY(TVN_SELCHANGED, IDC_TREE1, &CsnifferDlg::OnTvnSelchangedTree1)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CsnifferDlg::OnLvnItemchangedList1)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST1, &CsnifferDlg::OnNMCustomdrawList1)
	ON_CBN_SELCHANGE(IDC_COMBO1, &CsnifferDlg::OnCbnSelchangeCombo1)
	ON_CBN_DROPDOWN(IDC_COMBO1, &CsnifferDlg::OnCbnDropdownCombo1)
	ON_BN_CLICKED(IDC_BUTTON3, &CsnifferDlg::OnBnClickedButton3)
	ON_EN_CHANGE(IDC_EDIT9, &CsnifferDlg::OnEnChangeEdit9)
	ON_BN_CLICKED(IDC_BUTTON2, &CsnifferDlg::OnBnClickedButton2)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST1, &CsnifferDlg::OnNMDblclkList1)
	ON_EN_CHANGE(IDC_EDIT7, &CsnifferDlg::OnEnChangeEdit7)
	ON_EN_CHANGE(IDC_EDIT1, &CsnifferDlg::OnEnChangeEdit1)
END_MESSAGE_MAP()


// CsnifferDlg 消息处理程序
BOOL CsnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标
	//*****************************************************************
	// TODO: 在此添加额外的初始化代码
	//combox1.SetWindowTextA("请选择要监听的网卡");// 初始化combox内文字为第0个字符串

	// initialize ListEdit// 为列表视图控件添加全行选中和栅格风格LVS_EX_DOUBLEBUFFER
	list1.SetExtendedStyle(list1.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

	LONG lStyle;
	lStyle = GetWindowLong(list1.m_hWnd, GWL_STYLE);//获取当前窗口style
	lStyle &= ~LVS_TYPEMASK; //清除显示方式位
	lStyle |= LVS_REPORT; //设置style
	SetWindowLong(list1.m_hWnd, GWL_STYLE, lStyle);//设置style
	DWORD dwStyle = list1.GetExtendedStyle();
	dwStyle |= LVS_EX_GRIDLINES;//网格线（只适用与report风格的listctrl）
	//dwStyle |= LVS_EX_CHECKBOXES;
	dwStyle |= LVS_OWNERDATA;//设置自绘风格
	dwStyle |= LVS_EX_DOUBLEBUFFER;//内部双缓冲，防止界面闪烁VC6未定义LVS_EX_DOUBLEBUFFER宏，使用者可以自定义，#define LVS_EX_DOUBLEBUFFER 0x00010000
	list1.SetExtendedStyle(dwStyle); //设置扩展风格
	
	list1.InsertColumn(0, _T("序号"), LVCFMT_CENTER, 50);// 参数：索引，内容，对齐方式，列宽
	list1.InsertColumn(1, _T("时间"), LVCFMT_LEFT, 120);
	list1.InsertColumn(2, _T("源MAC地址"), LVCFMT_CENTER, 150);
	list1.InsertColumn(3, _T("目的MAC地址"), LVCFMT_CENTER, 150);
	list1.InsertColumn(4, _T("长度"), LVCFMT_CENTER, 70);
	list1.InsertColumn(5, _T("协议"), LVCFMT_CENTER, 70);
	list1.InsertColumn(6, _T("源IP:源端口号"), LVCFMT_LEFT, 160);
	list1.InsertColumn(7, _T("目的IP:目的端口号"), LVCFMT_LEFT, 160);
	// 表头不算第0行
	

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CsnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CsnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CsnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CsnifferDlg::OnCbnSelchangeWindowTileVert()
{
	// TODO: 在此添加控件通知处理程序代码

}





void CsnifferDlg::OnTvnSelchangedTree1(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMTREEVIEW pNMTreeView = reinterpret_cast<LPNMTREEVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
}


void CsnifferDlg::OnLvnItemchangedList1(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;

}



void CsnifferDlg::OnNMCustomdrawList1(NMHDR* pNMHDR, LRESULT* pResult)
{

}


void CsnifferDlg::OnCbnSelchangeCombo1()
{
	// TODO: 在此添加控件通知处理程序代码
	
}


pcap_if_t* alldevsHead;// 保存链表头，保证在确定按钮中使用的是同一个链表
void CsnifferDlg::OnCbnDropdownCombo1()
{
	// 清空下拉框中的网卡信息
	combox1.ResetContent();
	// 下拉框中添加网卡信息
	pcap_if_t* alldevs = GetAllAdapter();// 获取网卡信息
	alldevsHead = alldevs;// 保存链表头
	while (alldevs) {
		combox1.AddString((LPCTSTR)(CString)alldevs->description);// 将网卡描述添加到下拉框，不是名称！！！
		alldevs = alldevs->next;
	}
	//释放内存空间
	if (alldevs) 
		pcap_freealldevs(alldevs);

} 

// 筛选对话框

void CsnifferDlg::OnBnClickedButton3()
{
	// 弹出模态对话框
	RuleFilter dlg;
	dlg.DoModal();// 模态方式弹出
}


// click on button1
void CsnifferDlg::OnBnClickedButton1()
{
	DWORD threadId;//线程id
	bool threadExisted = false;
	// 动态改变button中间的文字
	CString str;
	static int count = 1;//抓包第count项
	GetDlgItemText(IDC_BUTTON1, str);
	if (str == _T("开始"))
	{
		SetDlgItemText(IDC_BUTTON1, _T("停止"));
		if(threadExisted == false){
			// 找到下拉框中的对应设备结构体devsHead
			int index = combox1.GetCurSel();// 获取下拉框的值
			pcap_if_t* devsHead = alldevsHead;
			while (index--)
				devsHead = devsHead->next;
			// 创建线程
			CloseHandle(m_hdlThread);
			// 第三个是线程函数名，第四个是传给线程的参数，最后一个是线程的ID好
			m_hdlThread = CreateThread(NULL, 0, setFilterRule, (LPVOID)devsHead, 0, &threadId);
			
			threadExisted = true;

		}
		else {
				ResumeThread(m_hdlThread);
		}
	}
	else
	{

		SetDlgItemText(IDC_BUTTON1, _T("开始"));
		SuspendThread(m_hdlThread);
	}
	
}


void CsnifferDlg::OnEnChangeEdit9()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}


void CsnifferDlg::OnBnClickedButton2()
{
	//置空统计栏
	CString strALL = 0;
	CString strIP = 0;
	CString strARP = 0;
	CString strTCP = 0;
	CString strUDP = 0;
	CString strICMP = 0;
	CString strHTTP = 0;
	CString strIGMP = 0;

	strALL.Format(TEXT("%ld"), all_ptk_count=0);
	this->SetDlgItemTextW(IDC_EDIT_ALL, strALL);

	strIP.Format(TEXT("%ld"), all_ptk_ip = 0);
	this->SetDlgItemTextW(IDC_EDIT_IP, strIP);

	strARP.Format(TEXT("%ld"), all_ptk_arp = 0);
	this->SetDlgItemTextW(IDC_EDIT_ARP, strARP);

	strTCP.Format(TEXT("%ld"), all_ptk_tcp = 0);
	this->SetDlgItemTextW(IDC_EDIT_TCP, strTCP);

	strUDP.Format(TEXT("%ld"), all_ptk_udp = 0);
	this->SetDlgItemTextW(IDC_EDIT_UDP, strUDP);

	strICMP.Format(TEXT("%ld"), all_ptk_icmp = 0);
	this->SetDlgItemTextW(IDC_EDIT_ICMP, strICMP);

	strHTTP.Format(TEXT("%ld"), all_ptk_rarp = 0);
	this->SetDlgItemTextW(IDC_EDIT_HTTP, strHTTP);

	strIGMP.Format(TEXT("%ld"), all_ptk_igmp = 0);
	this->SetDlgItemTextW(IDC_EDIT_IGMP, strIGMP);

	list1.DeleteAllItems();

	// TODO: 在此添加控件通知处理程序代码
	CloseHandle(m_hdlThread);



}

// 处理消息的函数,定义后会自动执行处理
LRESULT CsnifferDlg::OnMessageWinPcap(WPARAM wParam, LPARAM lParam)// 处理消息函数
{
	const struct pcap_pkthdr* header = (const struct pcap_pkthdr*)wParam;
	const u_char* pkt_data = (const u_char*)lParam;

	packet* pkt = new packet;
	pkt->header = header;
	pkt->pkt_data = pkt_data;

	tmpMyWinPcap.AppendPacket(pkt);// 存储捕获的数据包，方便后面选中listctrl进行使用
	analysisData(header, pkt_data);
	ShowStatisticInfo();// 打印计数
	
	return 0;
}

// 控件内双击
void CsnifferDlg::OnNMDblclkList1(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: Add your control notification handler code here
	packet* pkt = tmpMyWinPcap.GetPacket(pNMItemActivate->iItem + 1);
	const struct pcap_pkthdr* header = pkt->header;
	const u_char* pkt_data = pkt->pkt_data;


	m_treeDetailInfo.DeleteAllItems();
	/*while(m_listDataInfo.DeleteString(0)>0);
	m_listDataInfo.InsertString(1,TEXT("添加数据包信息"));*/
	CString str;
	HTREEITEM hItem;

	// NO - TimeStamp
	str.Format(TEXT("NO = %d"), pNMItemActivate->iItem + 1);
	hItem = m_treeDetailInfo.InsertItem(str);


	struct tm  lTime = { 0,0,0,0,0,0,0,0,0 };
	struct tm* plTime = &lTime;
	char strTime[9];
	time_t local_tv_sec;

	local_tv_sec = header->ts.tv_sec;
	localtime_s(plTime, &local_tv_sec);
	strftime(strTime, sizeof strTime, "%H:%M:%S", plTime);
	USES_CONVERSION;
	str.Format(TEXT("TimeStamp = %s"), A2W(strTime));
	m_treeDetailInfo.InsertItem(str, hItem);

	// show MAC detail info
	ShowMacDetail(hItem, pkt_data);

	ethernet_header* eth_hdr = (ethernet_header*)pkt_data;
	// 如果是IP数据包，则显示IP包的详细信息；
	if (ntohs(eth_hdr->eth_type) == 0x0800)
		ShowIPDetail(hItem, pkt_data); // show IP detail info

	ip_header* ip_hdr = (ip_header*)(pkt_data + 14);
	if (ip_hdr->protocol == 6)
	{
		ShowTCPDetail(hItem, pkt_data);// show TCP detail info
		if (IsHTTP(pkt_data))
			GetHTTPDetail(hItem, pkt_data);// show HTTP detail info
	}
	else if (ip_hdr->protocol == 17)
		GetUDPDetail(hItem, pkt_data);// show UDP detail info
	else if (ip_hdr->protocol == 1)
		GetICMPDetail(hItem, pkt_data);// show ICMP detail info


	
	// show pkt_data info(data)
	GetDataInfo(edit, pkt);

	*pResult = 0;
}


//**********类内函数


// 获取正确的Ethernet Type类型
void CsnifferDlg::GetMacType(CString& eth_strType, u_short eth_Type, bool isFirst) //& is to pass address
{
	//if (isFirst)
		//all_ptk_count++;

	switch (eth_Type)
	{
	case 0x0800:
		eth_strType = TEXT("IP");
		if (isFirst)
			all_ptk_ip++;
		break;
	case 0x0806:
		eth_strType = TEXT("ARP");
		if (isFirst)
			all_ptk_arp++;
		break;
	case 0x8035:
		eth_strType = TEXT("RARP");
		break;
	case 0x880B:
		eth_strType = TEXT("PPP");
		break;
	case 0x814C:
		eth_strType = TEXT("SNMP");
		break;
	default:
		eth_strType = TEXT("other");
		break;
	}
}
// 获取正确的Mac地址
void CsnifferDlg::GetMacAddress( TCHAR* eth_dMac, u_char eth_sMac[])
{
	swprintf_s(
		eth_dMac,
		18,
		TEXT("%02X-%02X-%02X-%02X-%02X-%02X"),
		eth_sMac[0],
		eth_sMac[1],
		eth_sMac[2],
		eth_sMac[3],
		eth_sMac[4],
		eth_sMac[5]);
}



// 获取正确的IP Type类型
void CsnifferDlg::GetIPType(CString& ip_strIP, u_short ip_Type, bool isFirst)
{
	switch (ip_Type)
	{
	case 1:
		ip_strIP = TEXT("ICMP");
		if (isFirst)
			all_ptk_icmp++;
		break;
	case 6:
		ip_strIP = TEXT("TCP");
		if (isFirst)
			all_ptk_tcp++;
		break;
	case 17:
		ip_strIP = TEXT("UDP");
		if (isFirst)
			all_ptk_udp++;
		break;
	case 2:
		ip_strIP = TEXT("IGMP");
		if (isFirst)
			all_ptk_igmp++;
		break;
	default:
		ip_strIP = TEXT("other");
		break;
	}
}

// 获取IP地址
void CsnifferDlg::GetIPAddress(TCHAR* ip_Address, ip_address* ip_addr)
{
	swprintf_s(
		ip_Address,
		16,
		TEXT("%d.%d.%d.%d"),
		ip_addr->byte1,
		ip_addr->byte2,
		ip_addr->byte3,
		ip_addr->byte4);
}














// 显示Mac（Ethernet）协议的详细信息
void CsnifferDlg::ShowMacDetail(HTREEITEM& hItem, const u_char* pkt_data)
{
	ethernet_header* mac_hdr = (ethernet_header*)pkt_data;
	hItem = m_treeDetailInfo.InsertItem(TEXT("MAC LAYER"));

	CString str = NULL;
	TCHAR mac_dstAddr[18];
	TCHAR mac_srcAddr[18];
	CString mac_strType = NULL;

	GetMacType(mac_strType, ntohs(mac_hdr->eth_type), false); // 16-bit == u_short ==  ntohs() is to swap network to host 
	str.Format(TEXT("Mac Type = %s"), mac_strType);
	m_treeDetailInfo.InsertItem(str, hItem);

	GetMacAddress(mac_srcAddr, mac_hdr->srcAddress);
	str.Format(TEXT("Source Mac = %s"), mac_srcAddr);
	m_treeDetailInfo.InsertItem(str, hItem);

	GetMacAddress(mac_dstAddr, mac_hdr->desAddress);
	str.Format(TEXT("Dest Mac = %s"), mac_dstAddr);
	m_treeDetailInfo.InsertItem(str, hItem);
}

// 显示IP协议的详细信息
void CsnifferDlg::ShowIPDetail(HTREEITEM& hItem, const u_char* pkt_data)
{
	// =================== IP ======================
	ip_header* ip_hdr = (ip_header*)(pkt_data + 14);

	hItem = m_treeDetailInfo.InsertItem(TEXT("IP LAYER"));
	CString str = NULL;
	// Version
	u_char ip_version = ip_hdr->version;
	str.Format(TEXT("Version = %d"), ip_version);
	m_treeDetailInfo.InsertItem(str, hItem);

	// Header Length
	u_char ip_length = ip_hdr->ihl;
	str.Format(TEXT("Header Length = %d"), ip_length);
	m_treeDetailInfo.InsertItem(str, hItem);

	// Type of service
	u_char ip_tos = ip_hdr->tos;
	str.Format(TEXT("Service Type = %0X"), ip_tos);
	m_treeDetailInfo.InsertItem(str, hItem);

	// Total Length
	u_short ip_totalLen = ip_hdr->tot_len;
	str.Format(TEXT("Total Length = %d"), ntohs(ip_totalLen));
	m_treeDetailInfo.InsertItem(str, hItem);

	// Identification
	str.Format(TEXT("Identification = %d"), ntohs(ip_hdr->id));
	m_treeDetailInfo.InsertItem(str, hItem);

	// Flags
	TCHAR ip_strFlag[4];
	u_short ip_flag = (ip_hdr->flag);
	_itow_s(ip_flag, ip_strFlag, 4, 2);
	str.Format(TEXT("Flag = %03s"), ip_strFlag);// 填充字符串方法：CString szTemp; szTemp.Format("%06d",   n); //n=123（000123）|456（000456）
	m_treeDetailInfo.InsertItem(str, hItem);

	// Flagment offset
	u_short ip_flagoff = ip_hdr->frag_off;
	str.Format(TEXT("Flagment offset = %d"), ip_flagoff);
	m_treeDetailInfo.InsertItem(str, hItem);

	// Time to live
	u_char ip_ttl = ip_hdr->ttl;
	str.Format(TEXT("Time to live = %d"), ip_ttl);
	m_treeDetailInfo.InsertItem(str, hItem);

	// IP Protocol
	CString ip_strProtocol = NULL;
	u_char ip_protocol = ip_hdr->protocol;
	GetIPType(ip_strProtocol, ip_protocol, false); // get ip protocol by call function -> GetIPType()
	str.Format(TEXT("IP Protocol = %s"), ip_strProtocol);
	m_treeDetailInfo.InsertItem(str, hItem);

	// Header CheckSum
	u_short ip_chksum = ip_hdr->chk_sum;
	str.Format(TEXT("Header CheckSum = %0X"), ntohs(ip_chksum));
	m_treeDetailInfo.InsertItem(str, hItem);

	// Source IP
	TCHAR ip_srcAddr[16];
	TCHAR ip_dstAddr[16];
	GetIPAddress(ip_srcAddr, &ip_hdr->srcaddr);
	GetIPAddress(ip_dstAddr, &ip_hdr->dstaddr);
	str.Format(TEXT("Source IP = %s"), ip_srcAddr);
	m_treeDetailInfo.InsertItem(str, hItem);
	str.Format(TEXT("Dest IP = %s"), ip_dstAddr);
	m_treeDetailInfo.InsertItem(str, hItem);
}

// 显示TCP协议的详细信息
void CsnifferDlg::ShowTCPDetail(HTREEITEM& hItem, const u_char* pkt_data)
{
	ip_header* ip_hdr = (ip_header*)(pkt_data + 14);
	u_short ip_hdrLen = ip_hdr->ihl * 4; //一行4字节，故乘以4
	tcp_header* tcp_hdr = (tcp_header*)(pkt_data + 14 + ip_hdrLen);

	hItem = m_treeDetailInfo.InsertItem(TEXT("TCP LAYER"));
	CString str = NULL;


	// 源端口号-目的端口号
	u_short tcp_srcPort = tcp_hdr->src_port;
	u_short tcp_dstPort = tcp_hdr->dst_port;
	str.Format(TEXT("Source Port = %d"), ntohs(tcp_srcPort));
	m_treeDetailInfo.InsertItem(str, hItem);
	str.Format(TEXT("Dest Port = %d"), ntohs(tcp_dstPort));
	m_treeDetailInfo.InsertItem(str, hItem);

	// 序列号 - 确认号
	u_int tcp_sepNo = tcp_hdr->seq_no;
	u_int tcp_ackNo = tcp_hdr->ack_no;
	str.Format(TEXT("Seq NO = %ld"), ntohl(tcp_sepNo)); //32-bit == u_int ==  ntohl() is to swap network to host
	m_treeDetailInfo.InsertItem(str, hItem);
	str.Format(TEXT("Ack NO = %ld"), ntohl(tcp_ackNo));
	m_treeDetailInfo.InsertItem(str, hItem);

	// 数据偏移
	u_char tcp_offset = tcp_hdr->offset;
	str.Format(TEXT("Offset = %d"), tcp_offset);
	m_treeDetailInfo.InsertItem(str, hItem);

	// 6保留位
	TCHAR tcp_strOffset1[5];
	TCHAR tcp_strOffset2[3];
	u_char tcp_reserved1 = tcp_hdr->reserved_1; // first 4 bit
	_itow_s(tcp_reserved1, tcp_strOffset1, 5, 2);
	u_char tcp_reserved2 = tcp_hdr->reserved_2; // last 2 bit
	_itow_s(tcp_reserved2, tcp_strOffset2, 3, 2);
	str.Format(
		TEXT("Reserved(6 bit) = %04s%02s"), // 填充字符串方法：1、char buff[20]; memset(buff,   'x',   sizeof(buff));   
		tcp_strOffset1,                     // 填充字符串方法：2、CString szTemp; szTemp.Format("%06d",   n); //n=123（000123）|456（000456）
		tcp_strOffset2);
	m_treeDetailInfo.InsertItem(str, hItem);

	// 6标志位
	TCHAR  tcp_strflags[7]; // it is used to save string in middle
	u_char tcp_flag = tcp_hdr->flag;
	_itow_s(tcp_flag, tcp_strflags, 7, 2); // number to string 
	str.Format(TEXT("%06s"), tcp_strflags); // add 0 before string if there is empty

	CString strFlags = str; // save str


	swprintf(           // ntohs()  net--->host format
		tcp_strflags,
		7,
		TEXT("%c%c%c%c%c%c"),
		str[5],
		str[4],
		str[3],
		str[2],
		str[1],
		str[0]);

	str.Format(TEXT("Flags = %s"), tcp_strflags);
	HTREEITEM childhItem = m_treeDetailInfo.InsertItem(str, hItem); // create a new child tree

	str.Format(TEXT("URG = %c"), strFlags[5]);
	m_treeDetailInfo.InsertItem(str, childhItem);
	str.Format(TEXT("ACK = %c"), strFlags[4]);
	m_treeDetailInfo.InsertItem(str, childhItem);
	str.Format(TEXT("PSH = %c"), strFlags[3]);
	m_treeDetailInfo.InsertItem(str, childhItem);
	str.Format(TEXT("RST = %c"), strFlags[2]);
	m_treeDetailInfo.InsertItem(str, childhItem);
	str.Format(TEXT("SYN = %c"), strFlags[1]);
	m_treeDetailInfo.InsertItem(str, childhItem);
	str.Format(TEXT("FIN = %c"), strFlags[0]);
	m_treeDetailInfo.InsertItem(str, childhItem);

	// 窗口大小
	u_short tcp_wndsize = tcp_hdr->wnd_size;
	str.Format(TEXT("Windows size = %d"), ntohs(tcp_wndsize));
	m_treeDetailInfo.InsertItem(str, hItem);

	// 校验和
	u_short tcp_checksum = tcp_hdr->chk_sum;
	str.Format(TEXT("CheckSum = %d"), ntohs(tcp_checksum));
	m_treeDetailInfo.InsertItem(str, hItem);

	// 紧急指针
	u_short tcp_urgpoint = tcp_hdr->urgt_p;
	str.Format(TEXT("Urgent Point = %d"), ntohs(tcp_urgpoint));
	m_treeDetailInfo.InsertItem(str, hItem);
}

// 显示UDP协议的详细信息
void CsnifferDlg::GetUDPDetail(HTREEITEM& hItem, const u_char* pkt_data)
{
	ip_header* ip_hdr = (ip_header*)(pkt_data + 14);
	u_short ip_hdrLen = ip_hdr->ihl * 4;
	udp_header* udp_hdr = (udp_header*)(pkt_data + 14 + ip_hdrLen);

	hItem = m_treeDetailInfo.InsertItem(TEXT("UDP LAYER"));
	CString str = NULL;

	// Port
	u_short udp_srcPort = udp_hdr->sport;
	u_short udp_dstPort = udp_hdr->dport;
	str.Format(TEXT("Source Port = %d"), ntohs(udp_srcPort));
	m_treeDetailInfo.InsertItem(str, hItem);
	str.Format(TEXT("Dest Port = %d"), ntohs(udp_dstPort));
	m_treeDetailInfo.InsertItem(str, hItem);

	// Header Length
	u_short udp_hdrLen = udp_hdr->len;
	str.Format(TEXT("Header Length = %d"), ntohs(udp_hdrLen));
	m_treeDetailInfo.InsertItem(str, hItem);

	// 校验和
	u_short udp_checksum = udp_hdr->crc;
	str.Format(TEXT("CheckSum = %d"), ntohs(udp_checksum));
	m_treeDetailInfo.InsertItem(str, hItem);
}


// 显示ICMP协议的详细信息
void CsnifferDlg::GetICMPDetail(HTREEITEM& hItem, const u_char* pkt_data)
{
	ip_header* ip_hdr = (ip_header*)(pkt_data + 14);
	u_short ip_hdrLen = ip_hdr->ihl * 4;
	icmp_header* icmp_hdr = (icmp_header*)(pkt_data + 14 + ip_hdrLen);

	hItem = m_treeDetailInfo.InsertItem(TEXT("ICMP LAYER"));
	CString str = NULL;

	// 类型
	u_char icmp_type = icmp_hdr->type;
	str.Format(TEXT("Type = %d"), icmp_type);
	m_treeDetailInfo.InsertItem(str, hItem);

	// 代码
	u_char icmp_code = icmp_hdr->code;
	str.Format(TEXT("Code = %d"), icmp_code);
	m_treeDetailInfo.InsertItem(str, hItem);

	// 检验和
	u_short icmp_checksum = icmp_hdr->chk_sum;
	str.Format(TEXT("CheckSum = %d"), ntohs(icmp_checksum));
	m_treeDetailInfo.InsertItem(str, hItem);
}

// 显示HTTP协议的详细信息====================================================================================================================================================================================
void CsnifferDlg::GetHTTPDetail(HTREEITEM& hItem, const u_char* pkt_data)
{
	ip_header* ip_hdr = (ip_header*)(pkt_data + 14);
	u_short ip_hdrLen = ip_hdr->ihl * 4;
	tcp_header* tcp_hdr = (tcp_header*)(pkt_data + 14 + ip_hdrLen);
	u_short tcp_hdrLen = tcp_hdr->offset * 4;


	u_char* http_pkt = (u_char*)(pkt_data + 14 + ip_hdrLen + tcp_hdrLen);
	u_short http_pktLen = ntohs(ip_hdr->tot_len) - (ip_hdrLen + tcp_hdrLen); //u_short httpLen2 = header->len - (14+ip_hdrLen+tcp_hdrLen);

	//http_packet * http_pktHdr = new http_packet ;// HTTP packet's  struct
	vector<CString> strVecRequestHttp; // 定义请求头容器
	vector<CString> strVecRespondHttp; // 定义响应头容器
	CString chrVecTmp = NULL; // 声明存入容器的临时字符
	CString strVecTmp = NULL; // 声明存入容器的临时字符串

	u_char* pchrHttpAllData = NULL; //定义HTTP协议包的起始位置，包括请求头或响应头都可
	u_char* pchrHttpRequestPos = NULL; //定义HTTP协议包的请求头的起始位置
	u_char* pchrHttpRespondPos = NULL; //定义HTTP协议包的响应头的起始位置
	pchrHttpAllData = http_pkt; //赋值得到HTTP协议包的开始位置

	CString strHttpALLData = NULL;//定义HTTP协议包的数据包,包括请求头或响应头都可
	CString strHttpRequestData = NULL;//定义HTTP协议包的请求头的数据
	CString strHttpRespondData = NULL;//定义HTTP协议包的响应头的数据

	u_short httpAllPos = 0;
	u_short httpAllLen = 0;
	httpAllLen = http_pktLen;

	if (IsHTTP(pkt_data)) // check is http
	{
		// show request to tree
		hItem = m_treeDetailInfo.InsertItem(TEXT("HTTP LAYER"));

		if (*pkt_data == 'H') // 如果第一个字符为H，即可能以HTTP开头的，则为响应头，否则应为请求头
		{
			for (int i = 0; i < httpAllLen; i++) // get http_Get data
			{
				chrVecTmp.Format(TEXT("%c"), pchrHttpAllData[i]); // format
				strHttpRespondData += chrVecTmp;//记录完整的HTTP响应头的数据

				chrVecTmp.Format(TEXT("%c"), pchrHttpAllData[i]); //记录每一行的内容，并保存在临时字符串中
				strVecTmp += chrVecTmp;
				if (i > 2 && pchrHttpAllData[i - 1] == 13 && pchrHttpAllData[i] == 10) //根据回车换行符判断，并把每行保存在vector数组中
				{
					strVecRespondHttp.push_back(strVecTmp);
					chrVecTmp = "";
					strVecTmp = "";
				}
			}

			HTREEITEM childhItem = m_treeDetailInfo.InsertItem(TEXT("Request Header:"), hItem);
			for (u_short irequest = 0; irequest < strVecRequestHttp.size(); irequest++)
				m_treeDetailInfo.InsertItem(strVecRequestHttp[irequest], childhItem);
		}
		else
		{
			for (int i = 0; i < httpAllLen; i++) // get http_Get data
			{
				chrVecTmp.Format(TEXT("%c"), pchrHttpAllData[i]); // format
				strHttpRequestData += chrVecTmp;//记录完整的HTTP响应头的数据

				chrVecTmp.Format(TEXT("%c"), pchrHttpAllData[i]); //记录每一行的内容，并保存在临时字符串中
				strVecTmp += chrVecTmp;
				if (i > 2 && pchrHttpAllData[i - 1] == 13 && pchrHttpAllData[i] == 10) //根据回车换行符判断，并把每行保存在vector数组中
				{
					strVecRespondHttp.push_back(strVecTmp);
					chrVecTmp = "";
					strVecTmp = "";
				}
			}

			HTREEITEM childhItem = m_treeDetailInfo.InsertItem(TEXT("Respond Header:"), hItem);
			for (u_short irespond = 0; irespond < strVecRespondHttp.size(); irespond++)
				m_treeDetailInfo.InsertItem(strVecRespondHttp[irespond], childhItem);
		}
	}








}

// 判断该协议是否为HTTP协议
bool CsnifferDlg::IsHTTP(const u_char* pkt_data)
{
	ip_header* ip_hdr = (ip_header*)(pkt_data + 14);
	u_short ip_hdrLen = ip_hdr->ihl * 4;
	tcp_header* tcp_hdr = (tcp_header*)(pkt_data + 14 + ip_hdrLen);
	u_short tcp_hdrLen = tcp_hdr->offset * 4;

	u_char* http_pkt = (u_char*)(pkt_data + 14 + ip_hdrLen + tcp_hdrLen);
	u_short http_pktLen = ntohs(ip_hdr->tot_len) - (ip_hdrLen + tcp_hdrLen); //u_short httpLen2 = header->len - (14+ip_hdrLen+tcp_hdrLen);

	CString chrTmp = NULL;
	CString strTmp = NULL;
	CString strHttp = NULL;

	int httpPos = 0;

	if (ip_hdr->protocol == 6)
	{
		for (int i = 0; i < http_pktLen; i++) // 仅提取第一行是否含有HTTP字符串
		{
			chrTmp.Format(TEXT("%c"), http_pkt[i]);
			strTmp += chrTmp;
			if (i > 2 && http_pkt[i - 1] == 13 && http_pkt[i] == 10)
				break;
		}
		//AfxMessageBox(strTmp);
		httpPos = strTmp.Find(TEXT("HTTP"), 0);

		if (httpPos != -1 && httpPos != 65535) // 如果第一行含有字符串HTTP，则为HTTP协议
		{
			return true;
		}

		else
			return false;

	}
	return false;
}


// 显示Packet Data数据信息，最下方控件显示；
void CsnifferDlg::GetDataInfo(CEdit& eText, packet* pkt)
{
	const struct pcap_pkthdr* header = pkt->header;
	const u_char* pkt_data = pkt->pkt_data;
	u_int pkt_dataLen = header->len; // 得到单个Packet_Data(注意：不是packet)数据包的长度

	CString strText = NULL;
	CString chrAppend = NULL;

	u_int eRows = 0;

	for (u_short i = 0; i < pkt_dataLen; i++)
	{
		CString strAppend = NULL;
		if (0 == (i % 16)) // 取余，换行
		{
			eRows++;

			if (0 == i)
			{
				strText += chrAppend;
				strAppend.Format(TEXT(" 0X%04X ->  "), eRows);
				strText += strAppend;
			}
			else
			{
				strText += TEXT("==>> ") + chrAppend;
				strAppend.Format(TEXT("\x0d\x0a 0X%04X ->  "), eRows); //0x0d:回车; 0x0a:换行;0X:表示16进制显示;%04x表示以4位的16进制显示并以0填充空位; eRows即显示行数（16进制格式显示）
				strText += strAppend;
			}
			chrAppend = ""; // reset null
		}
		strAppend.Format(TEXT("%02x "), pkt_data[i]);
		strText += strAppend;


		if (i > 2 && pkt_data[i - 1] == 13 && pkt_data[i] == 10)//如果遇到回车、换行，则直接继续，以免使显示字符换行
			continue;
		strAppend.Format(TEXT("%c"), pkt_data[i]);
		chrAppend += strAppend;

	}
	if (chrAppend != "")
		strText += TEXT("==>> ") + chrAppend;

	eText.SetWindowTextW(strText);
}



// 在“数据统计”组中，显示接收到的各种协议数据包统计信息
void CsnifferDlg::ShowStatisticInfo(void)
{
	CString strALL = NULL;
	CString strIP = NULL;
	CString strARP = NULL;
	CString strTCP = NULL;
	CString strUDP = NULL;
	CString strICMP = NULL;
	CString strHTTP = NULL;
	CString strIGMP = NULL;

	strALL.Format(TEXT("%ld"), all_ptk_count);
	this->SetDlgItemTextW(IDC_EDIT_ALL, strALL);

	strIP.Format(TEXT("%ld"), all_ptk_ip);
	this->SetDlgItemTextW(IDC_EDIT_IP, strIP);

	strARP.Format(TEXT("%ld"), all_ptk_arp);
	this->SetDlgItemTextW(IDC_EDIT_ARP, strARP);

	strTCP.Format(TEXT("%ld"), all_ptk_tcp);
	this->SetDlgItemTextW(IDC_EDIT_TCP, strTCP);

	strUDP.Format(TEXT("%ld"), all_ptk_udp);
	this->SetDlgItemTextW(IDC_EDIT_UDP, strUDP);

	strICMP.Format(TEXT("%ld"), all_ptk_icmp);
	this->SetDlgItemTextW(IDC_EDIT_ICMP, strICMP);

	strHTTP.Format(TEXT("%ld"), all_ptk_rarp);
	this->SetDlgItemTextW(IDC_EDIT_HTTP, strHTTP);

	strIGMP.Format(TEXT("%ld"), all_ptk_igmp);
	this->SetDlgItemTextW(IDC_EDIT_IGMP, strIGMP);


}

void CsnifferDlg::OnEnChangeEdit7()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}


void CsnifferDlg::OnEnChangeEdit1()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}





void  CsnifferDlg::analysisData(const struct pcap_pkthdr* header, const u_char* pkt_data)// packet_handler形参固定三个，否则pcap_loop无法调用
{


	// 获取主框架的指针
	CWnd* mainWnd = theApp.GetMainWnd();
	CsnifferDlg* dlg = (CsnifferDlg*)mainWnd;
	// 回调函数的数据结构体赋值


	struct tm* ltime;
	char timestr[16];
	mac_header* mh = (mac_header*)(pkt_data);// 14个字节是mac帧首部的长度，后面就是ip的首部
	ip_header* ih = (ip_header*)(pkt_data + 14); //ip数据包头部，并转化位ip_header结构体类型
	udp_header* uh = NULL;
	u_int ip_len;
	u_short sport, dport;

	// 0.list列表中的数据包序号
	int listRow = dlg->list1.GetItemCount();
	CString order;
	order.Format(TEXT("%d"), listRow);
	dlg->list1.InsertItem(listRow, order);
	// 1.list列表的时间

	struct tm lTime = { 0,0,0,0,0,0,0,0,0 };
	struct tm* plTime = &lTime;
	char strTime[16];
	time_t local_tv_sec;
	local_tv_sec = header->ts.tv_sec;
	localtime_s(plTime, &local_tv_sec);
	strftime(strTime, sizeof strTime, "%H:%M:%S", plTime);
	USES_CONVERSION;
	dlg->list1.SetItemText(listRow, 1, A2W(strTime));

	// 2.源mac
	CString srcMac;
	srcMac.Format(TEXT("%02X-%02X-%02X-%02X-%02X-%02X"),
		mh->srcAddress[0],
		mh->srcAddress[1],
		mh->srcAddress[2],
		mh->srcAddress[3],
		mh->srcAddress[4],
		mh->srcAddress[5]
	);
	dlg->list1.SetItemText(listRow, 2, srcMac);

	// 3.目的mac
	CString desMac;
	desMac.Format(TEXT("%02X-%02X-%02X-%02X-%02X-%02X"),
		mh->desAddress[0],
		mh->desAddress[1],
		mh->desAddress[2],
		mh->desAddress[3],
		mh->desAddress[4],
		mh->desAddress[5]
	);
	dlg->list1.SetItemText(listRow, 3, desMac);

	// 4.list列表的长度
	CString l;
	l.Format(TEXT("%d B"), header->len);
	dlg->list1.SetItemText(listRow, 4, l);

	all_ptk_count++;
	// 5.协议及包的数量
	switch (ntohs(mh->eth_type)) {
	case IPV4:
		dlg->list1.SetItemText(listRow, 5, _T("IPV4"));
		all_ptk_ip++;
		switch (ih->protocol) {
		case TCP:
			all_ptk_tcp++;
			break;
		case ICMP:
			all_ptk_icmp++;
			break;
		case UDP:
			all_ptk_udp++;
			break;
		case IGMP:
			all_ptk_igmp++;
			break;
		}
		break;
	case IPV6:
		dlg->list1.SetItemText(listRow, 5, _T("IPV6"));
		break;
	case ARP:
		dlg->list1.SetItemText(listRow, 5, _T("ARP"));
		all_ptk_arp++;
		break;
	case RARP:
		dlg->list1.SetItemText(listRow, 5, _T("RARP"));
		all_ptk_rarp++;
		break;
	default:
		dlg->list1.SetItemText(listRow, 5, _T("Other types"));
		break;
	}
	// 6.源IP
	/* 获得UDP首部的位置 */
	ip_len = (ih->ihl & 0xf) * 4;
	uh = (udp_header*)((u_char*)ih + ip_len);
	/* 将网络字节序列转换成主机字节序列 */
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);
	/* 打印IP地址和UDP端口 */
	CString srcIP;
	srcIP.Format(TEXT("%d.%d.%d.%d:%d"),
		ih->srcaddr.byte1,
		ih->srcaddr.byte2,
		ih->srcaddr.byte3,
		ih->srcaddr.byte4,
		sport
	);
	dlg->list1.SetItemText(listRow, 6, srcIP);
	// 7.目的IP
	CString desIP;
	desIP.Format(TEXT("%d.%d.%d.%d:%d"),
		ih->dstaddr.byte1,
		ih->dstaddr.byte1,
		ih->dstaddr.byte1,
		ih->dstaddr.byte1,
		dport);
	dlg->list1.SetItemText(listRow, 7, desIP);

	if (header)
	{
		delete header;
		header = NULL;
	}
	if (pkt_data)
	{
		delete pkt_data;
		pkt_data = NULL;
	}
}

