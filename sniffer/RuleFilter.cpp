// RuleFilter.cpp: 实现文件
//

#include "pch.h"
#include "sniffer.h"
#include "RuleFilter.h"


// RuleFilter 对话框

IMPLEMENT_DYNAMIC(RuleFilter, CDialogEx)

RuleFilter::RuleFilter(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG1, pParent)
{

}

RuleFilter::~RuleFilter()
{
}

void RuleFilter::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_CHECK2, m_tcp);
    DDX_Control(pDX, IDC_CHECK5, m_udp);
    DDX_Control(pDX, IDC_CHECK3, m_arp);
    DDX_Control(pDX, IDC_CHECK6, m_rarp);
    DDX_Control(pDX, IDC_CHECK4, m_icmp);
    DDX_Control(pDX, IDC_CHECK7, m_igmp);
    DDX_Control(pDX, IDC_EDIT1, editRule);
}


BEGIN_MESSAGE_MAP(RuleFilter, CDialogEx)
	ON_BN_CLICKED(IDOK, &RuleFilter::OnBnClickedOk)
    ON_EN_KILLFOCUS(IDC_EDIT1, &RuleFilter::OnEnKillfocusEdit1)
END_MESSAGE_MAP()


// RuleFilter 消息处理程序


void RuleFilter::OnBnClickedOk()
{
    filterName.Empty();
    if (1 == m_tcp.GetCheck())
    {
        filterName += _T("(tcp and ip) or ");
    }
    if (1 == m_udp.GetCheck())
    {
        filterName += _T("(udp and ip) or ");
    }
    if (1 == m_arp.GetCheck())
    {
        filterName += _T("arp or ");
    }
    if (1 == m_rarp.GetCheck())
    {
        filterName += _T("rarp or ");
    }
    if (1 == m_icmp.GetCheck())
    {
        filterName += _T("(icmp and ip) or ");
    }
    if (1 == m_igmp.GetCheck())
    {
        filterName += _T("(ip and igmp) or ");
    }
    filterName = filterName.Left(filterName.GetLength() - 4);
    CString ss;
    editRule.GetWindowTextW(ss);
    if (ss != _T(""))
        filterName = ss;
    
    //MessageBox(filtername);
	// TODO: 在此添加控件通知处理程序代码
	CDialogEx::OnOK();
}



void RuleFilter::OnEnKillfocusEdit1()
{
    // TODO: 在此添加控件通知处理程序代码
    CString str = _T("复选框选择将无效");
    MessageBox(str, _T("提示！"));
}
