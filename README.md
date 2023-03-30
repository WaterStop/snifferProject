> 王森    2021E8012020

#### 实验概述

> 实验名称：嗅探器设计与实现
> 操作系统：Windows
> 实验平台：Visual Stdio 2022
> 语言：C++
> Git链接：https://gitee.com/water_stop/sniffer

#### 项目设计原理
![image-20220330191902976](https://gitee.com/water_stop/pic-store/raw/master/image/image-20220330191902976.png)

1. 传输单位
   - 服务数据单元SDU是所要传输的数据，协议控制信息PCI是所要传输的协议控制信息
   - 协议数据单元PDU = SDU(数据)+PCI(规则)，是对等实体间的数据传送单位
   - PDU在物理层称为比特，在链路层称为帧，在网络层称为分组，在传输层称为报文
   - n-SDU + n-PCI = n-PDU = (n-1)SDU
2. 垂直方向
   - 最底层只能向上层提供服务，中间各层使用下层提供的服务实现自身功能并向上层提供服务，最高层面向用户进程提供服务
   - 上层只能通过接口使用下层服务，且服务实现细节是透明的
   - 发送方将用户数据层层包裹下放，再将数据以透明比特流形式发送，接收方将用户数据层层拆解分析
3. 水平方向
   - 对等实体在逻辑上有一条直接信道

4. TCP/IP五层网络结构

   - 应用层：添加的首部协议为HTTP、HTTPS、FTP、POP3、SMTP等。

   - 运输层：添加的首部协议为TCP、UDP

   -  网络层：添加的首部协议为IP、ICMP、IGMP、ARP、RARP

   -  链路层：添加MAC帧首部、

   - 物理层：常用设备有集线器、中继器、调制解调器、网线、双绞线、同轴电缆。

        ![image-20220330193107464](https://gitee.com/water_stop/pic-store/raw/master/image/image-20220330193107464.png)

5. 数据帧组成结构

 ![image-20220330111955352](https://gitee.com/water_stop/pic-store/raw/master/image/image-20220330111955352.png)

- 前同步码：7 byte，用来使接收端的适配器在接收 MAC 帧时能够迅速调整到与发送端相同的时钟频率

- 帧开始定界符：1 byte，告诉接收端适配器：“帧信息要来了，准备接收”。

- MAC帧结构

  - 目的地址： 6 byte， 接收帧的网络适配器的物理地址（MAC 地址）
  - 源地址： 6 byte， 发送帧的网络适配器的物理地址（MAC 地址）
  - 类型：2byte（协议名称  十六进制的表示）
    - IPV4      0x0800
    - IPV6      0x86DD
    - ARP      0x0806
    - RARP    0x8035
    - PPP       0x880B
    - ···
  
- 数据帧结构：长度为46 byte ~ 1500 byte，由前面的MAC的类型字段决定

  - 0x0800表示数据帧结构是IPV4的报文格式

        ![image-20220330114116029](https://gitee.com/water_stop/pic-store/raw/master/image/image-20220330114116029.png)

    - 版本：4 bits，表明IP协议实现的版本号，当前一般为IPv4，即0100。
  
    - 报头长度IHL：4 bits，表示IP报文头部按4字节计数的长度，即报文头的长度等于IHL的值乘以4
  
    - 服务类型：8 bits，前3bits为优先权子字段。中间4bits取1依次表示为最小时延、最大吞吐量、最高可靠性和最小费用，全为0则表示一般服务，第8比特保留未用常置0。
  
    - 总长度字段：16 byte，指明整个数据报的长度（以字节为单位）。最大长度为65535字节。
  
    - 标志字段：16 byte，用来唯一地标识主机发送的每一份数据报。通常每发一份报文，它的值会加1。
  
    - 标志位字段：3 byte，标志数据报是否要求分段。
  
    - 段偏移字段：13 byte，若该数据报要求分段的话，此字段指明该段偏移距原始数据报开始的位置。

    - 生存期TTL：8 byte，用来设置数据报最多可以经过的路由器数。每经过一个路由器，其值减1，直到0时该数据报被丢弃。

    - 协议字段：8 byte，指明IP层所封装的上层协议类型ICMP(1)、IGMP(2) 、TCP(6)、UDP(17)···

          ![image-20220330161900597](https://gitee.com/water_stop/pic-store/raw/master/image/image-20220330161900597.png)
          
          <img src="https://gitee.com/water_stop/pic-store/raw/master/image/image-20220330161951835.png" alt="image-20220330161951835" style="zoom: 80%;" />
  
    - 头部校验和字段：16 byte，内容是根据IP头部计算得到的校验和码。
  
    - 源IP地址字段：32 byte，发送IP数据报文的源主机IP地址
  
    - 目标IP地址字段：32 byte，发送IP数据报文的目的主机IP地址
  
    - 可选项字段：32 byte，用来定义一些任选项：如记录路径、时间戳等。可选项字段的长度必须是32比特的整数倍，如果不足，必须填充0以达到此长度要求
  
  - 0x08DD表示数据帧结构是IPV6的报文格式
     <img src="https://gitee.com/water_stop/pic-store/raw/master/image/image-20220330162918133.png" alt="image-20220330162918133" style="zoom:80%;" />
  
    - 版本号：4 bits，4表示为IPV4；6表示为IPV6
    - 流量等级：8 bits，以区分业务编码点（DSCP）标记一个IPv6数据包，以此指明数据包应当如何处理
    - 流标签：20 bits，用来标记IP数据包的一个流，当前的标准中没有定义如何管理和处理流标签的细节
    - 数据长度：16 bits，表示有效载荷的长度，指紧跟IPv6基本报头的数据包，包含IPv6扩展报头
    - 下一报头：8 bits，指明了跟随在IPv6基本报头后的扩展报头的信息类型。
    - 跳限制：8 bits，定义了IPv6数据包所能经过的最大跳数
    - 源地址：128 bits，表示该报文的源地址
    - 目的地址：128 bits，表示该报文的目的地址
    - 可变拓展报头
  
  - 0x0806表示数据帧结构是ARP的报文格式
  
        ![image-20220330111832424](https://gitee.com/water_stop/pic-store/raw/master/image/image-20220330111832424.png)
  
    - 硬件类型：2 byte，用来定义运行ARP的网络类型
    - 协议类型：2 byte，用来定义使用的协议。
    - 硬件长度：1 byte，用来定义物理地址的长度，以字节为单位。
    - 协议长度：1 byte，用来定义逻辑地址的长度，以字节为单位。
    - 操作码：2 byte，用来定义报文的类型。已定义的分组类型有两种：ARP请求（1），ARP响应（2）。
    - 源硬件地址：对于以太网为6 byte，用来定义发送方的物理地址。
    - 源逻辑地址：对于IP协议为4byte，用来定义发送方的IP地址。
    - 目的硬件地址：对于以太网为6 byte，用来定义发送方的物理地址。ARP请求报文，这个字段为全0
    - 目的逻辑地址：对于IP协议为4byte，用来定义接受方的IP地址。
    - padding字段：真正发包的时为了保证以太网帧的最小帧长为64 bytes，用来填充数据包大小

#### 项目设计

1. 获取网卡
   - 在下拉框控件中，使用`GetAllAdapter()`获取本地的网卡信息
   - 获取的网卡信息是pcap_if_t类型的链表，每个元素存储了一个网卡的信息
   - 点击确定控件时 ，会获取下拉框的位号，由于链表头使用的是全局变量，所以根据索引可以得到网卡信息的结构体
   - 获取网卡结构体的name，**注意description属性是网卡的型号并不唯一**
2. 设置过滤规则
   - 创建一个模态对话框，通过filterName进行过滤规则信息的传递
   - 在主对话框中解析该字符串获取过滤信息
3. 创建消息处理线程
   - `setFilterRule()`进行数据帧的处理
     - 使用`pcap_findalldevs_ex()`获取设备链表
     - 使用`pcap_open()`建立嗅探会话
     - 使用`pcap_compile()`编译集成过滤规则
     - 使用`pcap_setfilter()`关联过滤器和抓包驱动
     - 使用`pcap_next_ex()`捕获链路层数据帧
     - 使用`pcap_findalldevs_ex()`获取设备链表
   - `packet_handler()`每次获取一个网卡的数据封装成消息并放进消息队列中
   - 确认控件会创建线程、并可以中止和重启线程
   - 注册`OnMessageWinPcap()`可以获取消息队列并对每个消息进行处理
     - `AppendPacket()`可以将数据包追加到缓存文件中，后面进行调用显示
     - `analysisData()`进行数据的分析，并显示在listControl控件上
     - `ShowStatisticInfo()`显示计数到控件组中

#### 问题处理

1. List Control控件加载数据出现错行问题

   > 一开始我以为是，因为多线程出现数据的不同步问题，但是通过对于analysisData函数，进行加锁的处理，并没有解决问题。后来发现是控件的绘制属性问题，如果进行绘制属性为倒序排列，则会出现每次刷新的绘制错乱问题。

2. List Control控件一直出现闪烁

   > 对控件的属性进行调整，打开控件的双缓冲即可

3. 获取的是网卡的名称编码一直乱码

   > 解决：实际获取网卡结构体中name属性是网卡的编码，网卡的型号名称应该是describtion属性

4.  "char *" 类型的实参与 "LPCTSTR" 类型的形参不兼容

   > 解决：因为编辑器默认编码是Unicode字符集，因此只需要在 **项目 - 属性** **- 常规** 中把**字符集**修改为**“未设置”**即可。后面又出现了list Control控件的时间乱码问题，需要使用Unicode字符集合，再使用其他转化函数转换其他字符集。

5. 以上记录了几个比较棘手的bugs，当然还有其他已经解决的问题···

#### 参考文档

1. C/C++ Npcap包实现数据嗅探
   https://www.cnblogs.com/LyShark/p/12989949.html)https://www.cnblogs.com/LyShark/p/12989949.html

2. WinPcap笔记（7）
   https://blog.csdn.net/u012877472/category_5949949.html?spm=1001.2014.3001.5482

3. wincap获取数据包的两种方式

   https://www.cnblogs.com/codergeek/p/3479890.html

4. mac帧结构

   https://www.cnblogs.com/cs-lcy/p/7462072.html

   http://c.biancheng.net/view/6391.html

   https://blog.csdn.net/eydwyz/article/details/65446328

5. HTTP协议详解
   https://blog.csdn.net/weixin_33594195/article/details/113078806

6. MFC+WinPcap编写一个嗅探器之零（目录）

   https://www.cnblogs.com/raichen/p/4135384.html

7. MFC教程
   https://www.bilibili.com/video/BV1JW41147NX?p=6&spm_id_from=pageDriver

8. 过滤规则

    https://blog.csdn.net/a714804968/article/details/107299742?utm_medium=distribute.pc_relevant.none-task-blog-2~default~baidujs_baidulandingword~default-0.pc_relevant_default&spm=1001.2101.3001.4242.1&utm_relevant_index=3





