#include "pcap.h"
#include <Winsock2.h>
#include <stdio.h>
#include <time.h>
#include <iostream>
#include <string>
#include <vector>

using namespace std;
#define MK_ARP_REQUEST_PKT(dstMac, srcMac, srcIP, dstIP) makeARPPkt( dstMac, srcMac, 0x0001, dstIP, srcIP)
#define MK_ARP_REPLY_PKT(dstMac, srcMac, srcIP, dstIP) makeARPPkt( dstMac, srcMac, 0x0002, dstIP, srcIP)

#pragma pack(1) //进入字节对齐方式
typedef struct FrameHeader { //帧首部
    BYTE DesMAC[6];//目的地址
    BYTE SrcMAC[6];//源地址
    WORD FrameType;//帧类型
} FrameHeader;

typedef struct IPHeader {//IP首部
    BYTE Ver_HLen;//IP协议版本和IP首部长度
    BYTE TOS;//服务类型
    WORD TotalLen;//总长度
    WORD ID;//标识
    WORD Flag_Segment;//标志+片偏移
    BYTE TTL;//生存周期
    BYTE Protocol;//协议
    WORD Checksum;//头部校验和
    DWORD SrcIP;//源IP地址
    DWORD DstIP;//目的IP地址
} IPHeader;

typedef struct ARPFrame {// ARP数据包
    WORD HardwareType;//硬件类型
    WORD ProtocolType;//协议类型
    BYTE HLen;//硬件地址长度
    BYTE PLen;//协议地址长度
    WORD Operation;//操作类型
    BYTE SourceMAC[6];//发送方MAC地址
    DWORD SourceIP;//发送方IP地址
    BYTE DstMAC[6];//接收方MAC地址
    DWORD DstIP;//接收方IP地址
} ARPFrame;

typedef struct ICMP_Ping {//ICMP请求和回送报文
    BYTE Type;//类型
    BYTE Code;//代码
    WORD Checksum;//校验和
    WORD ID;//标识符
    WORD Seq;//序列号
    BYTE Data[32];//选项数据
} ICMP_Ping;

typedef struct ICMP_Error {//ICMP超时和不可达报文
    BYTE Type;//类型
    BYTE Code;//代码
    WORD Checksum;//校验和
    BYTE Unuesd[4];//未用字段
    IPHeader ipHeader;//IP首部
    BYTE Data[8];//原始IP数据包中的数据前8字节
} ICMP_Error;

typedef struct IPPkt {//IP数据包
    FrameHeader frameheader;//以太帧首部
    IPHeader ipheader;//IP首部
} IPPkt;

typedef struct ARPPkt {//ARP数据包
    FrameHeader frameheader;//以太帧首部
    ARPFrame arpframe;//ARP帧
} ARPPkt;

typedef struct ICMPPingPkt {//ICMP请求数据包
    FrameHeader frameheader;//以太帧
    IPHeader ipheader;//IP头部
    ICMP_Ping icmpPingData;//ICMP报文
} ICMPPingPkt;

typedef struct ICMPErrorPkt {//ICMP超时和不可达数据包
    FrameHeader frameheader;//以太帧
    IPHeader ipheader;//IP头部
    ICMP_Error icmpErrorData;//ICMP报文
} ICMPErrorPkt;

#pragma pack() // 恢复默认对齐方式
class PacketList;

class Packet {
private:
    ICMPPingPkt* icmpPingPkt;//待转发的ICMP报文
    time_t sendtime;//发送时间
    bool NeedDiscard;//是否应该丢弃
    Packet* prev;//在数据包队列中的前向指针
    Packet* next;//在数据包队列中的后向指针

public:
    Packet(ICMPPingPkt* icmpPingPkt, time_t time) {
        this->icmpPingPkt = icmpPingPkt;
        this->sendtime = time;
        this->NeedDiscard = false;
        next = NULL;
    };

    ~Packet() {};

    ICMPPingPkt* getICMPPingPkt() const {
        return icmpPingPkt;
    };

    time_t getTime() const {
        return sendtime;
    };

    bool shouldDiscard() const {
        return this->NeedDiscard;
    };

    void setDiscard(bool discardState) {
        this->NeedDiscard = discardState;
    };

    Packet* getNext() {
        return next;
    };

    friend class PacketList;
};

class PacketList {
private:
    Packet* head;//数据包头
    Packet* tail;//数据包尾
    u_int size;//数据包数量

public:
    PacketList() {
        head = NULL;
        tail = NULL;
        size = 0;
    };

    ~PacketList() {
        Packet* p = head;
        while (p != NULL) {
            Packet* tmp = p;
            p = p->next;
            delete tmp;
        }
    };

    void addAfter(ICMPPingPkt* icmpPingPkt) {//
        Packet* pkt = new Packet(icmpPingPkt, time(NULL));//创建一个新的 Packet 对象
        if (head == NULL) {// 创建一个新的 Packet 对象
            head = pkt;//设置头和尾为新节点
            tail = pkt;
        }
        else {//将新节点插入到队列头部
            pkt->next = head;
            head->prev = pkt;
            head = pkt;
        }
        size++;//增加队列大小
    };

    Packet* delPacket(Packet* packet) {//// 删除指定的报文节点并返回下一个节点
        Packet* ret; //用于保存下一个节点的指针
        ret = packet->next;//获取下一个节点的指针
        if (packet == head) {//如果要删除的节点是头节点
            head = packet->next;
            if (head != NULL) {//如果队列非空
                head->prev = NULL;//更新新头节点的前向指针
            }
        }
        else if (packet == tail) {//如果要删除的节点是尾节点
            tail = packet->prev;
            if (tail != NULL) {
                tail->next = NULL;
            }
        }
        else {//如果要删除的节点在队列中间
            packet->prev->next = packet->next;
            packet->next->prev = packet->prev;
        }
        delete packet;// 释放当前节点的内存
        size--;// 减小队列大小
        return ret;//返回下一个节点的指针
    };

    Packet* getHead() const {
        return head;
    };

    u_int getSize() const {
        return size;
    };
};

string b2s(DWORD addr) {
    char addrStr[16] = { 0 };
    sprintf(addrStr, "%d.%d.%d.%d", addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF, (addr >> 24) & 0xFF);
    return string(addrStr);
}

string b2s(BYTE* mac) {
    char macStr[18] = { 0 };
    sprintf(macStr, "%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return string(macStr);
}

string v2s(int value) {
    char valueStr[10] = { 0 };
    sprintf(valueStr, "%d", value);
    return string(valueStr);
}

string v2s(u_int value) {
    char valueStr[10] = { 0 };
    sprintf(valueStr, "%d", value);
    return string(valueStr);
}

string t2s(time_t time) {
    char timeStr[20] = { 0 };
    strftime(timeStr, 20, "%H:%M:%S", localtime(&time));
    return string(timeStr);
}

string recvLog(WORD frametype, DWORD srcIP, BYTE* srcMac, DWORD dstIP, BYTE* dstMac, int TTL) {
    string str = "";
    string temp;
    switch (ntohs(frametype)) {
    case 0x0806://ARP报文
        str += " 【Recv】接收到ARP数据包: \nSrcIP           SrcMac            DstIP           DstMac            TTL\n";
    case 0x0800://IP报文
        str += " 【Recv】接收到IP数据包: \nSrcIP           SrcMac            DstIP           DstMac            TTL\n";
    }
    temp = b2s(srcIP); temp.resize(16, ' '); str += temp;
    temp = b2s(srcMac); temp.resize(18, ' '); str += temp;
    temp = b2s(dstIP); temp.resize(16, ' '); str += temp;
    temp = b2s(dstMac); temp.resize(18, ' '); str += temp;
    temp = v2s(TTL); str += temp;
    return str;
}

string fwrdLog(WORD frametype, DWORD srcIP, BYTE* srcMac, DWORD dstIP, DWORD NextHop,BYTE* dstMac, int TTL, bool nextHop) {
    string str = "";
    string temp;
    switch (ntohs(frametype)) {
    case 0x0806://ARP报文
        str += " 【Send】转发ARP数据包: \n";
    case 0x0800:
        str += " 【Send】转发IP数据包: \n";
    }
    if (nextHop) {
        str += "NextHop           SrcMac            DstIP           NextHop         DstMac            TTL\n";
    }
    else {
        str += "SrcIP           SrcMac            DstIP           NextHop         DstMac            TTL\n";
    }
    temp = b2s(srcIP); temp.resize(16, ' '); str += temp;
    temp = b2s(srcMac); temp.resize(18, ' '); str += temp;
    temp = b2s(dstIP); temp.resize(16, ' '); str += temp;
    temp = b2s(NextHop); temp.resize(16, ' '); str += temp;
    temp = b2s(dstMac); temp.resize(18, ' '); str += temp;
    temp = v2s(TTL); str += temp;
    return str;
};

bool CmpMAC(BYTE* mac1, BYTE* mac2) {// 比较两个MAC地址是否相等
    if (mac2 == NULL) {// 如果第二个MAC地址为空，与全零地址比较
        return memcmp(mac1, "\0\0\0\0\0\0", 6) == 0;
    }
    else {// 否则，比较两个MAC地址是否相等
        return memcmp(mac1, mac2, 6) == 0;
    }
}

ARPPkt* makeARPPkt(u_char* dstMac, u_char* srcMac, WORD operation, DWORD dstIP, DWORD srcIP) {
    ARPPkt* pkt = new ARPPkt;
    memcpy(pkt->frameheader.DesMAC, dstMac, 6);//设置以太帧中的目的MAC
    memcpy(pkt->frameheader.SrcMAC, srcMac, 6);//设置以太帧中的源MAC
    pkt->frameheader.FrameType = htons(0x0806);//以太帧的类型设置为806h
    pkt->arpframe.HardwareType = htons(0x0001);//以太网的接口类型为1
    pkt->arpframe.ProtocolType = htons(0x0800);//高层的协议类型是IPV4
    pkt->arpframe.HLen = 6;//以太网中的物理地址即MAC地址，长度为6B
    pkt->arpframe.PLen = 4;//上层协议地址长度即IP地址长度为4B
    pkt->arpframe.Operation = htons(operation);//ARP 请求为 1，ARP 响应为 2
    memcpy(pkt->arpframe.SourceMAC, srcMac, 6);//设置源MAC
    pkt->arpframe.SourceIP = srcIP;//设置源IP
    memcpy(pkt->arpframe.DstMAC, dstMac, 6);//设置目的MAC
    pkt->arpframe.DstIP = dstIP;//设置目的IP
    return pkt;
};

bool isARPPkt(const u_char* pktData) {
    return ntohs(((ARPPkt*)pktData)->frameheader.FrameType) == 0x0806;
};

bool isIPPkt(const u_char* pktData) {
    return ntohs(((ARPPkt*)pktData)->frameheader.FrameType) == 0x0800;
};

u_short IPChecksum(u_short* pktData, int len) {
    u_long sum;
    u_short bac;
    u_short* ori;
    sum = 0;
    bac = ((IPPkt*)pktData)->ipheader.Checksum;
    ori = pktData;
    ((IPPkt*)pktData)->ipheader.Checksum = 0;
    pktData = (u_short*)&(((IPPkt*)pktData)->ipheader);
    len -= sizeof(FrameHeader);
    while (len > 1) {
        sum += *pktData++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(u_char*)pktData;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    pktData = ori;
    ((IPPkt*)pktData)->ipheader.Checksum = bac;
    return (u_short)(~sum);
};

u_short ICMPChecksum(u_short* pktData, int len) {
    u_long sum; // 用于保存校验和的累加值
    u_short bac;// 保存原始的ICMP数据的校验和
    u_short* ori;// 保存原始的数据指针

    sum = 0; // 初始化累加值为0
    bac = ((ICMPPingPkt*)pktData)->icmpPingData.Checksum;  // 保存原始ICMP数据的校验和
    ori = pktData;// 保存原始的数据指针
    ((ICMPPingPkt*)pktData)->icmpPingData.Checksum = 0;    // 将ICMP数据的校验和字段置为0
    pktData = (u_short*)&((ICMPPingPkt*)pktData)->ipheader; // 转换数据指针到IP头部之后的位置
    len -= sizeof(FrameHeader);// 减去FrameHeader的大小，以确保只处理有效数据
    while (len > 1) { // 循环处理16位的字，直到不足两个字节
        sum += *pktData++;  // 将16位字累加到校验和中
        len -= 2;// 减去已处理的16位字的长度
    }
    if (len == 1) {// 如果数据长度是奇数，处理最后一个字节
        sum += *(u_char*)pktData;
    }
    sum = (sum >> 16) + (sum & 0xffff); // 将高16位与低16位相加
    sum += (sum >> 16);  // 将可能的溢出加到结果中
    pktData = ori;// 恢复原始的数据指针
    ((ICMPPingPkt*)pktData)->icmpPingData.Checksum = bac;  // 恢复原始ICMP数据的校验和
    return (u_short)(~sum);// 返回校验和的反码
};


bool isICMPCorrupted(u_short* pktData, int len) {
    u_long sum;// 用于保存校验和的累加值
    sum = 0;// 初始化累加值为0
    pktData = (u_short*)&((ICMPPingPkt*)pktData)->ipheader;  // 转换数据指针到IP头部之后的位置
    len -= sizeof(FrameHeader);        // 减去FrameHeader的大小，以确保只处理有效数据
    while (len > 1) { // 循环处理16位的字，直到不足两个字节
        sum += *pktData++;// 将16位字累加到校验和中
        len -= 2; // 减去已处理的16位字的长度
    }
    if (len == 1) { // 如果数据长度是奇数，处理最后一个字节
        sum += *(u_char*)pktData;
    }
    sum = (sum >> 16) + (sum & 0xffff); // 将高16位与低16位相加
    sum += (sum >> 16); // 将可能的溢出加到结果中
    if (sum != 0xffff) {// 如果计算得到的校验和不是0xffff
        cout << " 【ERR】 ICMP报文校验和错误" << endl;  // 输出错误信息
    }
    return sum != 0xffff;// 返回校验和是否等于0xffff的结果
};


void setICMPChecksum(u_short* pktData) {
    ((IPPkt*)pktData)->ipheader.Checksum = IPChecksum(pktData, sizeof(IPPkt));
    ((ICMPPingPkt*)pktData)->icmpPingData.Checksum = ICMPChecksum(pktData, sizeof(ICMPPingPkt));
}

class Adapter {
private:
    string Name;// 设备名称
    string Description; // 设备描述
    DWORD IP[2]; // 含有两个IP地址的IP数组
    DWORD Mask[2];// 含有两个子网掩码的掩码数组
    BYTE Mac[6];// MAC地址

    friend class AdapteManager;

public:
    Adapter() {
        Name = "";
        Description = "";
        IP[0] = 0;
        IP[1] = 0;
        Mask[0] = 0;
        Mask[1] = 0;
        memset(Mac, 0, 6);
    };

    ~Adapter() {};

    DWORD getIP(u_int idx = 0) {
        if (idx < 2) {
            if (Mask[idx] == DWORD(0)) {
                cout << "【ERR】 获取网卡IP错误: IP地址[" << idx << "] 未被设置" << endl;
            }
        }
        else {
            cout << "【ERR】 获取网卡信息错误:  子网掩码下标超出范围" << endl;
            exit(1);
        }
        return IP[idx];
    };

    DWORD getMask(u_int idx = 0) {
        if (idx < 2) {
            if (Mask[idx] == 0) {
                cout << "【ERR】 获取网卡子网掩码错误: 掩码[" << idx << "] 未被设置" << endl;
            }
        }
        else {
            cout << "【ERR】 获取网卡子网掩码错误:  子网掩码" << idx << " 超出范围" << endl;
            exit(1);
        }
        return Mask[idx];
    };

    BYTE* getMac() {
        BYTE temp[6];
        memset(temp, 0, 6);
        if (memcmp(Mac, temp, 6) == 0) {
            cout << "【ERR】 获取网卡MAC错误:  MAC尚未获取" << endl;
            return NULL;
        }
        return Mac;
    };

    string toStr() {
        string str = "";
        str += "设备名称: " + Name + "\n描述信息: " + Description;
        if (Mask[0] != 0) {
            if (Mask[1] != 0) {//如果有两个IP地址
                str += "\nIP地址1: " + b2s(IP[0]) + "\t网络掩码: " + b2s(Mask[0])
                    + "\nIP地址12: " + b2s(IP[1]) + "\t网络掩码: " + b2s(Mask[1]);
            }
            else {//一个IP地址
                str += "\nIP地址1: " + b2s(IP[0]) + "\t网络掩码: " + b2s(Mask[0]);
            }
        }
        if (memcmp(Mac, "\0\0\0\0\0\0", 6) != 0) {//如果有MAC地址
            str += "\nMAC地址: " + b2s(Mac);
        }
        return str;
    };
};

class AdapteManager {
private:
    u_int AdapterNumber;//本地网卡设备的数量
    Adapter* AdapterList;//存放网卡设备指针的数组
    Adapter* OpenAdapter;//存放用户选取的网卡设备指针
    pcap_t* OpenHandle;//存放打开网卡设备后的指向pcap_t结构体的指针
    char errbuf[PCAP_ERRBUF_SIZE];//错误缓冲区

public:
    AdapteManager() {
        AdapterNumber = 0;
        AdapterList = NULL;
        OpenAdapter = NULL;
        OpenHandle = NULL;
    };

    ~AdapteManager() {
        if (AdapterList != NULL) {
            delete[] AdapterList;
        }
    };

    u_int GetAdapterNumber() {
        return AdapterNumber;
    };

    Adapter* getOpenAdapter() {
        return OpenAdapter;
    };

    pcap_t* getOpenHandle() {
        return OpenHandle;
    };

    string toStr() {
        string str = "";
        u_int i;
        if (AdapterNumber == 0) {
            str += "【ERR】暂未获取到可用设备";
        }
        else {
            str += "设备序号：: " + v2s(AdapterNumber) + "\n";
            for (i = 0; i < AdapterNumber; i++) {
                str += "设备 " + v2s(u_int(i + 1)) + ":\n" + AdapterList[i].toStr() + "\n";
            }
        }
        return str;
    };

    void FindAllDevs() {// 查找所有网卡,获取设备信息
        pcap_if_t* alldevs;//设备列表的指针
        pcap_if_t* d;//用于遍历设备列表的拷贝指针
        int i, j;
        pcap_addr_t* a;
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {  // 获取本机所有网卡列表
            cout << "【ERR】 查找本地设备失败，请查看错误原因： " << errbuf << endl;
            pcap_freealldevs(alldevs);
            exit(1);
        }
        for (d = alldevs; d != NULL; d = d->next) { // 获取网卡的数量
            AdapterNumber++;
        }
        if (AdapterNumber == 0) {
            cout << "【ERR】 当前主机没有可用的网卡设备！" << endl;
            exit(1);
        }
        AdapterList = new Adapter[AdapterNumber];//存放网卡设备指针的数组
        for (i = 0, d = alldevs; d != NULL; d = d->next, i++) { // 获取设备名和描述，i用于遍历网卡设备
            AdapterList[i].Name = string(d->name);//获取网卡名称
            AdapterList[i].Description = string(d->description);//获取网卡描述信息
            for (j = 0, a = d->addresses; j < 2 && a != NULL; a = a->next) {    // 获取设备IP地址,j用于遍历双网卡设备的两个IP
                if (a->addr->sa_family == AF_INET) {//如果是IPv4地址
                    AdapterList[i].IP[j] = inet_addr(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));//存储在Adapter的IP数组中
                    AdapterList[i].Mask[j] = inet_addr(inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));//存储在Adapter的Mask数组中
                    j++;//查找下一个IP地址
                }
            }
        }
        pcap_freealldevs(alldevs);
        cout << "【SUC】 获取本地设备成功！设备信息如下： " << endl;
        cout << toStr() << endl;
    };

    void SelectUserAdapter() {// 选择并打开网卡
        u_int userchoice;
        cout << "【CMD】 请选择本次实验中需要打开的网卡: ";
        cin >> userchoice;
        if (userchoice < 1 || userchoice > AdapterNumber) {//如果用户输入的编号不在正常范围内
            cout << "【ERR】 您选择的网卡不正确，即将退出程序" << endl;
            exit(1);
        }
        userchoice--;//获取数组下标
        OpenAdapter = &AdapterList[userchoice];//获取用户选取的网卡设备的指针
        if ((OpenHandle = pcap_open(OpenAdapter->Name.c_str(), 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) ==
            NULL) { // 打开网卡
            cout << "【ERR】 您选择的网卡不正确，请查看错误信息： " << errbuf << endl;
            exit(1);
        }
        if (pcap_datalink(OpenHandle) != DLT_EN10MB) { // 判断网卡是否为以太网适用
            cout << "【ERR】 您选择的网卡不能够使用以太网，即将退出程序" << endl;
            exit(1);
        }
        if (pcap_setnonblock(OpenHandle, 1, errbuf) == -1) { // 设置网卡为非阻塞模式
            cout << "【ERR】 您选择的网卡无法设置为非阻塞模式，请查看错误信息： " << errbuf << endl;
            exit(1);
        }
        cout << "【SUC】 成功打开您选择的网卡！" << endl;
    };

    void SetMac(BYTE* Mac, Adapter* adapter) {// 设置特定设备MAC地址
        if (Mac == NULL) {
            cout << "【ERR】 设置MAC地址失败，错误原因：传入的MAC地址为空" << endl;
            return;
        }
        if (adapter == NULL) {
            cout << "【ERR】 设置MAC地址失败，错误原因：要设置的设备为空" << endl;
        }
        if (adapter->getMac() != NULL) {
            cout << "【ERR】 设置MAC地址失败，错误原因：设备已有MAC地址" << endl;
            return;
        }
        memcpy(adapter->Mac, Mac, 6);
    };

    DWORD CheckDirectByIP(DWORD IP) {// 根据IP地址，查看是否在同一网段，并返回对应接口IP地址
        if (OpenAdapter == NULL) {
            cout << "【ERR】 判断直连失败：打开的网卡设备无效" << endl;
            return 0;
        }
        if (OpenHandle == NULL) {
            cout << "【ERR】 判断直连失败：打开的网卡设备无效" << endl;
            return 0;
        }
        if ((IP & OpenAdapter->Mask[0]) == (OpenAdapter->IP[0] & OpenAdapter->Mask[0])) {
            return OpenAdapter->IP[0];
        }
        if ((IP & OpenAdapter->Mask[1]) == (OpenAdapter->IP[1] & OpenAdapter->Mask[1])) {
            return OpenAdapter->IP[1];
        }
        return 0;
    };
};

class ARPTable;  // ARP表

class ARPEntry {
private:
    DWORD IP;// IP地址
    BYTE Mac[6];// MAC地址
    time_t time;// 最近一次更新时间
    ARPEntry* prev;//在ARP表项连接中的前向指针
    ARPEntry* next;//在ARP表项连接中的后向指针
    friend class ARPTable;

public:
    ARPEntry(DWORD ip, BYTE* mac, time_t time) {
        this->IP = ip;
        memcpy(this->Mac, mac, 6);
        this->time = time;
        this->prev = NULL;
        this->next = NULL;
    };

    ~ARPEntry() {};

    BYTE* getMac() {
        if (memcmp(Mac, "\0\0\0\0\0\0", 6) == 0) {
            cout << "【ERR】获取ARP表中的MAC地址失败，错误原因：MAC地址未设置" << endl;
            return NULL;
        }
        return Mac;
    };

    string toStr(bool showAttr = true) {
        string str = "";
        string temp;
        if (showAttr) {
            str += "IP地址      MAC地址       上一次更新时间\n";
        }
        temp = b2s(IP); temp.resize(16, ' '); str += temp;
        temp = b2s(Mac); temp.resize(18, ' '); str += temp;
        temp = t2s(time);  str += temp;
        return str;
    };

    ARPEntry* getNext() {
        return this->next;
    }
};

class ARPTable {
private:
    ARPEntry* head;//第一个表项的指针
    ARPEntry* tail;//最后一个表项的指针
    u_int Size;//ARP表中的表项个数
    u_int entryLifetime;//表项的老化时间

public:

    ARPTable() {
        this->head = NULL;
        this->tail = NULL;
        this->Size = 0;
        this->entryLifetime = 300;
    };

    ~ARPTable() {
        ARPEntry* arpEntry;
        arpEntry = head;
        while (arpEntry != NULL) {
            ARPEntry* next = arpEntry->next;
            delete arpEntry;
            arpEntry = next;
        }
    };

    void AddARPEntry(DWORD IP, BYTE* Mac) {
        ARPEntry* arpEntry;
        if (lookupARPEntry(IP) != NULL) {//如果ARP中已经存在该IP地址与MAC的映射关系
            return;//无须增加
        }
        arpEntry = new ARPEntry(IP, Mac, time(NULL));
        cout << "【Sys】增加ARP表项: " << arpEntry->toStr(false) << endl;
        if (head == NULL) {//如果这个表项是ARP表中的第一个
            head = arpEntry;//头和尾都指向这个ARP表项
            tail = arpEntry;
        }
        else {//如果前面有表项，就在增加在最后
            tail->next = arpEntry;//最后一个表项的后向指针指向新插入的 ARP表项
            arpEntry->prev = tail;//建立插入的ARP表项的前向指针
            tail = arpEntry;//更新尾指针
        }
        Size++;//更新ARP表中的大小
    };

    void DeleteARPEntry(ARPEntry* arpEntry) {
        cout << " 【Sys】删除ARP表项:  " << arpEntry->toStr(false) << endl;
        if (arpEntry->prev == NULL) {//如果要删除的ARP表项前面没有指针，说明是第一个表项
            head = arpEntry->next;//更新头指针
        }
        else {//将前面表项的后向指针指向后一个
            arpEntry->prev->next = arpEntry->next;
        }
        if (arpEntry->next == NULL) {//如果要删除的ARP表项后面没有指针，说明是最后一个表项
            tail = arpEntry->prev;//更新尾指针
        }
        else {//将后面表项的前向指针指向前一个
            arpEntry->next->prev = arpEntry->prev;
        }
        delete arpEntry;//删除该ARP表项
        Size--;//AEP表中的表项数量减一
    };

    ARPEntry* lookupARPEntry(DWORD IP) {
        ARPEntry* arpEntry;
        arpEntry = head;//拷贝ARP表项的头指针
        while (arpEntry != NULL) {//遍历ARP表中的表项
            if (arpEntry->IP == IP) {//如果找到了要查找的IP表项
                return arpEntry;//返回ARP表项指针
            }
            arpEntry = arpEntry->next;//继续遍历下一个
        }
        return NULL;
    };

    bool isExpired(ARPEntry* arpEntry) {
        return u_int(time(NULL) - arpEntry->time) > this->entryLifetime;
    };

    ARPEntry* getHead() {
        return this->head;
    }


    string toStr() {
        string str = "";
        ARPEntry* arpEntry;
        if (Size == 0) {
            str += "ARP表：空";
            return str;
        }
        str += "ARP表: \nIP地址     MAC地址      上一次更新时间\n";
        arpEntry = head;
        while (arpEntry != NULL) {
            str += arpEntry->toStr(false) + "\n";
            arpEntry = arpEntry->next;
        }
        return str;
    };
};

class RouteTable;

class RouteEntry {
private:
    DWORD Destination;// 目的地址
    DWORD MASK; // 子网掩码
    DWORD NextHop;// 下一跳地址
    DWORD Interfence;// 端口
    RouteEntry* prev;//连接路由器表项的前向指针
    RouteEntry* next;//连接路由器表项的后向指针

    friend class RouteTable;

public:
    RouteEntry(DWORD dest, DWORD netmask, DWORD gw, DWORD itf) {
        this->Destination = dest;
        this->MASK = netmask;
        this->NextHop = gw;
        this->Interfence = itf;
        this->prev = NULL;
        this->next = NULL;
    };

    ~RouteEntry() {};

    DWORD getNextHop() {
        return this->NextHop;
    };

    string toStr(bool showAttr = true) {
        string str = "";
        string temp;
        if (showAttr) {
            str += "目的地址     子网掩码        下一跳         端口\n";
        }         //255.255.255.255 255.255.255.255 255.255.255.255 255.255.255.255
        temp = b2s(this->Destination);  temp.resize(16, ' ');  str += temp;
        temp = b2s(this->MASK);  temp.resize(16, ' ');  str += temp;
        temp = b2s(this->NextHop);  temp.resize(16, ' ');  str += temp;
        temp = b2s(this->Interfence);  str += temp;
        return str;
    };
};

class RouteTable {
private:
    Adapter* OpenAdapter;//打开的网卡
    RouteEntry* head;//路由表项中的第一个
    RouteEntry* tail;//路由表中的最后一项
    u_int Size;//路由表的大小

public:
    RouteTable(Adapter* OpenAdapter) {
        this->OpenAdapter = OpenAdapter;
        this->head = NULL;
        this->tail = NULL;
        this->Size = 0;
    };

    ~RouteTable() {
        RouteEntry* routingEntry;
        routingEntry = this->head;
        while (routingEntry != NULL) {
            RouteEntry* next = routingEntry->next;
            delete routingEntry;
            routingEntry = next;
        }
    };

    void addRouteEntry(DWORD dest, DWORD netmask, DWORD nexthop) {
        RouteEntry* theRouteEntry;// 要添加的路由表项指针
        DWORD theInterfence;//转发的端口

        if ((theRouteEntry = lookupRouteEntry(dest)) != NULL && (theRouteEntry->MASK != 0)) {
            return;//如果路由表中已经有这一项，就不需要添加了
        }
        switch (netmask) {
        case 0:
            if ((OpenAdapter->getIP(0) & OpenAdapter->getMask(0)) == (nexthop & OpenAdapter->getMask(0))) {
                theInterfence = OpenAdapter->getIP(0);// 判断 NextHop 是否与第一个接口的子网匹配
            }
            else if ((OpenAdapter->getIP(1) & OpenAdapter->getMask(1)) == (nexthop & OpenAdapter->getMask(1))) {
                theInterfence = OpenAdapter->getIP(1);// 判断 NextHop 是否与第二个接口的子网匹配
            }
            else {
                cout << " 【ERR】添加默认路由表项失败：下一跳不可达" << endl;
                return;
            }
            theRouteEntry = new RouteEntry(0, 0, nexthop, theInterfence);
            break;
        default:
            if ((OpenAdapter->getIP(0) & OpenAdapter->getMask(0)) == (nexthop & OpenAdapter->getMask(0))) {
                theInterfence = OpenAdapter->getIP(0);// 判断 NextHop 是否与第一个接口的子网匹配
            }
            else if ((OpenAdapter->getIP(1) & OpenAdapter->getMask(1)) == (nexthop & OpenAdapter->getMask(1))) {
                theInterfence = OpenAdapter->getIP(1);// 判断 NextHop 是否与第二个接口的子网匹配
            }
            else {
                cout << " 【ERR】添加路由表项失败：端口不直连" << endl;
                return;
            }
            theRouteEntry = new RouteEntry(dest & netmask, netmask, nexthop, theInterfence);
        }

        if (head == NULL) {//如果路由表中为空
            head = tail = theRouteEntry;//新建一个，头指针和尾指针都指向这个新添加的表项
        }
        else {
            tail->next = theRouteEntry;//在末尾添加
            theRouteEntry->prev = tail;
            tail = theRouteEntry;
        }
        Size++;
        cout << " 【SYS】添加路由表项： " << theRouteEntry->toStr(false) << endl;
    };

    void addRouteEntry(const char* dest, const char* netmask, const char* nexthop) {
        addRouteEntry(inet_addr(dest), inet_addr(netmask), inet_addr(nexthop));
    };

    void DeleteRouteEntry(RouteEntry* routingEntry) {
        if (routingEntry == NULL) {
            cout << " 【ERR】删除路由表项失败：未找到需要删除的路由表项" << endl;
            return;
        }
        if (Size == 0) {
            cout << " 【ERR】删除路由表项失败：路由表为空" << endl;
            return;
        }
        cout << "【SUC】成功删除路由表项： " << routingEntry->toStr(false) << endl;
        if (routingEntry->prev == NULL) {
            head = routingEntry->next;
        }
        else {
            routingEntry->prev->next = routingEntry->next;
        }
        if (routingEntry->next == NULL) {
            tail = routingEntry->prev;
        }
        else {
            routingEntry->next->prev = routingEntry->prev;
        }
        delete routingEntry;
        Size--;
    };

    RouteEntry* lookupRouteEntry(DWORD dest) {
        RouteEntry* routeEntry;
        RouteEntry* candidate;
        DWORD maxPrefixNetmask;

        routeEntry = head;
        if (routeEntry == NULL) {
            cout << " 【ERR】查找路由表项失败：路由表为空" << endl;
            return NULL;
        }
        candidate = NULL; // 初始化候选项为NULL
        maxPrefixNetmask = head->MASK;// 初始化最大前缀掩码为第一个路由表项的掩码
        while (routeEntry != NULL) {
            if ((routeEntry->Destination & routeEntry->MASK) == (dest & routeEntry->MASK)) {// 判断当前路由表项的目的网络是否与目标地址的网络相匹配
                if (ntohl(routeEntry->MASK) > ntohl(maxPrefixNetmask)) { //比较前缀掩码大小
                    maxPrefixNetmask = routeEntry->MASK;// 如果当前掩码更大，更新最大前缀掩码和候选项
                    candidate = routeEntry;
                }
                candidate = routeEntry;// 更新候选项为当前路由表项
            }
            routeEntry = routeEntry->next;// 移动到下一个路由表项
        }
        if (candidate == NULL) {
            cout << "【ERR】查找路由表项失败：路由表中不存在该项" << endl;
        }
        return candidate;
    };

    string toStr() {
        string str = "";
        RouteEntry* therouteEntry;

        therouteEntry = head;
        if (therouteEntry == NULL) {
            str += "路由表：空";
        }
        else {
            str += "路由表: \n目的地址     子网掩码         下一跳         端口\n";
            while (therouteEntry != NULL) {
                str += therouteEntry->toStr(false) + "\n";
                therouteEntry = therouteEntry->next;
            }
        }
        return str;
    };
};

class Router {
private:
    AdapteManager* adaptermanager;
    ARPTable* arpTable;
    RouteTable* routetable;
    PacketList* pktBuf;
    u_int pktLifetime;
    char errbuf[PCAP_ERRBUF_SIZE];
    HANDLE sendthread;
    HANDLE recvthread;
    CRITICAL_SECTION PacketMutex;
    CRITICAL_SECTION ARPMutex;

    BYTE* getOpenDeviceMac(Adapter* device) { //获取网卡设备的MAC地址
        BYTE DstMac[6], SrcMac[6];//源MAC和目的MAC
        DWORD DstIP, SrcIP;//源IP和目的IP
        ARPPkt* BroadcastARP;//广播ARP
        ARPPkt* ReplyARP;//接收到的回复ARP
        int result;
        struct pcap_pkthdr* header;
        const u_char* pktData;

        if (device == NULL) {
            cout << "【ERR】获取网卡设备MAC错误：设备无效" << endl;
            return NULL;
        }
        if (device->getMac() != NULL) { // 如果已经获取过MAC地址就直接读取
            return device->getMac();
        }

        memset(DstMac, 0xff, 6);// 目的MAC地址为广播地址
        memset(SrcMac, 0x00, 6);// 源MAC地址为0
        DstIP = adaptermanager->getOpenAdapter()->getIP(0);            // 目的IP地址为网卡IP地址
        SrcIP = inet_addr("111.111.111.111");                        // 伪造源IP地址
        BroadcastARP = MK_ARP_REQUEST_PKT(DstMac, SrcMac, SrcIP, DstIP);     // 虚构地址的ARP请求数据包
        if (pcap_sendpacket(adaptermanager->getOpenHandle(), (u_char*)BroadcastARP, sizeof(ARPPkt)) != 0) {
            cout << "【ERR】 获取网卡设备MAC错误： 无法发送广播ARP报文，具体错误信息： " << pcap_geterr(adaptermanager->getOpenHandle()) << endl;
            exit(1);
        }
        while ((result = pcap_next_ex(adaptermanager->getOpenHandle(), &header, &pktData)) >= 0) {//持续监听数据包
            if (result == 0)//超时就继续等待
                continue;
            ReplyARP = (ARPPkt*)pktData;//收到一个数据包
            if (ntohs(ReplyARP->frameheader.FrameType) == 0x0806 && ntohs(ReplyARP->arpframe.Operation) == 0x0002 && ReplyARP->arpframe.DstIP == SrcIP &&
                ReplyARP->arpframe.SourceIP == DstIP) {//检查是否是ARP类型，并且源和目的IP正确
                cout << "【SYS】 成功接受来自 " << ReplyARP->arpframe.SourceIP << "的ARP回复报文！" << endl;
                adaptermanager->SetMac(ReplyARP->frameheader.SrcMAC, device);//将报文中的MAC地址复制到网卡结构体中
                break;
            }
        }
        if (result == -1) {//如果接受错误
            cout << "【ERR】 获取网卡设备MAC错误： 监听ARP回复报文错误，具体错误信息 " << pcap_geterr(adaptermanager->getOpenHandle()) << endl;
            exit(-1);
        }
        cout << "【SUC】获取网卡设备MAC成功！更新设备信息 :" << endl;
        cout << adaptermanager->getOpenAdapter()->toStr() << endl;
        return device->getMac();
    };

    void PrintHelp() {
        cout << "=========================================================\n";
        cout << "【CMD】控制台线程开启！持续监听控制台命令，以下是正确的命令格式\n";
        cout << "---------------------------------------------------------\n";
        cout << "路由表相关:\n";
        cout << "route  add     [destination] mask [subnetMast] [gateway]\n";
        cout << "route  delete  [destination]\n";
        cout << "route  print\n";
        cout << "---------------------------------------------------------\n";
        cout << "ARP表相关:\n";
        cout << "arp    -a\n";
        cout << "=========================================================\n";
        cout << "【CMD】 请在控制台上输入您的命令: " << endl;
    }

    void parseCmd(char* cmd) {
        char* p;// 用于分割命令字符串的指针
        vector<string> cmdVec;// 存储分割后的命令参数的字符串向量
        if (string(cmd) == "") {
            cout << "【CMD】 没有读取有效的指令!" << endl;
            return;
        }
        p = strtok(cmd, " ");// 使用strtok函数按空格分割命令字符串，并将结果存储在cmdVec中
        do {
            cmdVec.push_back(string(p));
        } while ((p = strtok(NULL, " ")) != NULL);
        if (cmdVec[0] == "route") {// 处理"route"命令
            if (cmdVec[1] == "add") {// 添加路由表项
                routetable->addRouteEntry(cmdVec[2].c_str(), cmdVec[4].c_str(), cmdVec[5].c_str());
            }
            if (cmdVec[1] == "delete") {// 删除路由表项
                if (cmdVec[2] == "0.0.0.0") {
                    cout << "【ERR】 不能删除默认路由表项!" << endl;
                    return;
                }
                routetable->DeleteRouteEntry(routetable->lookupRouteEntry(inet_addr(cmdVec[2].c_str())));
            }
            if (cmdVec[1] == "change") {  // 先删除再添加路由表项，实现修改
                routetable->DeleteRouteEntry(routetable->lookupRouteEntry(inet_addr(cmdVec[2].c_str())));
                routetable->addRouteEntry(cmdVec[2].c_str(), cmdVec[4].c_str(), cmdVec[5].c_str());
            }
            if (cmdVec[1] == "print") { // 输出路由表内容
                cout << routetable->toStr() << endl;
            }
        }
        if (cmdVec[0] == "arp") {// 处理"arp"命令
            if (cmdVec[1] == "-a") {// 输出ARP表内容
                cout << arpTable->toStr() << endl;
            }
        }
    }

    void cmdThrd() {// 主控线程
        char cmd[50];
        cin.ignore();
        while (true) {
            cout << "【CMD】 请在控制台上输入您的命令: " << endl;
            cin.getline(cmd, 50);
            parseCmd(cmd);
        }
    };

    bool bcstARPReq(DWORD ip) {// 广播ARP请求，默认不找自己
        BYTE DstMac[6], SrcMac[6];//源MAC和目的MAC
        DWORD DstIP, SrcIP;//源IP和目的IP
        ARPPkt* BroadcastARP;//广播ARP
        if (ip == 0) {// 检查目标IP是否为0
            cout << "【ERR】 广播ARP失败：目的IP无效" << endl;
            return false;
        }
        if (adaptermanager->getOpenAdapter() == NULL) {// 检查网络适配器是否存在
            cout << "【ERR】 广播ARP失败：打开的网卡失效" << endl;
            return false;
        }
        if ((SrcIP = adaptermanager->CheckDirectByIP(ip)) == 0) {// 不发送跨网段的ARP
            cout << "【ERR】 广播ARP失败：打开的网卡失效" << endl;
            return false;
        }
        memset(DstMac, 0xff, 6);// 初始化目的MAC为全1（广播地址）
        memcpy(SrcMac, adaptermanager->getOpenAdapter()->getMac(), 6);//初始源MAC为当前网络适配器的MAC地址
        DstIP = ip;//初始化目的IP
        BroadcastARP = MK_ARP_REQUEST_PKT(DstMac, SrcMac, SrcIP, DstIP);// 构建广播ARP请求包
        if (pcap_sendpacket(adaptermanager->getOpenHandle(), (u_char*)BroadcastARP, sizeof(ARPPkt)) != 0) {
            cout << "【ERR】  广播ARP失败：发送ARP报文失败，错误原因： " << pcap_geterr(adaptermanager->getOpenHandle()) << endl;
            return false;
        }
        cout << "【SUC】 广播ARP成功！ 请求IP地址为" << b2s(ip) << " 的MAC地址" << endl;
        return true;
    };

    void forward(ICMPPingPkt* pkt, BYTE* dstMac) {//
        if (pkt == NULL) {//如果数据包为空
            cout << "【ERR】 转发数据包错误：转发的数据报是无效数据包" << endl;
            return;
        }
        if (dstMac == NULL) {//如果数据包不为空
            cout << "【ERR】 转发数据包错误: 目的MAC为空" << endl;
            return;
        }
        memcpy(pkt->frameheader.SrcMAC, adaptermanager->getOpenAdapter()->getMac(), 6);//修改数据包中的源地址为网卡的MAC地址
        memcpy(pkt->frameheader.DesMAC, dstMac, 6);//修改数据包中的目的MAC地址
        pkt->ipheader.TTL--;//报文生存期-1
        setICMPChecksum((u_short*)pkt);
        if (pcap_sendpacket(adaptermanager->getOpenHandle(), (u_char*)pkt, sizeof(ICMPPingPkt)) != 0) {
            cout << "【ERR】转发数据包错误:  转发函数调用失败，具体错误原因: " << pcap_geterr(adaptermanager->getOpenHandle()) << endl;
            exit(1);
        }
    };   // 转发数据包

    static DWORD WINAPI SendThread(LPVOID lpParam) { // 转发线程函数
        cout << "【SYS】 转发线程开启！\n";
        Router* router;
        Packet* pkt;
        router = (Router*)lpParam;
        while (true) {
            EnterCriticalSection(&router->getPacketMutex());//开启进入互斥量
            pkt = router->getPktBuf()->getHead();//获取当前数据包列表中的第一个数据包
            while (pkt != NULL) {//遍历所有数据包
                if (pkt->shouldDiscard()) {//如果数据包需要丢弃
                    pkt = router->getPktBuf()->delPacket(pkt);//从队列中删除这个数据包
                }
                else {
                    pkt = pkt->getNext();//获取最开始的数据包
                }
            }
            pkt = router->getPktBuf()->getHead();//删除所有该丢弃的数据包后，回到数据包列表第一个
            if (pkt == NULL) {//如果数据包列表是空的
                LeaveCriticalSection(&router->getPacketMutex());//离开互斥区
                continue;
            }
            router->tryToFwd(router->getPktBuf()->getHead());//处理数据包
            pkt = pkt->getNext();
            LeaveCriticalSection(&router->getPacketMutex());
            while (pkt != NULL) {//循环处理数据包
                router->tryToFwd(pkt);
                pkt = pkt->getNext();
            }
        }
    };

    static DWORD WINAPI RecvThread(LPVOID lpParam) {// 接收线程函数
        cout << "【SYS】 接收线程开启！\n";
        int res = 0;
        Router* router;
        struct pcap_pkthdr* header;
        const u_char* pktData;

        router = (Router*)lpParam;
        while ((res = pcap_next_ex(router->getDeviceManager()->getOpenHandle(), &header, &pktData)) >= 0) {//持续接收数据报
            if (res == 0) continue;//超时继续接收
            switch (ntohs(((FrameHeader*)pktData)->FrameType)) {//根据数据包类型分别处理
            case 0x0806://ARP报文
                if ((ntohs(((ARPPkt*)pktData)->arpframe.Operation) == 0x0001)// 如果是ARP请求
                    || router->getDeviceManager()->CheckDirectByIP(((ARPPkt*)pktData)->arpframe.SourceIP) == 0) // 或者与网卡不直连(跨网段请求ARP）
                    continue;//不做处理，丢弃
                router->getARPTable()->AddARPEntry(((ARPPkt*)pktData)->arpframe.SourceIP, ((ARPPkt*)pktData)->arpframe.SourceMAC); // 对于ARP应答报文，添加ARP表项
                //cout << recvLog(((FrameHeader*)pktData)->FrameType, ((ARPPkt*)pktData)->arpframe.SourceIP, ((ARPPkt*)pktData)->arpframe.SourceMAC, ((ARPPkt*)pktData)->arpframe.DstIP, ((ARPPkt*)pktData)->arpframe.DstMAC, -1) << endl;//输出日志信息
                break;
            case 0x0800://IP报文
                if (((IPPkt*)pktData)->ipheader.DstIP == router->getDeviceManager()->getOpenAdapter()->getIP(0)// 如果目的IP为本机IP
                    || ((IPPkt*)pktData)->ipheader.DstIP == router->getDeviceManager()->getOpenAdapter()->getIP(1)
                    || isICMPCorrupted((u_short*)pktData, sizeof(ICMPPingPkt)))// 或ICMP校验和错误
                    continue;//不做处理，丢弃
                EnterCriticalSection(&router->getPacketMutex());//进入互斥区
                router->getPktBuf()->addAfter((ICMPPingPkt*)pktData);//添加需要处理的数据报
                cout << recvLog(((FrameHeader*)pktData)->FrameType, ((ICMPPingPkt*)pktData)->ipheader.SrcIP, ((ICMPPingPkt*)pktData)->frameheader.SrcMAC, ((ICMPPingPkt*)pktData)->ipheader.DstIP, ((ICMPPingPkt*)pktData)->frameheader.DesMAC, (int)((ICMPPingPkt*)pktData)->ipheader.TTL) << endl;//输出日志信息
                LeaveCriticalSection(&router->getPacketMutex());//离开互斥区
                break;
            }
        }
        if (res == -1) {
            cout << "【ERR】 接收数据报错误：具体错误信息 " << pcap_geterr(router->getDeviceManager()->getOpenHandle()) << endl;
            exit(-1);
        }
        return 0;
    };

    static DWORD WINAPI ARPaging(LPVOID lpParam) {
        Router* router=(Router*)lpParam;
        ARPTable* arpTable = router->getarpTable();
        ARPEntry* arpEntry;
        arpEntry = arpTable->getHead(); //拷贝ARP表项的头指针
        while (arpEntry != NULL) {//遍历ARP表中的表项
            if (arpTable->isExpired(arpEntry)){//如果超时
                EnterCriticalSection(&router->getARPMutex());
                arpTable->DeleteARPEntry(arpEntry);//删除该表项
                LeaveCriticalSection(&router->getARPMutex());
            }
            arpEntry = arpEntry->getNext();//继续遍历下一个
        }
        return NULL;
    }
public:
    ARPTable* getarpTable(){
        return this->arpTable;
    };
    Router() {
        adaptermanager = new AdapteManager();
        memset(errbuf, 0, sizeof(errbuf));
        adaptermanager->FindAllDevs();// 查找可用设备
        adaptermanager->SelectUserAdapter();// 打开选中设备
        getOpenDeviceMac(adaptermanager->getOpenAdapter()); // 获取打开设备的Mac地址

        pktBuf = new PacketList();//初始化数据包队列
        pktLifetime = 10; // 数据包的生存时间
        arpTable = new ARPTable();//初始化ARP表
        routetable = new RouteTable(adaptermanager->getOpenAdapter());//初始化路由表
        routetable->addRouteEntry("0.0.0.0", "0.0.0.0", "206.1.2.2");   // 添加默认路由，不可删除，可修改

        InitializeCriticalSection(&PacketMutex);//初始化临界区
        sendthread = CreateThread(NULL, 0, SendThread, this, 0, NULL); // 创建转发线程
        Sleep(100);
        recvthread = CreateThread(NULL, 0, RecvThread, this, 0, NULL); // 创建接收线程
        Sleep(100);
        PrintHelp();
        freopen("output.txt", "w", stdout);
        cmdThrd();// 主线程进行指令控制
    };

    ~Router() {
        delete adaptermanager;
        delete arpTable;
        delete routetable;
        CloseHandle(recvthread);
        CloseHandle(sendthread);
        DeleteCriticalSection(&PacketMutex);
    };

    AdapteManager* getDeviceManager() {
        return adaptermanager;
    };

    ARPTable* getARPTable() {
        return arpTable;
    };

    RouteTable* getRoutingTable() {
        return routetable;
    };

    PacketList* getPktBuf() {
        return pktBuf;
    };

    u_int getPktLifetime() {
        return pktLifetime;
    };

    CRITICAL_SECTION& getPacketMutex() {
        return PacketMutex;
    };

    CRITICAL_SECTION& getARPMutex() {
        return ARPMutex;
    };

    void tryToFwd(Packet* pkt) {
        if (pkt == NULL) {
            cout << "【ERR】 转发数据包失败: 数据包无效" << endl;
            return;
        }
        BYTE* dstMac;
        RouteEntry* routingEntry;
        ARPEntry* arpEntry;

        if (pkt->shouldDiscard()) {
            cout << pkt->shouldDiscard() << endl;
            cout << "【ERR】 转发数据包失败: 数据包应当被丢弃" << endl;
            return;
        }
        if (pkt->getICMPPingPkt()->ipheader.TTL == 0) {
            cout << "【ERR】 转发数据包失败: 数据包生存时间为0" << endl;
            pkt->setDiscard(true);
            // TODO : send ICMP time exceeded
            return;
        }
        if (time(NULL) - pkt->getTime() > pktLifetime) {
            cout << "【ERR】 转发数据包失败: 数据包已超时" << endl;
            pkt->setDiscard(true);
            // TODO : send ICMP time exceeded
            return;
        }
        if (adaptermanager->CheckDirectByIP(pkt->getICMPPingPkt()->ipheader.DstIP) != 0) {
            if ((arpEntry = arpTable->lookupARPEntry(pkt->getICMPPingPkt()->ipheader.DstIP)) == NULL) {
                cout << "【ERR】 ARP表中没有该IP的信息。IP: " << b2s(pkt->getICMPPingPkt()->ipheader.DstIP) << endl;
                bcstARPReq(pkt->getICMPPingPkt()->ipheader.DstIP);
                return;
            }
            dstMac = arpEntry->getMac();
            forward(pkt->getICMPPingPkt(), dstMac);
            cout << fwrdLog((pkt->getICMPPingPkt())->frameheader.FrameType, pkt->getICMPPingPkt()->ipheader.SrcIP, adaptermanager->getOpenAdapter()->getMac(), pkt->getICMPPingPkt()->ipheader.DstIP, routingEntry->getNextHop(), dstMac, (int)(pkt->getICMPPingPkt()->ipheader.TTL), false) << endl;
            pkt->setDiscard(true);
            return;
        }
        if ((routingEntry = routetable->lookupRouteEntry(pkt->getICMPPingPkt()->ipheader.DstIP)) == NULL) {
            cout << "【ERR】 路由表中没有该IP的信息。IP: " << b2s(pkt->getICMPPingPkt()->ipheader.DstIP) << endl;
            pkt->setDiscard(true);
            // TODO : send ICMP net unreachable
            return;
        }
        if ((arpEntry = arpTable->lookupARPEntry(routingEntry->getNextHop())) == NULL) {
            cout << "【ERR】 ARP表中没有下一跳的信息 下一跳IP: " << b2s(routingEntry->getNextHop()) << endl;
            bcstARPReq(routingEntry->getNextHop());
            return;
        }
        dstMac = arpEntry->getMac();
        forward(pkt->getICMPPingPkt(), dstMac);
        cout << fwrdLog((pkt->getICMPPingPkt())->frameheader.FrameType, pkt->getICMPPingPkt()->ipheader.SrcIP, adaptermanager->getOpenAdapter()->getMac(), pkt->getICMPPingPkt()->ipheader.DstIP, routingEntry->getNextHop(), dstMac, (int)(pkt->getICMPPingPkt()->ipheader.TTL), false) << endl;
        pkt->setDiscard(true);
        return;
    };

};

int main() {
    Router router;
    return 0;
}