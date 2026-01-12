#pragma once
#include "sys_mem.h" // 内核读写接入
#include <bitset>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <ios>
#include <iostream>
#include <limits>
#include <ostream>
#include <regex>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <thread>
#include <time.h>
#include <type_traits>
#include <unistd.h>
#include <vector>
#include <wait.h>
#include <set>

#define ADDR_HEARD 0x40000
#define ADDR_FOOT32 0xFFFFFFFF
#define ADDR_FOOT64 0x7FFFFFFFFFFF
#define D_PRINT 1000
#define MAX_INPUT 255
typedef signed long __xor;
typedef unsigned char u_byte;
typedef unsigned long DWORD;
typedef unsigned long long DWORD64;
typedef signed char __byte;
typedef signed long __DWORD;
typedef signed long long __DWORD64;

struct MAPS
{
  DWORD64 baddr = 0;
  DWORD64 eaddr = 0;
  std::string flag;
  std::string infor;
};
struct MAPS2
{
  MAPS maps;           // 开始地址;结束地址;
  char flag[10] = {0}; // 读写权限信息(rw--p、r--p、r--s相关);
  char pgoff[20] = {
      0}; // 对有名映射，表示此段虚拟内存起始地址在文件中以页为单位的偏移。
  char s_dev[10] = {
      0};                // 对匿名映射，它等于0或者vm_start/PAGE_SIZE;映射文件所属设备号;
  char s_ino[20] = {0};  // 映射文件所属节点号;
  char infor[256] = {0}; // 其他信息(文件名，栈和堆)。
};
#ifndef _c
namespace crypt
{
#define WINCHAN_PEES_RTSX                                       \
  ((__TIME__[7] - '0') * 1ull + (__TIME__[6] - '0') * 10ull +   \
   (__TIME__[4] - '0') * 60ull + (__TIME__[3] - '0') * 600ull + \
   (__TIME__[1] - '0') * 3600ull + (__TIME__[0] - '0') * 36000ull)
  constexpr unsigned long long winchan_ROTARENEG(unsigned rounds)
  {
    return 1013904223ull +
           (1664525ull * ((rounds > 0) ? winchan_ROTARENEG(rounds - 1)
                                       : (WINCHAN_PEES_RTSX))) %
               0xFFFFFFFF;
  }
#define winchan_MODNA() winchan_ROTARENEG(10)
#define XSTR_RANDOM_NUMBER(Min, Max) (Min + (winchan_MODNA() % (Max - Min + 1)))
  constexpr const unsigned long long XORKEY = XSTR_RANDOM_NUMBER(0, 0xFF);
  template <typename Char>
  constexpr Char encrypt_character(const Char character, int index)
  {
    return character ^ (static_cast<Char>(XORKEY) + index);
  }
  template <unsigned size, typename Char>
  class WINCHAN_GNISS
  {
  public:
    const unsigned _nb_chars = (size - 1);
    Char _string[size];
    inline constexpr WINCHAN_GNISS(const Char *string) : _string{}
    {
      for (unsigned i = 0u; i < size; ++i)
        _string[i] = encrypt_character<Char>(string[i], i);
    }
    const Char *decrypt() const
    {
      Char *string = const_cast<Char *>(_string);
      for (unsigned t = 0; t < _nb_chars; t++)
      {
        string[t] = string[t] ^ (static_cast<Char>(XORKEY) + t);
      }
      string[_nb_chars] = '\0';
      return string;
    }
  };
} // namespace crypt
#define WINCHAN_SROX(name, my_string)                                      \
  constexpr crypt::WINCHAN_GNISS<(sizeof(my_string) / sizeof(char)), char> \
  name(my_string)
#define WINCHAN_GNIRTS_ROX(my_string) \
  [] {                                                                         \
    constexpr crypt::WINCHAN_GNISS<(sizeof(my_string) / sizeof(char)), char>   \
        expr(my_string);                                                       \
    return expr; }()                            \
      .decrypt()
#define _c(string) WINCHAN_GNIRTS_ROX(string)
#define WINCHAN_SWROX(name, my_string)                                  \
  constexpr crypt::WINCHAN_GNISS<(sizeof(my_string) / sizeof(wchar_t)), \
                                 wchar_t>                               \
  name(my_string)
#define WINCHAN_GNIRTS_ROX_W(my_string) \
  [] {                                                                         \
    constexpr crypt::WINCHAN_GNISS<(sizeof(my_string) / sizeof(wchar_t)),      \
                                   wchar_t>                                    \
        expr(my_string);                                                       \
    return expr; }()                              \
      .decrypt()
#define _cw(string) WINCHAN_GNIRTS_ROX_W(string)
#endif

/* memTools3.2.5 最后编辑2023年9月24日 by337737304 */
// 较上个版本区别：紧急修复过缺页内存的问题！！！有一行代码写错写反了;
static inline DWORD64 headAddr = ADDR_HEARD, footAddr = ADDR_FOOT64;
static inline std::vector<MAPS> vMaps;       /* vecter maps */
static inline std::vector<DWORD64> vResults; /* vecter results */
/* static conf */
static inline int pPid = 0;             // process pid
static inline std::string pProcessName; // process name
static inline std::string pName;        // process package name
static int ProcessBit = -1;      // process bit(1->32bit，2->64bit)
const size_t mysize = 0xFFF;
static inline bool isDebug = false;
static inline int currentWM = 0;
static inline bool Rflag; // 读取成功的标志
// 内核读写接入
static c_driver *sys_mem_all = nullptr;
namespace Mem
{
  enum myWriteMode
  {
    W_Default,
    W_Attach,
    W_Open
  }; // {默认syscall修改, 附加修改, 普通open修改}
  // 过缺页类
  class PageMapReader
  {
  public:
    PageMapReader(pid_t pid) : pid(pid)
    {
      char filename[32];
      snprintf(filename, sizeof(filename), "/proc/%d/pagemap", pid);
      pagemap = nullptr;
      pagemap = fopen(filename, "rb");
      page_size = sysconf(_SC_PAGESIZE);
      page_mask = ~(static_cast<uint64_t>(page_size) - 1);
      if (!pagemap)
      {
        // std::cout << "[PageMapReader]无法打开pagemap文件" << std::endl;
        pagemap = nullptr;
        return;
      }
    }

    ~PageMapReader()
    {
      if (pagemap)
      {
        fclose(pagemap);
        pagemap = nullptr;
      }
    }
    bool isInit() { return pagemap != nullptr; };
    // 判断内存是否缺页内存
    bool check_mem(uint64_t address)
    {
      // 计算在pagemap中的偏移
      const uint64_t page_offset = (address & page_mask) / page_size;
      const off_t offset = static_cast<off_t>(page_offset * sizeof(uint64_t));
      // 定位到文件位置
      if (fseeko(pagemap, offset, SEEK_SET) != 0)
      {
        return true; // 定位失败视为缺页
      }
      // 直接读取64位条目
      uint64_t entry;
      if (fread(&entry, sizeof(entry), 1, pagemap) != 1)
      {
        return true; // 读取失败视为缺页
      }
      // 检查第63位（页面存在位）
      return !(entry & PRESENT_BIT);
    }

  private:
    FILE *pagemap = nullptr;
    pid_t pid;
    size_t page_size;
    uint64_t page_mask;

    // 第63位掩码（1 << 63）
    static constexpr uint64_t PRESENT_BIT = (1ULL << 63);
  };
  static PageMapReader *mis_page_check = nullptr;
  static uint ALL = 0x0, AS = 0x1, JH = 0x2, J = 0x4, CD = 0x8, CB = 0x10,
              S = 0x20, CA = 0x40, CH = 0x80, B = 0x100, XS = 0x200, XA = 0x400,
              A = 0x800, O = 0x1000;
  static std::string CA_bk = _c("(.+)anon:((?!.bss).)(.+)");
  void mem(
      std::string packName, int rw_mode = -1,
      bool isDbg =
          false); // 初始化(包名,
                  // 读写模式[-1不使用内核，0使用选择的内核，1-7使用qxv8等固定内核],
                  // 是否输出调试)
  static uint ms = 0;
  /* other */
  size_t mem_read(DWORD64 addr, void *buffer, size_t size);         // 普通读取
  size_t mem_write(DWORD64 addr, void *buffer, size_t size);        // 普通写入
  size_t mem_write_ptrace(DWORD64 addr, void *buffer, size_t size); // 附加写入
  size_t mem_write_open(DWORD64 addr, void *buffer, size_t size);   // 强制写入
  bool isInMaps(DWORD64 addr);
  bool isInFreeze(DWORD64 addr);
  int strToV(std::vector<std::string> &str_v, std::string data_s,
             std::string sub_s, std::string remove_s = "");
  int GetTracerPid(int MainPid);
  bool isRunning(int pid);
  bool isRunning(std::string pack_name);
  bool isRunning();
  int killprocess(const char *bm);
  bool isExistGG();
  bool isRunGG(bool isKill = false);
  int readmaps(std::string flag_rex, std::string infor_rex,
               bool isPrintf = false); // 自行匹配maps
  int isX64(DWORD pid);                // 判断进程BIT, 64bit返回2,
  // 32bit返回1, 查不到返回0,is_all_match是是否全匹配，默认是
  static bool is_all_match = 1;
  int getPid();
  int getPid(std::string pack);
  bool initMisCheck(); // 初始化缺页内存检测类，如果不初始化则表示不使用过缺页
  static void Pid_Set(bool is_all_match_tmp) { is_all_match = is_all_match_tmp; };
  int WF(std::string path, std::string str, int flag = std::ios::out);
  std::string RF(std::string path, int line = -1);
  std::string RF_E(std::string path, int line, char ends = '\0');
  std::wstring c2w(const char *pc);
  std::string w2c(const wchar_t *pw);
  std::string u16tocs(std::u16string str);
  std::u16string cstou16(std::string str);
  // 备份和恢复
  static std::vector<DWORD64> vResults_bk;
  inline void ResChange(__DWORD64 offset)
  {
    for (int i = 0; i < vResults.size(); i++)
      vResults[i] += offset;
  }
  inline void ResBackup()
  {
    vResults_bk.assign(vResults.begin(), vResults.end());
  }
  inline void ResRecover(__DWORD64 offset = 0)
  {
    if (!vResults.empty())
      vResults.clear();
    if (vResults_bk.empty())
      return;
    vResults.assign(vResults_bk.begin(), vResults_bk.end());
    if (offset != 0)
      ResChange(offset);
  }
  inline void ResBackupClear()
  {
    if (!vResults_bk.empty())
      vResults_bk.clear();
  };

  inline void SetWM(int w_m)
  {
    currentWM = w_m;
  }; // 重设修改内存的方式(默认普通，W_Attach为修改无保护的进程)
  /* maps */
  void SetMemRange(uint mRange,
                   bool isPrintf = false); // 设置内存类型(CA、A、B......)
  inline void SetMemRange(std::string flag_rex, std::string infor_rex,
                          bool isPrintf = false)
  {
    // 自定义内存类型正则规则,
    // 参数一读写权限信息, 参数二infor
    readmaps(flag_rex, infor_rex, isPrintf);
  };
  inline int getAddrRange(DWORD64 addr);           // 获取内存地址在哪个内存区域范围
  void SetAddrRange(DWORD64 hAddr, DWORD64 fAddr); // 限制搜索地址的最小和最大值
  void SetMapSize(DWORD64 minAddr = 0x0,
                  DWORD64 maxAddr = ADDR_FOOT64); // 设置maps最小和最大值
  /* mem */
  // 模块搜索 直接获取
  DWORD64 SearchBaseAddr(std::string b_str);
  // 模块搜索 保存到搜索结果
  int SearchBaseAddr(
      std::string b_str, int sType, __DWORD64 offset = 0,
      std::string strPosstr =
          ""); // !配合ceserver!搜索基址保存到结果SearchBaseAddr("so名/so名.往下第几个[下标0开始]",
               // <sType==-1,存最后一个,sType==0,存全部，sType>0存第sType个>)
  DWORD64 GetBaseAddrByName(std::string b_str,
                            int num = 1); // 基址获取(名称,  获取第几个)
  void OffsetPointer(
      std::vector<__DWORD64> offset_all,
      bool isAll = true); // 对搜索结果进行指针操作(指针集,  是否全部范围)
  // 搜索
  template <class T>
  int UnkS(T &value);
  inline int SByte(__byte value) { return UnkS(value); }
  inline int SWord(short value) { return UnkS(value); }
  inline int SDword(int value) { return UnkS(value); }
  inline int SQWord(__DWORD64 value) { return UnkS(value); }
  inline int SFloat(float value) { return UnkS(value); }
  inline int SDouble(double value) { return UnkS(value); }
  inline int SXor(__xor value) { return UnkS(value); }
  int SString(std::string value);
  int SWstring(std::string value);
  // 改善
  template <class T>
  int UnkOffset(T &value, __DWORD64 &offset);
  inline int OffsetByte(__byte value, __DWORD64 offset)
  {
    return UnkOffset(value, offset);
  }
  inline int OffsetSWord(short value, __DWORD64 offset)
  {
    return UnkOffset(value, offset);
  }
  inline int OffsetSDword(int value, __DWORD64 offset)
  {
    return UnkOffset(value, offset);
  }
  inline int OffsetSQWord(__DWORD64 value, __DWORD64 offset)
  {
    return UnkOffset(value, offset);
  }
  inline int OffsetSFloat(float value, __DWORD64 offset)
  {
    return UnkOffset(value, offset);
  }
  inline int OffsetSDouble(double value, __DWORD64 offset)
  {
    return UnkOffset(value, offset);
  }
  inline int OffsetSXor(__xor value, __DWORD64 offset)
  {
    return UnkOffset(value, offset);
  }
  // 跳级改善
  template <class T>
  int UnkVOffset(T &value, std::vector<__DWORD64> &vOffset);
  inline int VOffsetByte(__byte value, std::vector<__DWORD64> vOffset)
  {
    return UnkVOffset(value, vOffset);
  }
  inline int VOffsetSWord(short value, std::vector<__DWORD64> vOffset)
  {
    return UnkVOffset(value, vOffset);
  }
  inline int VOffsetSDword(int value, std::vector<__DWORD64> vOffset)
  {
    return UnkVOffset(value, vOffset);
  }
  inline int VOffsetSQWord(__DWORD64 value, std::vector<__DWORD64> vOffset)
  {
    return UnkVOffset(value, vOffset);
  }
  inline int VOffsetSFloat(float value, std::vector<__DWORD64> vOffset)
  {
    return UnkVOffset(value, vOffset);
  }
  inline int VOffsetSDouble(double value, std::vector<__DWORD64> vOffset)
  {
    return UnkVOffset(value, vOffset);
  }
  inline int VOffsetSXor(__xor value, std::vector<__DWORD64> vOffset)
  {
    return UnkVOffset(value, vOffset);
  }
  // 修改
  template <class T>
  int UnkW(T &value, __DWORD64 &offset);
  inline int WByte(__byte value, __DWORD64 offset = 0)
  {
    return UnkW(value, offset);
  }
  inline int WWord(short value, __DWORD64 offset = 0)
  {
    return UnkW(value, offset);
  }
  inline int WDword(int value, __DWORD64 offset = 0)
  {
    return UnkW(value, offset);
  }
  inline int WQword(__DWORD64 value, __DWORD64 offset = 0)
  {
    return UnkW(value, offset);
  }
  inline int WFloat(float value, __DWORD64 offset = 0)
  {
    return UnkW(value, offset);
  }
  inline int WDouble(double value, __DWORD64 offset = 0)
  {
    return UnkW(value, offset);
  }
  inline int WXor(__xor value, __DWORD64 offset = 0)
  {
    return UnkW(value, offset);
  }
  int WString(std::string value, __DWORD64 offset = 0);
  int WWstring(std::string value, __DWORD64 offset = 0);
  // 直接读数值
  template <class T>
  T UnkR(DWORD64 &addr);
  inline DWORD64 RPointer(DWORD64 addr)
  {
    DWORD64 p_tmp[2] = {0};
    mem_read(addr, p_tmp, ProcessBit * 4);
    return p_tmp[0];
  }
  inline __byte RByte(DWORD64 addr) { return UnkR<__byte>(addr); }
  inline short RWord(DWORD64 addr) { return UnkR<short>(addr); }
  inline uint RDword(DWORD64 addr) { return UnkR<uint>(addr); }
  inline DWORD64 RDword64(DWORD64 addr) { return UnkR<DWORD64>(addr); }
  inline float RFloat(DWORD64 addr) { return UnkR<float>(addr); }
  inline double RDouble(DWORD64 addr) { return UnkR<double>(addr); }
  inline int RInt(DWORD64 addr) { return UnkR<int>(addr); }
  inline __DWORD64 R__DWORD64(DWORD64 addr) { return UnkR<__DWORD64>(addr); }
  inline __DWORD64 RQword(DWORD64 addr) { return R__DWORD64(addr); }
  inline __xor RXor(DWORD64 addr) { return UnkR<__xor>(addr); }
  std::string RString(DWORD64 addr, size_t MaxLen = MAX_INPUT,
                      char endChar = '\0');
  std::wstring RWstring(DWORD64 addr, size_t MaxLen = MAX_INPUT,
                        wchar_t endChar = L'\0');
  inline DWORD64 JumpPointer(DWORD64 addr, std::vector<DWORD64> addr_list);
  // 其它
  void ResultsCut(int b_num, int count_num);      // 搜索结果数量截断(开始,数量)
  void ResultsAppend(DWORD64 addr_temp);          // 手动添加地址到结果中
  inline int count() { return vResults.size(); }; // 结果数
  int GetTracerPid();                             // 获取Trace进程PID
  void clear();

  /* print */
  void print(std::string buf);
  void print(DWORD isAll = D_PRINT); // 打印结果(打印结果数量;);
  // 为0则全部打印
  void print_maps(DWORD isAll = 0); // 打印maps(打印结果数量);
  // 为0则全部打印
  template <class T>
  void print(DWORD isAll = D_PRINT);

  // ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  inline void w2c_b(std::wstring &str, char *res, int wsize = 2)
  {
    res[wsize * str.size()] = '\0';
    for (int i = 0; i < str.size(); i++)
      memcpy(&res[i * wsize], &str[i], wsize);
  }

  inline bool isHex_a(std::string &str)
  {
    int len = str.size();
    if (!len)
      return false;
    while (len--)
      if ((str[len] > 57 || str[len] < 48) && (str[len] > 70 || str[len] < 65) &&
          str[len] != 45)
        return false;
    return true;
  }

  inline int GetTracerPid() { return GetTracerPid(pPid); };

  inline void clear()
  {
    pName = "";
    if (!vResults.empty())
      vResults.clear();
    if (!vMaps.empty())
      vMaps.clear();
  };

#define errprint(log) \
  {                   \
    print(log);       \
    return 0;         \
  }

  // 读写模式[-1不使用内核，0使用选择的内核，1-7使用qxv8等固定内核]
  inline bool init_ko(int rw_mode)
  {
    if (sys_mem_all == nullptr)
    {
      sys_mem_all = new c_driver(rw_mode);
      sys_mem_all->init(rw_mode);
    }
    return sys_mem_all->is_open();
  }

  inline void mem(std::string packName, int rw_mode, bool isDbg)
  {
    pProcessName.clear();
    isDebug = isDbg;
    void *num = 0;
    struct stat file_stat;
    if (packName.find("/") != -1)
    {
      if (stat(packName.c_str(), &file_stat) == 0)
      {
        off_t file_size = file_stat.st_size;
        if (isDbg)
          printf("二进制文件模式.文件大小: %ld 字节\n", file_size);
        if (file_size > 0x80000000 || file_size < 0x10)
        {
          if (isDbg)
            printf("不支持2G以上16kb以下的文件!\n");
          exit(0);
        }
        pPid = open(packName.c_str(), O_RDWR); // 存文件fd指针
        if (pPid == -1)
        {
          if (isDbg)
            printf("打开文件失败!\n");
          exit(0);
        }
        headAddr = 0;
        footAddr = 0xF0000000;
        ProcessBit = 1;
        currentWM = file_size;
        if (!vMaps.empty())
          vMaps.clear();
        vMaps.push_back({(DWORD64)0, (DWORD64)file_size});
      }
      else
      {
        if (isDbg)
          printf("二进制文件模式.获取文件大小失败！\n");
        exit(0);
      }
      return;
    }
    headAddr = ADDR_HEARD;
    footAddr = ADDR_FOOT64;
    currentWM = 0;
    if (!vMaps.empty())
      vMaps.clear();
    if (isDebug)
      std::cout << (_c("当前运行环境:") + std::to_string(sizeof(num) * 8) +
                    _c("位。"))
                << std::endl;
    // 获取pid
    pPid = getPid(packName);
    if (pPid < 1)
    {
      if (isDebug)
        std::cout << _c("获取进程pid失败,初始化失败!") << std::endl;
      return;
    }
    // 使用内核读写
    if (rw_mode >= 0)
    {
      if (isDebug)
        std::cout << _c("使用内核读写!模式:") << std::dec << rw_mode << std::endl;
      init_ko(rw_mode);
      sys_mem_all->initialize(pPid);
    }
    ProcessBit = isX64(pPid);
    if (ProcessBit > 0)
    {
      pProcessName = packName;
      if (isDebug)
        std::cout << (_c("获取") + std::to_string(ProcessBit * 32) +
                      _c("bit进程PID成功， PID:") + std::to_string(pPid) +
                      _c("。"))
                  << std::endl;
    }
    else
    {
      if (isDebug)
        std::cout << _c("获取进程bit失败, 初始化失败!") << std::endl;
      return;
    }
    if (ProcessBit == 1)
    {
      footAddr = ADDR_FOOT32;
    }
  }

  // 获取地址在哪个内存范围中，-1代表未知
  inline int getAddrRange(DWORD64 addr)
  {
    for (int i = 0; i < vMaps.size(); i++)
    {
      if (addr >= vMaps[i].baddr && addr < vMaps[i].eaddr)
      {
        std::string flag = vMaps[i].flag;
        std::string infor = vMaps[i].infor;
        if (regex_match(infor, std::regex(_c("/dev/ashmem/(.+)"))) &&
            regex_match(flag, std::regex(_c("(.+)-s"))))
        {
          return AS;
        }
        else if (regex_match(
                     infor, std::regex(_c("(.*)\\[anon:dalvik(.*)||/dev/ashmem/"
                                          "dalvik-large(.+)|/dev/ashmem/"
                                          "dalvik-allocation(.+)|/dev/ashmem/"
                                          "dalvik-main(.+)|/"
                                          "dev/ashmem/dalvik-free(.+)"))))
        {
          return JH;
        }
        else if (regex_match(flag, std::regex(_c("r(.+)|(.*)w(.+)"))) &&
                 regex_match(infor, std::regex(_c("/dev/ashmem/(.+)"))))
        {
          return J;
        }
        else if (regex_match(infor, std::regex(_c("/data/(.+).so"))) &&
                 !regex_match(flag, std::regex(_c("(.+)-xp"))))
        {
          return CD;
        }
        else if (regex_match(infor, std::regex(_c("\\[anon:.bss\\]"))))
        {
          return CB;
        }
        else if (regex_match(infor, std::regex(_c("\\[stack(.*)\\]"))))
        {
          return S;
        }
        else if (regex_match(infor, std::regex(_c("\\[anon:libc_malloc\\]"))))
        {
          return CA;
        }
        else if (regex_match(infor, std::regex(_c("\\[heap\\]"))))
        {
          return CH;
        }
        else if (regex_match(infor, std::regex(_c("/dev/kgsl-3d0(.*)"))))
        {
          return B;
        }
        else if (regex_match(infor, std::regex(_c("/system/(.+)"))))
        {
          return XS;
        }
        else if (regex_match(flag, std::regex(_c("(.+)-xp"))))
        {
          return XA;
        }
        else if (regex_match(flag, std::regex(_c("r(.+)|(.*)w(.+)"))) &&
                 infor.size() < 4)
        {
          return A;
        }
        else if (vMaps[i].eaddr - vMaps[i].baddr > 0x1)
        {
          return O;
        }
        break;
      }
    }
    return -1;
  }

  inline void SetMemRange(uint mRange, bool isPrintf)
  {
    if (!vMaps.empty())
      vMaps.clear();
    if (!isRunning())
    {
      print(_c("PID error"));
      return;
    }
    if (sys_mem_all != nullptr)
    {
      print("内核模式下不支持此功能!");
      return;
    }
    std::string allMaps;
    std::ifstream t(_c("/proc/") + std::to_string(pPid) + _c("/maps"),
                    std::ios::in);
    if (t.is_open())
    {
      allMaps = std::string((std::istreambuf_iterator<char>(t)),
                            std::istreambuf_iterator<char>());
      t.close();
    }
    else
    {
      print("打开maps失败!");
      return;
    }
    std::vector<std::string> vRes;
    strToV(vRes, allMaps, "\n");
    DWORD64 searchSize = 0, totalVirtualSize = 0, totalSize = 0;
    std::string range_str;
    for (int i = 0; i < vRes.size(); i++)
    {
      MAPS2 map_temp = {0};
      sscanf(vRes[i].c_str(), "%llx-%llx %s %s %s %s %[^\n]",
             &map_temp.maps.baddr, &map_temp.maps.eaddr, map_temp.flag,
             map_temp.pgoff, map_temp.s_dev, map_temp.s_ino, map_temp.infor);
      DWORD64 sizeTmp = map_temp.maps.eaddr - map_temp.maps.baddr;
      std::string flag = map_temp.flag;
      std::string pgoff = map_temp.pgoff;
      std::string s_dev = map_temp.s_dev;
      std::string s_ino = map_temp.s_ino;
      std::string infor = map_temp.infor;
      map_temp.maps.infor = infor;
      map_temp.maps.flag = flag;
      if (mRange == ALL && sizeTmp > 1 && sizeTmp < footAddr)
      {
        range_str = "范围[ALL]";
        totalSize += sizeTmp;
        if (mis_page_check)
        {
          if (mis_page_check->check_mem(map_temp.maps.baddr))
          { // 如果是缺页内存
            totalVirtualSize += sizeTmp;
            continue;
          }
        }
        else
          searchSize += sizeTmp;
        vMaps.push_back(map_temp.maps);
        if (isPrintf && isDebug)
        {
          std::cout << _c("大小: 0x") << std::hex << sizeTmp << " " << infor
                    << std::endl
                    << map_temp.maps.baddr << "~" << map_temp.maps.eaddr
                    << std::endl;
        }
      }
      else
      {
        std::string str_temp;
        if (regex_match(infor, std::regex(_c("/dev/ashmem/(.+)"))) &&
            regex_match(flag, std::regex(_c("(.+)-s"))) && (mRange & AS))
        {
        }
        else if (regex_match(
                     infor,
                     std::regex(_c("(.*)\\[anon:dalvik(.*)||/dev/ashmem/"
                                   "dalvik-large(.+)|/dev/ashmem/"
                                   "dalvik-allocation(.+)|/dev/ashmem/"
                                   "dalvik-main(.+)|/"
                                   "dev/ashmem/dalvik-free(.+)"))) &&
                 (mRange & JH))
        {
          str_temp = "范围[JH]";
        }
        else if (regex_match(flag, std::regex(_c("r(.+)|(.*)w(.+)"))) &&
                 regex_match(infor, std::regex(_c("/dev/ashmem/(.+)"))) & (mRange & J))
        {
          str_temp = "范围[J]";
        }
        else if (regex_match(infor, std::regex(_c("/data/(.+).so"))) &&
                 !regex_match(flag, std::regex(_c("(.+)-xp"))) && (mRange & CD))
        {
          str_temp = "范围[CD]";
        }
        else if (regex_match(infor, std::regex(_c("\\[anon:.bss\\]"))) && (mRange & CB))
        {
          str_temp = "范围[CB]";
        }
        else if (regex_match(infor, std::regex(_c("\\[stack(.*)\\]"))) && (mRange & S))
        {
          str_temp = "范围[S]";
        }
        else if (regex_match(infor,
                             std::regex(_c("\\[anon:libc_malloc\\]"))) &&
                 (mRange & CA))
        {
          str_temp = "范围[CA]";
        }
        else if (regex_match(infor, std::regex(_c("\\[heap\\]"))) && (mRange & CH))
        {
          str_temp = "范围[CH]";
        }
        else if (regex_match(infor, std::regex(_c("/dev/kgsl-3d0(.*)"))) && (mRange & B))
        {
          str_temp = "范围[B]";
        }
        else if (regex_match(infor, std::regex(_c("/system/(.+)"))) && (mRange & XS))
        {
          str_temp = "范围[XS]";
        }
        else if (regex_match(flag, std::regex(_c("(.+)-xp"))) && (mRange & XA))
        {
          str_temp = "范围[XA]";
        }
        else if (infor.empty() && (mRange & A))
        {
          str_temp = "范围[A]";
        }
        else if ((map_temp.maps.eaddr - map_temp.maps.baddr) > 0x1 && infor.find("(deleted)") == std::string::npos && (mRange & O))
        {
          str_temp = "范围[O]";
        }
        else
        {
          continue;
        }
        if (sizeTmp > 0)
        {
          totalSize += sizeTmp;
          if (mis_page_check)
          {
            if (mis_page_check->check_mem(
                    map_temp.maps.baddr))
            { // 如果是缺页内存
              totalVirtualSize += sizeTmp;
              continue;
            }
          }
          else
          {
            searchSize += sizeTmp;
          }
          vMaps.push_back(map_temp.maps);
          if (isPrintf && isDebug)
          {
            std::cout << std::hex << map_temp.maps.baddr << "~" << map_temp.maps.eaddr << "," << str_temp << _c(",大小: 0x")  << sizeTmp
                      << std::endl << ":" << infor << std::endl;
          }
        }
      }
    }
    if (range_str.size() < 2)
    {
      range_str = "范围["+std::string(mRange&AS?"AS":"")+std::string(mRange&JH?"JH":"")+std::string(mRange&J?"J":"")+std::string(mRange&CD?"CD":"")+std::string(mRange&CB?"CB":"")+std::string(mRange&S?"S":"")+std::string(mRange&CA?"CA":"")+std::string(mRange&CH?"CH":"")+std::string(mRange&B?"B":"")+std::string(mRange&XS?"XS":"")+std::string(mRange&XA?"XA":"")+std::string(mRange&A?"A":"")+std::string(mRange&O?"O":"")+"]";
    }
    if (isDebug)
    {
      std::string t_a = _c("M");
      std::cout << std::dec << "总大小(" << ((double)totalSize) / 1000000 << t_a
                << ")," << range_str << "\n  缺页("
                << ((double)totalVirtualSize) / 1000000 << t_a << ")\n  搜索("
                << ((double)searchSize) / 1000000 << t_a << ")" << std::endl;
    }
  }

  inline void SetAddrRange(DWORD64 hAddr, DWORD64 fAddr)
  {
    if (vMaps.empty() || hAddr < headAddr || fAddr > footAddr ||
        fAddr - hAddr < 1)
    {
      print(_c("指定范围错误!"));
      return;
    }
    std::vector<MAPS> vMapsTmp;
    for (int i = 0; i < vMaps.size(); i++)
    {
      if (hAddr > vMaps[i].baddr)
        vMaps[i].baddr = hAddr;
      if (fAddr < vMaps[i].eaddr)
        vMaps[i].eaddr = fAddr;
      if ((__DWORD64)(vMaps[i].eaddr - vMaps[i].baddr) < 1)
        continue;
      vMapsTmp.push_back(vMaps[i]);
    }
    if (vMapsTmp.size() > 0)
      vMaps.swap(vMapsTmp);
    else if (!vMaps.empty())
      vMaps.clear();
  }

  inline void SetMapSize(DWORD64 minAddr, DWORD64 maxAddr)
  {
    if (vMaps.empty())
      return;
    std::vector<MAPS> vMapsTmp;
    for (int i = 0; i < vMaps.size(); i++)
    {
      DWORD64 size_temp = vMaps[i].eaddr - vMaps[i].baddr;
      if (size_temp < minAddr || size_temp > maxAddr)
        continue;
      vMapsTmp.push_back(vMaps[i]);
    }
    if (vMapsTmp.size() > 0)
      vMaps.swap(vMapsTmp);
    else
      vMaps.clear();
  }

  inline int SearchBaseAddr_New(std::string b_str, __DWORD64 offset,
                                std::vector<MAPS2> &vMaps2)
  {
    if (!vResults.empty())
      vResults.clear();
    if (sys_mem_all != nullptr)
    {
      print("内核模式下不支持此功能!");
      return 0;
    }
    std::string allMaps;
    std::ifstream t(_c("/proc/") + std::to_string(pPid) + _c("/maps"),
                    std::ios::in);
    if (t.is_open())
    {
      allMaps = std::string((std::istreambuf_iterator<char>(t)),
                            std::istreambuf_iterator<char>());
      t.close();
    }
    else
    {
      print("打开maps失败!");
      return 0;
    }
    std::vector<std::string> vRes;
    strToV(vRes, allMaps, "\n");
    std::vector<MAPS> moduleMaps;
    bool nextAdd = false; // 下一行强制加入
    char lastso[512], lastModule[512];
    int nextNum = 0, lastSoCount = 1;
    unsigned long long lastsoAddr;
    std::regex e(b_str);
    for (int i = 0; i < vRes.size(); i++)
    {
      MAPS2 map_temp = {0};
      unsigned long long pgoff;
      sscanf(vRes[i].c_str(), "%llx-%llx %s %llx %s %s %[^\n]",
             &map_temp.maps.baddr, &map_temp.maps.eaddr, map_temp.flag, &pgoff,
             map_temp.s_dev, map_temp.s_ino, map_temp.infor);
      {
        char *modulepath = map_temp.infor;
        DWORD64 start = map_temp.maps.baddr;
        // 模块处理
        unsigned long long offset_tmp = start - lastsoAddr;
        char bufTmp[512]; // 临时存储模块名
        if (strstr(modulepath, ".so") != NULL)
        {
          // printf("so:%d-%llX-%s\n", (int)is_missmem, start, modulepath);
          // 把前缀去掉
          char *filename = strrchr(modulepath, '/');
          if (filename != NULL)
            filename++;
          strcpy(bufTmp, filename);
          memset(modulepath, 0, sizeof(modulepath) / sizeof(char));
          strcpy(modulepath, bufTmp);
          // // 重复模块处理
          if (strcmp(modulepath, lastso) == 0)
          {
            sprintf(bufTmp, "0x%llX@%s", offset_tmp, modulepath);
            memset(modulepath, 0, sizeof(modulepath) / sizeof(char));
            strcpy(modulepath, bufTmp);
            // printf("next:%s\n", modulepath);
          }
          else
          {
            // 记录上一个so模块信息
            memset(lastso, 0, sizeof(lastso) / sizeof(char));
            strcpy(lastso, modulepath);
            lastsoAddr = start;
            // printf("first:%s\n", modulepath);
          }
          nextAdd = 1; // 下一个非so模块也加进去
        }
        else if (nextAdd)
        {
          nextAdd = 0;
          sprintf(bufTmp, "0x%llX@%s", offset_tmp, lastso);
          memset(modulepath, 0, sizeof(modulepath) / sizeof(char));
          strcpy(modulepath, bufTmp);
          // printf("not so:%s\n", modulepath);
        }
        if (std::regex_search(std::string(modulepath), e))
        {
          vMaps2.push_back(map_temp);
          vResults.push_back(map_temp.maps.baddr + offset);
          moduleMaps.push_back({map_temp.maps.baddr, map_temp.maps.eaddr});
        }
        // if(std::string(map_temp.infor).find(b_str)!=-1){

        // }
      }
    }
    moduleMaps.swap(vMaps);
    return vResults.size();
  }

  inline DWORD64 SearchBaseAddr_New(std::string b_str)
  {
    if (sys_mem_all != nullptr)
    {
      print("内核模式下不支持此功能!");
      return 0;
    }
    std::vector<MAPS2> vTmp;
    if (SearchBaseAddr_New(b_str, 0, vTmp))
    {
      return vTmp[0].maps.baddr;
    }
    return 0;
  }

  inline DWORD64 SearchBaseAddr(std::string b_str)
  {
    DWORD64 addr = 0;
    int findTmp = b_str.find_last_of("@");
    if (findTmp != -1)
    {
      std::stringstream ss;
      ss << std::hex << b_str.substr(0, b_str.size() - findTmp);
      ss >> addr;
      b_str = b_str.substr(findTmp + 1);
    }
    if (sys_mem_all != nullptr)
    {
      addr += sys_mem_all->get_module_base((char *)b_str.c_str());
    }
    else
    {
      SearchBaseAddr(b_str, 1);
      if (!vResults.empty())
      {
        addr += vResults[0];
        vResults.clear();
      }
    }
    return addr;
  }

  inline int SearchBaseAddr(std::string b_str, int sType, __DWORD64 offset,
                            std::string strPosstr)
  {
    if (!vResults.empty())
      vResults.clear();
    if (sys_mem_all != nullptr)
    {
      print("内核模式下不支持此功能!");
      return 0;
    }
    std::string allMaps;
    std::ifstream t(_c("/proc/") + std::to_string(pPid) + _c("/maps"),
                    std::ios::in);
    if (t.is_open())
    {
      allMaps = std::string((std::istreambuf_iterator<char>(t)),
                            std::istreambuf_iterator<char>());
      t.close();
    }
    else
    {
      print("打开maps失败!");
      return 0;
    }
    std::vector<std::string> vRes;
    strToV(vRes, allMaps, "\n");
    bool isPush = false;
    MAPS lastMap;
    std::string lastSoName;
    int nextNum = 0, sCount = 0;
    std::vector<MAPS> moduleMaps;
    for (int i = 0; i < vRes.size(); i++)
    {
      MAPS2 map_temp = {0};
      sscanf(vRes[i].c_str(), "%llx-%llx %s %s %s %s %[^\n]",
             &map_temp.maps.baddr, &map_temp.maps.eaddr, map_temp.flag,
             map_temp.pgoff, map_temp.s_dev, map_temp.s_ino, map_temp.infor);
      std::string flag = map_temp.flag;
      std::string pgoff = map_temp.pgoff;
      std::string s_dev = map_temp.s_dev;
      std::string s_ino = map_temp.s_ino;
      std::string infor = map_temp.infor;
      map_temp.maps.infor = infor;
      map_temp.maps.flag = flag;
      {
        if (std::string(infor).find(".so") != -1)
        {
          int findTmp = infor.find_last_of("/");
          if (findTmp != -1)
          {
            findTmp += 1;
            lastSoName = infor.substr(findTmp, lastSoName.size() - findTmp);
            infor = lastSoName;
            nextNum = 0;
          }
        }
        else
        {
          nextNum++;
          infor = lastSoName + "." + std::to_string(nextNum);
        }
        if (infor == b_str)
        {
          sCount++;
          if (sType == -1)
            lastMap = map_temp.maps;
          else if (sType > 0 && sCount == sType)
          {
            lastMap = map_temp.maps;
            break;
          }
          else if (sType == 0 &&
                   std::string(map_temp.infor).find(strPosstr) != -1)
          {
            vResults.push_back(map_temp.maps.baddr + offset);
            moduleMaps.push_back(map_temp.maps);
          }
        }
      }
    }
    if (sType == -1 || sType > 0)
    {
      vResults.push_back(lastMap.baddr + offset);
      moduleMaps.push_back(lastMap);
    }
    moduleMaps.swap(vMaps);
    return vResults.size();
  }

  inline DWORD64 GetBaseAddrByName(std::string b_str, int num)
  {
    std::vector<MAPS> map_befor, map_act;
    map_befor.swap(vMaps);
    readmaps(_c("(.*)"), _c("(.+)") + b_str);
    map_act.swap(vMaps);
    vMaps.swap(map_befor);
    if (!vResults.empty())
      vResults.clear();
    if (map_act.size() >= num)
      return map_act[num - 1].baddr;
    return 0;
  }

  inline void OffsetPointer(std::vector<__DWORD64> offset_all, bool isAll)
  {
    /*
       搜索结果进行指针操作({0x10,0xD0,...}) 参数说明:
       vResults结果的地址+0x10转指针，转完指针+0xD0的地址...最终结果
     */
    if (offset_all.empty() || vResults.empty() || !isRunning() || ProcessBit < 1)
      return;
    std::vector<DWORD64> result_temp;
    int RSize = ProcessBit * 4;
    char buf;
    for (int i = 0; i < vResults.size(); i++)
    {
      DWORD64 addr_temp = 0;
      if (mem_read(vResults[i] + offset_all[0], &addr_temp, RSize) != RSize)
        continue;
      if (mem_read(addr_temp, &buf, 1) != 1 || (!isAll && !isInMaps(addr_temp)))
        continue;
      for (int n = 1; n < offset_all.size() && mem_read(addr_temp, &buf, 1) == 1;
           n++)
      {
        if (n == offset_all.size() - 1)
        {
          addr_temp += offset_all[n];
          break;
        }
        if (mem_read(addr_temp + offset_all[n], &addr_temp, RSize) != RSize ||
            (!isAll && !isInMaps(addr_temp)))
          break;
      }
      if (!isAll && !isInMaps(addr_temp))
        continue;
      if (mem_read(addr_temp, &buf, 1) == 1)
        result_temp.push_back(addr_temp);
    }
    vResults.clear();
    vResults.swap(result_temp);
  }

  template <class T>
  inline int UnkS(T &value)
  {
    /* 1 */
    size_t type_size = sizeof(value);
    if (!vResults.empty())
      vResults.clear();
    if (!isRunning())
      errprint(_c("PID error!"));
    int size_a = type_size * mysize, rSize = 0;
    DWORD64 cuA, addrTmp;
    for (size_t v = 0; v < vMaps.size(); v++)
    {
      rSize = vMaps[v].eaddr - vMaps[v].baddr;
      if (rSize > size_a)
        rSize = size_a;
      if (rSize < 1 || headAddr > vMaps[v].baddr || footAddr < vMaps[v].eaddr)
        continue;
      for (cuA = vMaps[v].baddr; cuA < vMaps[v].eaddr; cuA += rSize)
      {
        if (ms > 0)
          usleep(ms);
        if constexpr (std::is_same<__xor, T>::value)
        {
          if (ProcessBit == 1)
          {
            int vv = (int)value;
            uint buf[mysize] = {0};
            int buf_count = (int)mem_read(cuA, buf, rSize) / 4;

            if (buf_count < 1)
              continue;
            for (int i = 0; i < buf_count; i++)
            {
              uint addr_temp = cuA + i * 4;
              if (vv == (addr_temp ^ buf[i]))
                vResults.push_back(addr_temp);
            }
          }
          else
          {
            __DWORD64 vv = (__DWORD64)value;
            DWORD64 buf[mysize] = {0};
            size_a = 8 * mysize;
            int buf_count = (int)mem_read(cuA, buf, size_a) / 8;
            if (buf_count < 1)
              continue;
            for (int i = 0; i < buf_count; i++)
            {
              DWORD64 addr_temp = cuA + i * 8;
              if (vv == (addr_temp ^ buf[i]))
                vResults.push_back(addr_temp);
            }
          }
        }
        else
        {
          T buf[mysize] = {0};
          int buf_count = (int)mem_read(cuA, buf, rSize) / type_size;
          if (buf_count < 1)
            continue;
          for (int i = 0; i < buf_count; i++)
          {
            if (buf[i] == value)
              vResults.push_back(cuA + i * type_size);
          }
        }
      }
    }
    // 去重
    std::sort(vResults.begin(), vResults.end());
    vResults.erase(std::unique(vResults.begin(), vResults.end()), vResults.end());
    return vResults.size();
  }

  inline int SString(std::string value)
  {
    size_t type_size = sizeof(char);
    size_t str_len = value.size();
    if (str_len > 1024 || str_len < 2)
      return 0;
    if (!vResults.empty())
      vResults.clear();
    if (!isRunning())
      errprint(_c("PID error!"));
    size_t size_a = type_size * mysize;
    // print(_c("\n首次搜索......"));
    for (size_t v = 0; v < vMaps.size(); v++)
    {
      int rSize = vMaps[v].eaddr - vMaps[v].baddr - str_len;
      if (rSize > size_a)
        rSize = size_a;
      if (rSize < 1 || headAddr > vMaps[v].baddr || footAddr < vMaps[v].eaddr)
        continue;
      for (DWORD64 hAddr = vMaps[v].baddr; hAddr < vMaps[v].eaddr;
           hAddr += rSize)
      {
        char buf[mysize] = {0};
        int buf_size = (int)mem_read(hAddr, buf, rSize);
        if (buf_size < 1)
          continue;
        for (int i = 0; i < buf_size; i++)
        {
          if (buf[i] == value[0])
          {
            if (0 == memcmp(&buf[i], value.c_str(), str_len))
              vResults.push_back(hAddr + i * type_size);
          }
        }
        if (rSize == size_a)
          hAddr = hAddr - str_len;
      }
    }
    return vResults.size();
  }

  inline int SWstring(std::string value)
  {
    size_t type_size = sizeof(char);
    size_t str_len = value.size();
    if (str_len > 1024 || str_len < 2)
      return 0;
    if (!vResults.empty())
      vResults.clear();
    if (!isRunning())
      errprint(_c("PID error!"));
    size_t size_a = type_size * mysize;
    // print(_c("\n首次搜索......"));
    std::wstring str_temp = c2w(value.c_str());
    char *value_str = new char[str_temp.size() * 2 + 1];
    value_str[str_temp.size()] = '\0';
    w2c_b(str_temp, value_str);
    str_len = str_temp.size() * 2;
    for (size_t v = 0; v < vMaps.size(); v++)
    {
      int rSize = vMaps[v].eaddr - vMaps[v].baddr - str_len;
      if (rSize > size_a)
        rSize = size_a;
      if (rSize < 1 || headAddr > vMaps[v].baddr || footAddr < vMaps[v].eaddr)
        continue;
      for (DWORD64 hAddr = vMaps[v].baddr; hAddr < vMaps[v].eaddr;
           hAddr += rSize)
      {
        char buf[mysize] = {0};
        int buf_size = (int)mem_read(hAddr, buf, rSize);
        if (buf_size < 1)
          continue;
        for (int i = 0; i < buf_size; i += 2)
        {
          if (0 == memcmp(&buf[i], value_str, str_len))
            vResults.push_back(hAddr + i * type_size);
        }
        if (rSize == size_a)
          hAddr = hAddr - str_len;
      }
    }
    if (value_str)
    {
      delete[] value_str;
      value_str = NULL;
    }
    return vResults.size();
  }

  template <class T>
  inline int UnkOffset(T &value, __DWORD64 &offset)
  {
    if (vResults.empty())
      return 0;
    if (!isRunning())
      errprint(_c("PID error!"));
    // print(_c("再次搜索..."));
    std::vector<DWORD64> vResults_temp;
    size_t v_size = sizeof(value);
    for (int i = 0; i < vResults.size(); i++)
    {
      if constexpr (std::is_same<__xor, T>::value)
      {
        if (ProcessBit == 1)
        {
          uint buf = 0;
          int vv = (int)value;
          mem_read(vResults[i] + offset, &buf, 4);
          if (((vResults[i] + offset) ^ buf) == vv)
            vResults_temp.push_back(vResults[i]);
        }
        else
        {
          DWORD64 buf = 0;
          __DWORD64 vv = (__DWORD64)value;
          mem_read(vResults[i] + offset, &buf, 8);
          if (((vResults[i] + offset) ^ buf) == vv)
            vResults_temp.push_back(vResults[i]);
        }
      }
      else
      {

        T buf = 0;
        mem_read(vResults[i] + offset, &buf, v_size);
        if (buf == value)
          vResults_temp.push_back(vResults[i]);
      }
    }
    vResults.clear();
    vResults.swap(vResults_temp);
    return vResults.size();
  }

  template <class T>
  inline int UnkVOffset(T &value, std::vector<__DWORD64> &vOffset)
  {
    if (vResults.empty())
      return 0;
    if (!isRunning())
      errprint(_c("PID error!"));
    // print(_c("跳级改善..."));
    std::vector<DWORD64> vResults_temp;
    size_t v_size = sizeof(value);
    int RSize = ProcessBit * 4;
    char buf;
    for (int i = 0; i < vResults.size(); i++)
    {
      DWORD64 addr_temp = 0;
      if (mem_read(vResults[i] + vOffset[0], &addr_temp, RSize) != RSize)
        continue;
      if (mem_read(addr_temp, &buf, 1) != 1)
        continue;
      for (int n = 1; n < vOffset.size() && mem_read(addr_temp, &buf, 1) == 1;
           n++)
      {
        if (n == vOffset.size() - 1)
        {
          addr_temp += vOffset[n];
          break;
        }
        if (mem_read(addr_temp + vOffset[n], &addr_temp, RSize) != RSize)
          break;
      }
      if (mem_read(addr_temp, &buf, 1) != 1)
        continue;

      if constexpr (std::is_same<__xor, T>::value)
      {
        if (ProcessBit == 1)
        {
          uint buf = 0;
          int vv = (int)value;
          mem_read(addr_temp, &buf, 4);
          if (((addr_temp) ^ buf) == vv)
            vResults_temp.push_back(vResults[i]);
        }
        else
        {
          DWORD64 buf = 0;
          __DWORD64 vv = (__DWORD64)value;
          mem_read(addr_temp, &buf, 8);
          if (((addr_temp) ^ buf) == vv)
            vResults_temp.push_back(vResults[i]);
        }
      }
      else
      {

        T buf = 0;
        mem_read(addr_temp, &buf, v_size);
        if (buf == value)
          vResults_temp.push_back(vResults[i]);
      }
    }
    vResults.clear();
    vResults.swap(vResults_temp);
    return vResults.size();
  }

  template <class T>
  inline int UnkW(T &value, __DWORD64 &offset)
  {
    if (vResults.empty())
      return 0;
    if (!isRunning())
      errprint(_c("PID error!"));
    size_t v_size_a = sizeof(value);
    for (int i = 0; i < vResults.size(); i++)
    {
      if constexpr (std::is_same<__xor, T>::value)
      {
        if (ProcessBit == 1)
        {
          int value_temp = ((uint)(vResults[i] + offset) ^ value);
          mem_write(vResults[i] + offset, &value_temp, 4);
        }
        else
        {
          __DWORD64 value_temp = ((DWORD64)(vResults[i] + offset) ^ value);
          mem_write(vResults[i] + offset, &value_temp, 8);
        }
      }
      else
      {
        mem_write(vResults[i] + offset, &value, v_size_a);
      }
    }
    // print(_c("修改执行成功!\n"));
    return vResults.size();
  }

  inline int WString(std::string value, __DWORD64 offset)
  {
    if (vResults.empty())
      return 0;
    if (!isRunning())
      errprint(_c("PID error!"));
    int size_a = value.size();
    for (int i = 0; i < vResults.size(); i++)
      mem_write(vResults[i] + offset, (void *)value.c_str(), size_a);
    // print(_c("修改执行成功!\n"));
    return vResults.size();
  }

  inline int WWstring(std::string value, __DWORD64 offset)
  {
    if (vResults.empty())
      return 0;
    if (!isRunning())
      errprint(_c("PID error!"));

    size_t v_size = value.size() * 2;
    char *value_str = new char[v_size + 1];
    std::wstring str_temp = c2w(value.c_str());
    w2c_b(str_temp, value_str);
    str_temp.resize(0);
    value_str[v_size] = '\0';
    for (int i = 0; i < vResults.size(); i++)
      mem_write(vResults[i] + offset, (void *)value_str, v_size);
    // print(_c("修改执行成功!\n"));
    if (value_str)
    {
      delete[] value_str;
      value_str = NULL;
    }
    return vResults.size();
  }

  template <class T>
  inline T UnkR(DWORD64 &addr)
  {
    Rflag = 1;
    if constexpr (std::is_same<__xor, T>::value)
    {
      if (ProcessBit == 1)
      {
        uint value;
        if (mem_read(addr, &value, sizeof(value)) == sizeof(value))
          return (int)(((uint)addr) ^ value);
      }
      else
      {
        DWORD64 value;
        if (mem_read(addr, &value, sizeof(value)) == sizeof(value))
          return (__DWORD64)(addr ^ value);
      }
    }
    else
    {
      T value;
      if (mem_read(addr, &value, sizeof(value)) == sizeof(value))
        return value;
    }

    Rflag = 0;
    return 0;
  }

  inline std::string RString(DWORD64 addr, size_t MaxLen, char endChar)
  {
    std::string str;
    Rflag = 0;
    char buf[2048];
    int r_size = mem_read(addr, buf, MaxLen);
    if (r_size < 1 || MaxLen > 2048)
      return str;
    for (size_t i = 0; i < r_size; i++)
    {
      if (buf[i] != endChar)
        str.resize(str.size() + 1, buf[i]);
      else
        break;
    }
    if (str.size() > 0)
      Rflag = 1;
    return str;
  }

  inline std::wstring RWstring(DWORD64 addr, size_t MaxLen, wchar_t endChar)
  {
    std::wstring str;
    Rflag = 0;
    size_t myWSize = 2;
    int r_size = MaxLen * myWSize;
    char *buf = new char[r_size + 1];
    buf[r_size] = '\0';
    r_size = mem_read(addr, buf, r_size) / myWSize;
    if (r_size < 1)
      return str;
    for (size_t i = 0; i < r_size; i++)
    {
      wchar_t str_a = '\0';
      memcpy(&str_a, &buf[i * myWSize], myWSize);
      if (str_a != endChar)
        str.resize(str.size() + 1, str_a);
      else
        break;
    }
    if (buf)
    {
      delete[] buf;
      buf = NULL;
    }
    if (str.size() > 0)
      Rflag = 1;
    return str;
  }

  inline DWORD64 JumpPointer(DWORD64 addr,
                             std::vector<DWORD64> addr_list)
  { // 指针智能跳转
    if (addr == 0 || addr_list.size() == 0)
      return 0;
    for (int i = 0; i < addr_list.size(); i++)
    {
      if (i == addr_list.size() - 1)
      {
        addr += addr_list[i];
      }
      else
      {
        addr = RPointer(addr + addr_list[i]);
        if (addr < 0x4FFFF || addr > 0x00007fffffffffff)
        {
          addr = 0;
          break;
        }
      }
    }
    return addr;
  }

  // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  inline int readmaps(std::string flag_rex, std::string infor_rex,
                      bool isPrintf)
  {
    if (!vMaps.empty())
      vMaps.clear();
    if (!isRunning())
    {
      print(_c("PID error"));
      return 0;
    }
    if (!vResults.empty())
      vResults.clear();
    std::string allMaps;
    std::ifstream t(_c("/proc/") + std::to_string(pPid) + _c("/maps"),
                    std::ios::in);
    if (t.is_open())
    {
      allMaps = std::string((std::istreambuf_iterator<char>(t)),
                            std::istreambuf_iterator<char>());
      t.close();
    }
    else
    {
      print("打开maps失败!");
      return 0;
    }
    std::vector<std::string> vRes;
    strToV(vRes, allMaps, "\n");
    DWORD64 searchSize = 0, totalVirtualSize = 0, totalSize = 0;
    std::string printOne;

    for (int i = 0; i < vRes.size(); i++)
    {
      MAPS2 map_temp = {0};
      sscanf(vRes[i].c_str(), "%llx-%llx %s %s %s %s %[^\n]",
             &map_temp.maps.baddr, &map_temp.maps.eaddr, map_temp.flag,
             map_temp.pgoff, map_temp.s_dev, map_temp.s_ino, map_temp.infor);
      DWORD64 sizeTmp = map_temp.maps.eaddr - map_temp.maps.baddr;
      std::string flag = map_temp.flag;
      std::string pgoff = map_temp.pgoff;
      std::string s_dev = map_temp.s_dev;
      std::string s_ino = map_temp.s_ino;
      std::string infor = map_temp.infor;
      {
        if (regex_match(infor, std::regex(infor_rex)) &&
            regex_match(flag, std::regex(flag_rex)))
        {
          printOne = "范围[ALL]";
          totalSize += sizeTmp;
          if (mis_page_check)
          {
            if (mis_page_check->check_mem(
                    map_temp.maps.baddr))
            { // 如果是缺页内存
              totalVirtualSize += sizeTmp;
              continue;
            }
          }
          else
            searchSize += sizeTmp;
          vMaps.push_back(map_temp.maps);
          if (isPrintf && isDebug)
          {
            std::cout << _c("大小: 0x") << std::hex << sizeTmp << " " << infor
                      << std::endl
                      << map_temp.maps.baddr << "~" << map_temp.maps.eaddr
                      << std::endl;
          }
          vMaps.push_back(map_temp.maps);
        }
      }
    }
    if (isDebug)
    {
      std::string t_a = _c("M");
      std::cout << std::dec << "总大小(" << ((double)totalSize) / 1000000 << t_a
                << ")," << printOne << "\n  缺页("
                << ((double)totalVirtualSize) / 1000000 << t_a << ")\n  搜索("
                << ((double)searchSize) / 1000000 << t_a << ")" << std::endl;
    }
    return vMaps.size();
  }

  inline void print_maps(DWORD isAll)
  {
    if (isDebug)
    {
      DWORD64 totalSize = 0;
      for (int i = 0; i < vMaps.size() && (i < isAll || 0 == isAll); i++)
      {
        DWORD64 sizeTmp = vMaps[i].eaddr - vMaps[i].baddr;
        std::cout << _c("大小: 0x") << std::hex << sizeTmp << std::endl
                  << vMaps[i].baddr << "~" << vMaps[i].eaddr << std::endl;
        if (sizeTmp > 0)
          totalSize += sizeTmp;
      }
      std::string t_a = _c("M");
      std::cout << _c("总大小: ") << std::dec << ((double)totalSize) / 1000000
                << t_a << _c("(") << totalSize << _c("子节)") << std::endl;
    }
  }

  inline bool isInMaps(DWORD64 addr)
  {
    for (int i = 0; i < vMaps.size(); i++)
    {
      if (vMaps[i].baddr <= addr && addr <= vMaps[i].eaddr)
        return true;
    }
    return false;
  }

  inline void ResultsCut(int b_num, int count_num)
  {
    std::vector<DWORD64> vresults_temp(vResults.begin() + b_num,
                                       vResults.begin() + count_num + b_num);
    vResults = vresults_temp;
  }

  inline void ResultsAppend(DWORD64 addr_temp) { vResults.push_back(addr_temp); }

  inline bool isRunning(std::string pack_name)
  {
    int pidTmp = getPid(pack_name);
    if (pidTmp > 0)
      return true;
    return false;
  }

  inline bool isRunning(int pid)
  {
    if (pid < 0x1)
      return false;
    char path[32];
    snprintf(path, sizeof(path), "/proc/%d", pid);
    struct stat st;
    if (stat(path, &st) == 0)
    {
      // 检查是否是目录
      if (S_ISDIR(st.st_mode))
      {
        return true;
      }
    }
    return false;
  }

  inline bool isRunning() { return isRunning(pPid); };

  inline int isX64(DWORD pid)
  {
    char buf[101] = {0};
    int result = readlink(
        (_c("/proc/") + std::to_string(pid) + _c("/exe")).c_str(), buf, 100);
    if (-1 == result)
      return -1;
    std::string path = std::string(buf);
    path.resize(result);
    std::ifstream ofile(path, std::ios::in | std::ios::binary);
    if (ofile)
    {
      ofile.read(buf, 10);
      ofile.close();
      return buf[4];
    }
    return -1;
  }

  inline int getPid(std::string pack)
  {
    if (pack.size() == 0)
      return -1;
    DWORD pid_temp = 0;
    DIR *dir = NULL;
    struct dirent *ptr = NULL;
    dir = opendir(_c("/proc"));
    if (NULL != dir)
    {
      while ((ptr = readdir(dir)) != NULL)
      {
        if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0) ||
            ptr->d_type != DT_DIR)
        {
          continue;
        }
        std::string pack_tmp =
            RF_E(_c("/proc/") + std::string(ptr->d_name) + _c("/cmdline"), 1);
        if (is_all_match)
        {
          if (pack == pack_tmp)
          {
            pid_temp = atoi(ptr->d_name);
            break;
          }
        }
        else
        {
          if (pack_tmp.find(pack) != -1)
          {
            pid_temp = atoi(ptr->d_name);
            break;
          }
        }
      }
    }
    closedir(dir);
    return pid_temp;
  }

  inline int getPid() { return pPid; }

  inline int killprocess(const char *bm)
  {
    int pid = getPid(bm);
    if (pid == 0)
      return -1;
    char mll[32];
    sprintf(mll, _c("kill %d"), pid);
    system(mll); // 杀掉进程
    return 0;
  }

  inline bool isExistGG()
  {
    bool isExist = false;
    DIR *dir = NULL;
    DIR *dirGG = NULL;
    struct dirent *ptr = NULL;
    struct dirent *ptrGG = NULL;
    char filepath[256];
    char filetext[128];
    dir = opendir(_c("/data/data"));
    int flag = 1;
    if (dir != NULL)
    {
      while (flag && (ptr = readdir(dir)) != NULL)
      {
        if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0))
          continue;
        if (ptr->d_type != DT_DIR)
          continue;
        sprintf(filepath, "/data/data/%s/files", ptr->d_name);
        dirGG = opendir(filepath);
        if (dirGG != NULL)
        {
          while ((ptrGG = readdir(dirGG)) != NULL)
          {
            if ((strcmp(ptrGG->d_name, ".") == 0) ||
                (strcmp(ptr->d_name, "..") == 0))
              continue;
            if (ptrGG->d_type != DT_DIR)
              continue;
            if (strstr(ptrGG->d_name, _c("GG")))
              isExist = true;
          }
        }
      }
    }
    closedir(dir);
    closedir(dirGG);
    return isExist;
  }

  inline bool isRunGG(bool isKill)
  {
    bool isExist = false;
    DIR *dir = NULL;
    DIR *dirGG = NULL;
    struct dirent *ptr = NULL;
    struct dirent *ptrGG = NULL;
    char filepath[256];
    char filetext[128];
    dir = opendir(_c("/data/data"));
    int flag = 1;
    if (dir != NULL)
    {
      while (flag && (ptr = readdir(dir)) != NULL)
      {
        if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0))
          continue;
        if (ptr->d_type != DT_DIR)
          continue;
        sprintf(filepath, "/data/data/%s/files", ptr->d_name);
        dirGG = opendir(filepath);
        if (dirGG != NULL)
        {
          while ((ptrGG = readdir(dirGG)) != NULL)
          {
            if ((strcmp(ptrGG->d_name, ".") == 0) ||
                (strcmp(ptr->d_name, "..") == 0))
              continue;
            if (ptrGG->d_type != DT_DIR)
              continue;
            if (strstr(ptrGG->d_name, _c("GG")))
            {

              int pid = getPid(ptr->d_name);
              if (pid == 0)
                continue;
              else
              {
                isExist = true;
                if (isKill)
                  killprocess(ptr->d_name);
              }
            }
          }
        }
      }
    }
    closedir(dir);
    closedir(dirGG);
    return isExist;
  }

  inline int WF(std::string path, std::string str, int flag)
  {
    std::fstream outFile(path, flag);
    if (!outFile.is_open())
      return 0;
    outFile << str;
    outFile.close();
    return 1;
  }

  inline std::string RF(std::string path, int line)
  {
    if (line == -1)
    {
      std::ifstream t(path, std::ios::in | std::ios::binary);
      if (!t.is_open())
        return "";
      std::string buf((std::istreambuf_iterator<char>(t)),
                      std::istreambuf_iterator<char>());
      t.close();
      return buf;
    }
    else
    {
      std::string str, str_temp2;
      int ii = 0;
      std::ifstream readFile(path.c_str());
      if (readFile && line > 0)
      {
        while (getline(readFile, str_temp2) && ii < line - 2)
          ii++;
        getline(readFile, str);
        readFile.close();
      }
      if (line == 1)
        return str_temp2;
      else
        return str;
    }
  }

  inline std::string RF_E(std::string path, int line, char ends)
  {
    std::string buf;
    std::ifstream in(path);
    if (line > 0)
      while (line && getline(in, buf, ends))
        line--;
    else
      buf = std::string((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    in.close();
    return buf;
  }

  inline void print(std::string buf)
  {
    if (!isDebug)
      return;
    std::cout << buf << std::endl;
  }

  inline void print(DWORD isAll)
  {
    if (!isDebug)
      return;
    std::cout << std::endl
              << _c("结果: ") << std::to_string(vResults.size()) << std::endl;
    if (vResults.size() < 1)
      return;
    std::cout << _c("打印:") << std::endl
              << _c("-----------+-----------") << std::endl;
    if (isAll < 1)
    {
      for (int v = 0; v < vResults.size(); v++)
        std::cout << std::setiosflags(std::ios::uppercase) << std::hex
                  << vResults[v] << std::endl;
    }
    else
    {
      for (int v = 0; v < isAll && v < vResults.size(); v++)
        std::cout << std::setiosflags(std::ios::uppercase) << std::hex
                  << vResults[v] << std::endl;
      if (vResults.size() >= D_PRINT && isAll > D_PRINT)
        std::cout << _c("......(默认只打印") + std::to_string(D_PRINT) +
                         _c("个结果, 如需全部打印, 请使用'print(0);')")
                  << std::endl
                  << std::endl;
    }
    std::cout << _c("-----------+-----------") << std::endl;
    std::cout << _c("结果: ") << std::to_string(vResults.size()) << std::endl
              << std::endl;
  }

  template <class T>
  inline void print(DWORD isAll)
  {
    if (!isDebug)
      return;
    std::cout << std::endl
              << _c("结果: ") << std::to_string(vResults.size()) << std::endl;
    if (vResults.size() < 1)
      return;
    std::cout << _c("打印:") << std::endl
              << _c("-----------+-----------") << std::endl;
    if (isAll < 1)
    {
      for (int v = 0; v < vResults.size(); v++)
      {
        T vTmp;
        mem_read(vResults[v], &vTmp, sizeof(vTmp));
        std::cout << std::setiosflags(std::ios::uppercase) << std::hex
                  << vResults[v] << " " << std::to_string(vTmp) << std::endl;
      }
    }
    else
    {
      for (int v = 0; v < isAll && v < vResults.size(); v++)
      {
        T vTmp;
        mem_read(vResults[v], &vTmp, sizeof(vTmp));
        std::cout << std::setiosflags(std::ios::uppercase) << std::hex
                  << vResults[v] << " " << std::to_string(vTmp) << std::endl;
      }
      if (vResults.size() >= D_PRINT && isAll > D_PRINT)
        std::cout << _c("......(默认只打印") + std::to_string(D_PRINT) +
                         _c("个结果, 如需全部打印, 请使用'print(0);')")
                  << std::endl
                  << std::endl;
    }
    std::cout << _c("-----------+-----------") << std::endl;
    std::cout << _c("结果: ") << std::to_string(vResults.size()) << std::endl
              << std::endl;
  }

  // 定义一个函数来处理内存区域
  static void processMemory(void *buffer, size_t size)
  {
    uint64_t *ptr = (uint64_t *)buffer;
    size_t numInts =
        size / sizeof(uint64_t); // 计算buffer中可以容纳的64位整数的数量

    for (size_t i = 0; i < numInts; i++)
    {
      // 检查每个64位整数的最高8位是否为0xB4
      if ((ptr[i] >> 56) == 0xB4)
      {
        // 去掉最高8位的0xB4
        ptr[i] &= 0xFFFFFFFFFFFFFF;
      }
    }
  }

  // 写入日志
  inline void log_text(std::string text)
  {
    const char *log_path = "/data/local/tmp/mis_mem";
    // 检查文件大小
    struct stat st;
    long file_size = 0;
    if (stat(log_path, &st) == 0)
    {
      file_size = st.st_size;
    }
    // 超过1MB (1048576字节)则替换写入，否则追加
    std::ios_base::openmode mode =
        (file_size > 1048576) ? std::ios::trunc : std::ios::app;
    // 写入日志
    std::ofstream log_file(log_path, mode);
    if (log_file.is_open())
    {
      log_file << text;
      log_file.close();
    }
  }

  inline bool is_valid(DWORD64 &addr, DWORD64 minAddr = 0x400FF, DWORD64 maxAddr = 0x00007fffffffffff)
  {
    if (addr >= maxAddr || addr <= minAddr)
      return 0;
    return 1;
  }

  inline size_t mem_read(DWORD64 addr, void *buffer, size_t size)
  {
    if (!is_valid(addr))
      return 0;
    if (mis_page_check)
    {
      if (mis_page_check->check_mem(addr))
      { // 如果是缺页内存
        // log_text("\n[WARN]该内存地址是缺页内存! 已跳过读取:"
        // +std::to_string(addr));
        return 0;
      }
    }
    if (currentWM >= 0x10)
    {
      lseek(pPid, addr, SEEK_SET);
      return read(pPid, buffer, size);
    }
    int read_size = 0;
    // 内核读取和普通读取
    if (sys_mem_all != nullptr)
    {
      bool is_read = sys_mem_all->read(addr, buffer, size);
      if (is_read)
        read_size = size;
    }
    else
    {
      char buf[40960] = {0};
      struct iovec iov_ReadBuffer, iov_ReadOffset;
      iov_ReadBuffer.iov_base = buf;
      iov_ReadBuffer.iov_len = size;
      iov_ReadOffset.iov_base = (void *)addr;
      iov_ReadOffset.iov_len = size;
      read_size = syscall(SYS_process_vm_readv, pPid, &iov_ReadBuffer, 1,
                          &iov_ReadOffset, 1, 0);
      if (read_size > 0)
      {
        memcpy(buffer, buf, size);
      }
    }
    if (sizeof(addr) == 8)
      processMemory(buffer, size);
    return read_size;
  }

  inline size_t mem_write(DWORD64 addr, void *buffer, size_t size)
  {
    if (!is_valid(addr))
      return 0;
    if (mis_page_check)
    {
      if (mis_page_check->check_mem(addr))
      { // 如果是缺页内存
        // log_text("\n[WARN]该内存地址是缺页内存! 已跳过写入:"
        // +std::to_string(addr));
        return 0;
      }
    }
    if (currentWM >= 0x10)
    {
      lseek(pPid, addr, SEEK_SET);
      return write(pPid, buffer, size);
    }
    int flag_a = -1;
    // 内核写入和普通写入
    if (sys_mem_all != nullptr)
    {
      bool is_read = sys_mem_all->write(addr, buffer, size);
      if (is_read)
        flag_a = size;
    }
    else
    {
      if (currentWM == W_Attach)
      { // 附加写入
        flag_a = mem_write_ptrace(addr, buffer, size);
      }
      else if (currentWM == W_Open)
      {
        flag_a = mem_write_open(addr, buffer, size);
      }
      else
      { // syscall方式写入
        struct iovec iov_WriteBuffer, iov_WriteOffset;
        iov_WriteBuffer.iov_base = buffer;
        iov_WriteBuffer.iov_len = size;
        iov_WriteOffset.iov_base = (void *)addr;
        iov_WriteOffset.iov_len = size;
        flag_a = syscall(SYS_process_vm_writev, pPid, &iov_WriteBuffer, 1,
                         &iov_WriteOffset, 1, 0);
      }
    }
    // if (isDebug) {
    // if (-1 == flag_a)
    // std::cout << "修改失败! 地址: 0x" << std::hex << addr <<
    // "syscall(errno="
    // << std::to_string(errno) << "))" << std::endl; else std::cout <<
    // "修改成功! 地址: 0x" << std::hex
    // << addr << std::endl;
    // }
    return flag_a;
  }

  inline size_t mem_write_ptrace(DWORD64 addr, void *buffer, size_t size)
  {
    int flag_a = -1, stat;
    do
    {
      char *buf = (char *)buffer;
      // ptrace附加写入
      flag_a = ptrace(PTRACE_ATTACH, pPid, NULL, NULL);
      wait(&stat);
      if (ProcessBit == 2)
      {
        for (int i = 0; i < size; i++)
        {
          ptrace(PTRACE_POKEDATA, pPid, (addr + i), buf[0]);
          buf++;
        }
      }
      else
      {
        DWORD addr_temp = (DWORD)addr;
        for (int i = 0; i < size; i++)
        {
          ptrace(PTRACE_POKEDATA, pPid, (addr_temp + i), buf[0]);
          buf++;
        }
      }
      flag_a = ptrace(PTRACE_DETACH, pPid, NULL, NULL);
    } while (0);

    // if (isDebug) {
    // std::string ptxt;
    // switch (errno)
    // {
    // case EPERM:
    // ptxt = "特殊进程不可以被跟踪或进程已经被跟踪:
    // (TracerPid="+std::to_string(GetTracerPid())+"))"; break; case
    // ESRCH: ptxt = "指定的进程不存在!"; break; case EIO:
    // ptxt = "请求非法!"; break; default: ptxt =
    // "未知(errno=" + std::to_string(errno) + "))"; break;
    // }
    // if (-1 == flag_a)
    // std::cout << "修改失败! 地址: 0x" << std::hex << addr << "
    // 原因:" <<
    // ptxt
    // << std::endl; else std::cout << "修改成功! 地址: 0x" <<
    // std::hex
    // << addr
    // << std::endl;
    // }
    return flag_a;
  }

  inline size_t mem_write_open(DWORD64 addr, void *buffer,
                               size_t size)
  { // 强制写入
    if (pPid == 0)
      return 0;
    if (sys_mem_all != nullptr)
    {
      print("内核模式下不支持此功能!");
      return 0;
    }
    char lj[64];
    int handle;
    sprintf(lj, "/proc/%d/mem", pPid);
    handle = open(lj, O_RDWR);
    if (handle > 0)
    {
      lseek(handle, 0, SEEK_SET);
      pwrite64(handle, buffer, size, addr);
      close(handle);
    }
    return 0;
  }

  inline int GetTracerPid(int MainPid)
  {
    if (MainPid < 1)
    {
      MainPid = pPid;
    }
    if (!isRunning(MainPid))
    {
      print(_c("PID error"));
      return 0;
    }
    if (sys_mem_all != nullptr)
    {
      print("内核模式下不支持此功能!");
      return 0;
    }
    int tracer_pid = 0;
    std::string allMaps;
    std::ifstream t(_c("/proc/") + std::to_string(MainPid) + _c("/status"),
                    std::ios::in);
    if (t.is_open())
    {
      allMaps = std::string((std::istreambuf_iterator<char>(t)),
                            std::istreambuf_iterator<char>());
      t.close();
    }
    else
    {
      print("打开status失败!");
      return 0;
    }
    std::vector<std::string> vRes;
    strToV(vRes, allMaps, "\n");
    for (int i = 0; i < vRes.size(); i++)
    {
      if (std::string(vRes[i].c_str()).find(_c("TracerPid")) != -1)
      {
        sscanf(vRes[i].c_str(), "%*s %d", &tracer_pid);
        break;
      }
    }
    return tracer_pid;
  }

  inline std::wstring c2w(const char *pc)
  {
    std::wstring val = L"";
    if (NULL == pc)
      return val;
    size_t size_of_wc;
    size_t destlen = mbstowcs(0, pc, 0);
    if (destlen == (size_t)(-1))
      return val;
    size_of_wc = destlen + 1;
    wchar_t *pw = new wchar_t[size_of_wc];
    mbstowcs(pw, pc, size_of_wc);
    val = pw;
    delete[] pw;
    return val;
  }

  inline std::string w2c(const wchar_t *pw)
  {
    std::string val = "";
    if (!pw)
      return val;
    size_t size = wcslen(pw) * sizeof(wchar_t);
    char *pc = NULL;
    if (!(pc = (char *)malloc(size)))
      return val;
    size_t destlen = wcstombs(pc, pw, size);
    /* 转换不为空时，返回值为-1。如果为空，返回值0 */
    if (destlen == (size_t)(0))
      return val;
    val = pc;
    delete pc;
    return val;
  }

  inline std::string u16tocs(std::u16string str)
  {
    std::wstring wstr;
    for (int i = 0; i < str.size(); i++)
      wstr.push_back((wchar_t)str[i]);
    return w2c(wstr.c_str());
  }

  inline std::u16string cstou16(std::string str)
  {
    std::wstring wstr = c2w(str.c_str());
    std::u16string u16str;
    for (int i = 0; i < wstr.size(); i++)
      u16str.push_back((char16_t)wstr[i]);
    return u16str;
  }

  inline int strToV(std::vector<std::string> &str_v, std::string data_s,
                    std::string sub_s, std::string remove_s)
  {
    // 存在remove_s字符串则去掉再分割
    if (!remove_s.empty())
    {
      data_s.erase(std::remove(data_s.begin(), data_s.end(), remove_s[0]),
                   data_s.end());
    }
    // 字符串切割放进std::vector中
    if (!str_v.empty())
      str_v.clear();
    int find1 = data_s.find(sub_s), find_old = 0;
    int count = 0;
    if (find1 == data_s.npos)
    {
      if (!data_s.empty())
      {
        str_v.push_back(data_s);
      }
      return str_v.size();
    }
    while (find1 != data_s.npos)
    {
      str_v.push_back(data_s.substr(find_old, find1 - find_old));
      find_old = find1 + 1;
      find1 = data_s.find(sub_s, find_old);
    }
    if (find_old < data_s.size())
      str_v.push_back(data_s.substr(find_old, data_s.size() - find_old));
    return str_v.size();
  }

  inline bool Mem::initMisCheck()
  {
    if (mis_page_check != nullptr)
    {
      delete mis_page_check;
      mis_page_check = nullptr;
    }
    mis_page_check = new PageMapReader(pPid);
    return mis_page_check->isInit();
  }

}; // namespace Mem
