#include "pscan.h"
#include "memextend.h"
#include <iostream>

int main()
{
    // 创建PScan对象 (假定为64位, 32位改uint32_t)
    // Create PScan object (assumes 64-bit, use uint32_t for 32-bit)
    pscan::PScan<size_t> pscan_tool;

    memtool::base::target_pid = memtool::base::get_pid("com.LanPiaoPiao.PlantsVsZombiesRH");
    if (memtool::base::target_pid == -1)
        return -1;
    
    // memtool::base::target_pid = 9999; 获取有错就先这样
    
    printf("pid %d\n", memtool::base::target_pid);

    memtool::extend::get_target_mem();

    memtool::extend::set_mem_ranges(memtool::Anonymous + memtool::C_alloc + memtool::C_bss + memtool::C_data);

    // 获取指针
    // Get pointers
    printf("%ld\n", pscan_tool.getPointers(0, 0, false, 10, 1 << 20));

    // 设置目标地址
    // Set target address
    std::vector<size_t> addr;
    addr.emplace_back(0x742F5DFD4C);

    // 扫描指针链并输出到文件 (深度6层, 偏移2500)
    // Scan pointer chain and output to file (depth 6, offset 2500)
    printf("%ld\n", pscan_tool.scanPointerChain(addr, 6, 2500, false, 0, "/data/local/tmp/pscan_tmp"));

    // 格式化输出示例 (已注释)
    // Format output example (commented out)
    /*
    pscan::PScan<size_t> pscan_format;
    printf("%ld\n", pscan_format.formatOutputFile("1", "2")); // 读取文件1并输出到文件2
    // printf("%ld\n", pscan_format.formatOutputFolder("1", "2")); // 读取文件1并输出到文件夹2
    */
    
    return 0;
}
