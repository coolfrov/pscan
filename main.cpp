#include "ccformat.h"
#include "ccscan.h"
#include <iostream>
#include <unordered_map>
#include <vector>

int main()
{
    chainer::cscan<size_t> t; // 假定为64位 32位改uint32_t

    // memtool::base::target_pid = memtool::base::get_pid("com.LanPiaoPiao.PlantsVsZombiesRH");
    // if (memtool::base::target_pid == -1)
    //     return -1;

    // // memtool::base::target_pid = 9999; 获取有错就先这样

    // printf("pid %d\n", memtool::base::target_pid);

    // memtool::extend::get_target_mem();

    // memtool::extend::set_mem_ranges(memtool::Anonymous + memtool::C_alloc + memtool::C_bss + memtool::C_data);

    // printf("%d\n", t.get_pointers(0, 0, false, 10, 1 << 20));

    // memtool::base::target_pid = -1;
    Mem::mem("com.LanPiaoPiao.PlantsVsZombiesRH");
    int mem_range = Mem::A | Mem::CD | Mem::CB | Mem::CA | Mem::JH;

    std::cout << "====正在收集指针映射集====" << std::endl;
    int res_count = t.custom_get_pointers(pPid, mem_range);
    printf("%d\n", res_count);

    std::cout << "====正在进行指针扫描====" << std::endl;
    std::vector<size_t> addr;
    addr.emplace_back(0x742F5DFD4C);
    auto f = fopen("/data/local/tmp/pscan_tmp", "wb+");
    res_count = t.scan_pointer_chain(addr, 4, 2500, false, 0, f);
    printf("%ld\n", res_count); // x层 偏移n
    fclose(f);                  // 现在已经结束了 后面的是格式化

    std::cout << "====分页获取指针结果并输出====" << std::endl;
    std::vector<STRUCT_PLIST> pointer_result;
    int page_size = 10000;
    for (int n = 0; n < res_count; n += page_size)
    {
        int rows_count = t.get_scanned_rows(pointer_result, n, page_size);
        for (int i = 0; i < pointer_result.size(); i++)
        {
            auto &item = pointer_result[i];
            std::cout << std::dec << i + 1 << ".[" << item.p_static_data->name << "]" << std::hex << item.p_static_data->start;
            for (auto &j : item.v_off)
            {
                std::cout << std::hex << "->" << j;
            }
            std::cout << std::endl;
        }
        std::cout << std::dec << "已遍历" << n << "~" << n+page_size << ",回车继续遍历." << std::endl;
        getchar();
    }
    /*chainer::cformat<size_t> t2;
    auto f2 = fopen("1", "rb+");

    printf("%ld\n", t2.format_bin_chain_data(f2, "2", 0)); // 文件
    //  printf("%ld\n", t2.format_bin_chain_data(f2, "2", 1)); // 文件夹 需要在当前目录有2文件夹

    fclose(f2);*/
    return 0;
}
