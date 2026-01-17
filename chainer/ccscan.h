//
// Create by 青杉白衣 on 2023
//

#pragma once

#include "cscan.h"

// 标准的单个指针偏移保存结构
struct STRUCT_PLIST{
    std::shared_ptr<vm_static_data> p_static_data = nullptr;
    std::vector<int> v_off;
};

namespace chainer
{

template <class T>
struct cscan : public ::chainer::scan<T>
{
    size_t get_pointers(T start, T end, bool rest, int count, int size);

    bool is_static_pointer(T &addr, vm_static_data *p_static_data=nullptr);

    size_t scan_pointer_chain(std::vector<T> &addr, int depth, size_t offset, bool limit, size_t plim, FILE *outstream);

    // 指针结果
    size_t get_scanned_rows(std::vector<STRUCT_PLIST> &v_results, int index_start=1, int max_rows=10000);
    cscan();
    ~cscan();

private:
    // 递归收集偏移的辅助函数
    void collect_offsets_recursive(
        std::vector<utils::mapqueue<chainer::pointer_dir<T> *>> &contents, 
        int current_level, 
        int current_index, 
        std::vector<int> &current_path, 
        std::vector<std::vector<int>> &all_paths,
        int depth);
    std::vector<STRUCT_PLIST> saved_results;
};

extern template class chainer::cscan<uint32_t>;
extern template class chainer::cscan<size_t>;

} // namespace chainer