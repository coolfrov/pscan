//
// Create by 青杉白衣 on 2023
//

#ifndef CHAINER_CCSCAN_CPP
#define CHAINER_CCSCAN_CPP

#include "ccscan.h"
#include "cscan.h"
#include <cstddef>
#include <unordered_map>
#include <vector>

template <class T>
size_t chainer::cscan<T>::get_pointers(T start, T end, bool rest, int count, int size)
{
    return search<T>::get_pointers(start, end, rest, count, size);
}

template <class T>
bool chainer::cscan<T>::is_static_pointer(T &addr, vm_static_data *p_static_data)
{
    for (auto &v : this->vm_static_list)
    {
        if (addr >= v->start && addr < v->end)
        {
            p_static_data = v;
            return 1;
        }
    }
    return 0;
}

template <class T>
size_t chainer::cscan<T>::scan_pointer_chain(std::vector<T> &addr, int depth, size_t offset, bool limit, size_t plim, FILE *outstream)
{
    if (addr.empty())
        return 0;
    this->saved_results.clear();
    size_t fidx, count;
    utils::timer ptimer;
    std::vector<chainer::pointer_range<T>> ranges;
    std::vector<utils::mapqueue<pointer_dir<T>>> dirs(depth + 1);
    // 所有的指针结果，数据结构：map{adrress(T), [offset1(int array), offset2(int array), ......]};
    std::vector<STRUCT_PLIST> v_results;
    fidx = count = 0;
    ptimer.start();
    // printf("Do not go gentle into that good night\n");
    for (auto level = 0; level <= depth; ++level)
    {
        std::vector<pointer_data<T> *> curr;
        // printf("\ncurrent level: %d\n", level);
        fflush(stdout);
        if (level > 0)
        {
            this->search_pointer(dirs[level - 1], curr, offset, limit, plim);
            // printf("%d: search %ld pointers\n", level, curr.size());
            if (curr.empty())
                break;
            this->filter_pointer_ranges(dirs, ranges, curr, level);
            this->create_assoc_dir_index(dirs[level - 1], dirs[level], offset, 10000);
            continue;
        }
        this->trans_addr_to_pointer_data(addr, curr);
        std::sort(curr.begin(), curr.end(), [](auto x, auto y)
                  { return x->address < y->address; });
        this->filter_pointer_ranges(dirs, ranges, curr, level);
        fidx = ranges.size();
        utils::free_container_data(curr); // why don't i put it outside the loop is because lazy and level < 0
    }
    for (; fidx < ranges.size(); ++fidx)
        this->create_assoc_dir_index(dirs[ranges[fidx].level - 1], ranges[fidx].results, offset, 10000); // not 'associate_data_index' or not ranges[fidx].results.size() because i wanna run it by multi thread
    utils::thread_pool->wait();
    if (ranges.empty())
        return count;
    // // printf("\nsearch and associate finish, spend: %fs, start filter pointers\n", ptimer.get() / 1000000.0);
    auto [counts, contents] = this->build_pointer_dirs_tree(dirs, ranges);
    if (counts.size() == 0 || contents.size() == 0)
        return count;
    // 2026年1月16日 coolforv 理解：ranges是静态的结果也就是一级，contents是二级还有以后的结果（都是动态地址）
    for (auto &r : ranges)
    {
        auto temp = 0ul;
        auto &ccount = counts[r.level];
        // std::cout << std::dec << "level:" << r.level << ",level_ccount[" << ccount.size() << "],results:[" << r.results.size() << "]" << std::endl;
        for (auto &v : r.results)
        {
            temp += ccount[v.end] - ccount[v.start];
            // std::cout << std::hex << v.address << "-" << v.value << "," << std::dec << v.start << "~" << v.end << ":" << std::endl;
            // 递归获取偏移列表
            std::vector<std::vector<int>> offsets;
            // 从当前节点开始构建完整的偏移路径
            for (int ii1 = 0; ii1 < v.end - v.start; ii1++)
            {
                // 获取第一层偏移
                std::vector<int> path;
                DWORD64 current_addr = contents[r.level - 1][ii1 + v.start]->address;
                DWORD64 current_value = contents[r.level - 1][ii1 + v.start]->value;
                DWORD64 parent_value = v.value; // 上一级的值

                // 计算第一层偏移
                DWORD64 first_offset = current_addr - parent_value;
                path.push_back(v.address - r.vma->start); // 第0层，静态模块地址层偏移
                path.push_back(first_offset);

                // 递归获取后续层级的偏移
                this->collect_offsets_recursive(contents, r.level - 1, ii1 + v.start, path, offsets, 1);
                // 保存结果
                for (int n = 0; n < offsets.size(); n++)
                {
                    v_results.push_back(STRUCT_PLIST{
                        .p_static_data = std::shared_ptr<vm_static_data>(r.vma, [](vm_static_data *) {}), // 使用自定义删除器避免重复释放
                        .v_off = std::move(offsets[n])});
                }
                offsets.clear();
            }
        }
        count += temp;
    }
    std::cout << "total rows:" << v_results.size() << std::endl;
    std::cout << "total count:" << count << std::endl;
    // 保存结果到成员变量
    this->saved_results.swap(v_results);
    this->integr_data_to_file(contents, ranges, outstream);
    //  printf("\nfinish write into file, total spend: %fs\n", ptimer.get() / 1000000.0);
    return this->saved_results.size();
}

// 添加一个辅助函数来递归收集偏移
template <class T>
void chainer::cscan<T>::collect_offsets_recursive(
    std::vector<utils::mapqueue<chainer::pointer_dir<T> *>> &contents,
    int current_level,
    int current_index,
    std::vector<int> &current_path,
    std::vector<std::vector<int>> &all_paths,
    int depth)
{
    // 如果到达最底层，则保存当前路径
    if (current_level <= 0)
    {
        all_paths.push_back(current_path);
        return;
    }

    // 获取当前节点的子节点
    auto &current_node = contents[current_level][current_index];
    DWORD64 parent_value = current_node->value;

    // 遍历当前节点指向的所有子节点
    for (uint32_t i = current_node->start; i < current_node->end; i++)
    {
        if (i >= contents[current_level - 1].size())
            break;

        auto child_node = contents[current_level - 1][i];
        DWORD64 child_addr = child_node->address;
        DWORD64 child_value = child_node->value;

        // 计算偏移
        DWORD64 offset = child_addr - parent_value;

        // 添加到路径
        current_path.push_back(offset);

        // 递归处理下一层
        collect_offsets_recursive(contents, current_level - 1, i, current_path, all_paths, depth + 1);

        // 回溯
        current_path.pop_back();
    }

    // 如果没有子节点，说明到达叶子节点，也保存路径
    if (current_level > 0 && current_node->start >= contents[current_level - 1].size())
    {
        all_paths.push_back(current_path);
    }
}

// 获取指针结果，数据结构：map{adrress(T), [offset1(int array), offset2(int array), ......]};
template <class T>
size_t chainer::cscan<T>::get_scanned_rows(std::vector<STRUCT_PLIST> &v_results, int index_start, int max_rows)
{
    if (this->saved_results.empty())
    {
        return 0; // 如果没有保存的结果，返回0
    }
    v_results.clear(); // 清空传入的结果容器
    if (index_start >= this->saved_results.size())
    {
        return 0;
    }
    size_t copied_count = std::min(max_rows, static_cast<int>(this->saved_results.size()) - index_start);
    v_results.insert(v_results.end(), this->saved_results.begin() + index_start, this->saved_results.begin() + index_start + copied_count);
    return copied_count; // 返回实际复制的行数
}

template <class T>
chainer::cscan<T>::cscan()
{
}

template <class T>
chainer::cscan<T>::~cscan()
{
}

template class chainer::cscan<uint32_t>;
template class chainer::cscan<size_t>;

#endif