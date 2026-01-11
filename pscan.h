//
// PScan wrapper class - encapsulates pointer scanning and file output
// Create by 青杉白衣 on 2023
//

#pragma once

#include "ccscan.h"
#include "ccformat.h"
#include <string>
#include <vector>

namespace pscan
{

template <class T>
class PScan
{
private:
    chainer::cscan<T> scanner;
    chainer::cformat<T> formatter;

public:
    PScan();
    ~PScan();

    // 获取指针
    // Get pointers within a memory range
    size_t getPointers(T start, T end, bool rest, int count, int size);

    // 扫描指针链并输出到文件
    // Scan pointer chain and output to file
    size_t scanPointerChain(std::vector<T> &addr, int depth, size_t offset, 
                           bool limit, size_t plim, const char *output_file);

    // 读取二进制文件并格式化输出结果
    // Read binary file and format output results
    size_t formatOutputFile(const char *input_file, const char *output_file);

    // 读取二进制文件并格式化输出到文件夹
    // Read binary file and format output to folder
    size_t formatOutputFolder(const char *input_file, const char *folder_path);
};

// 显式模板实例化声明
extern template class PScan<uint32_t>;
extern template class PScan<size_t>;

} // namespace pscan
