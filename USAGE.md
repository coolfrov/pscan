# PScan 使用说明 / PScan Usage Guide

## 概述 / Overview

PScan 是一个指针扫描工具的封装类，提供了简洁的接口来执行指针扫描和文件格式化输出。

PScan is a wrapper class for pointer scanning tools that provides a clean interface for pointer scanning and file format output.

## 类定义 / Class Definition

```cpp
namespace pscan {
    template <class T>
    class PScan {
    public:
        // 构造函数 / Constructor
        PScan();
        
        // 析构函数 / Destructor
        ~PScan();
        
        // 获取指针 / Get pointers
        size_t getPointers(T start, T end, bool rest, int count, int size);
        
        // 扫描指针链并输出到文件 / Scan pointer chain and output to file
        size_t scanPointerChain(std::vector<T> &addr, int depth, size_t offset, 
                               bool limit, size_t plim, const char *output_file);
        
        // 读取二进制文件并格式化输出结果 / Read binary file and format output
        size_t formatOutputFile(const char *input_file, const char *output_file);
        
        // 读取二进制文件并格式化输出到文件夹 / Read binary file and format to folder
        size_t formatOutputFolder(const char *input_file, const char *folder_path);
    };
}
```

## 使用示例 / Usage Examples

### 基础使用 / Basic Usage

```cpp
#include "pscan.h"
#include "memextend.h"
#include <vector>

int main() {
    // 1. 创建 PScan 对象 (64位使用 size_t, 32位使用 uint32_t)
    // Create PScan object (use size_t for 64-bit, uint32_t for 32-bit)
    pscan::PScan<size_t> scanner;
    
    // 2. 设置目标进程
    // Set target process
    memtool::base::target_pid = memtool::base::get_pid("com.example.app");
    if (memtool::base::target_pid == -1) {
        printf("Failed to find target process\n");
        return -1;
    }
    
    // 3. 获取目标内存信息
    // Get target memory information
    memtool::extend::get_target_mem();
    memtool::extend::set_mem_ranges(memtool::Anonymous + memtool::C_alloc + 
                                    memtool::C_bss + memtool::C_data);
    
    // 4. 获取指针
    // Get pointers
    size_t pointer_count = scanner.getPointers(0, 0, false, 10, 1 << 20);
    printf("Found %ld pointers\n", pointer_count);
    
    // 5. 扫描指针链
    // Scan pointer chain
    std::vector<size_t> target_addresses;
    target_addresses.push_back(0x12345678);  // 目标地址
    
    size_t chain_count = scanner.scanPointerChain(
        target_addresses,           // 目标地址列表
        6,                          // 深度 (层数)
        2500,                       // 偏移范围
        false,                      // 是否限制
        0,                          // 指针限制
        "/data/local/tmp/output"    // 输出文件路径
    );
    printf("Found %ld pointer chains\n", chain_count);
    
    return 0;
}
```

### 格式化输出 / Format Output

```cpp
#include "pscan.h"

int main() {
    pscan::PScan<size_t> formatter;
    
    // 方法 1: 输出到单个文件
    // Method 1: Output to a single file
    size_t result = formatter.formatOutputFile(
        "/data/local/tmp/raw_data",      // 输入的二进制文件
        "/data/local/tmp/formatted.txt"  // 输出的格式化文件
    );
    printf("Formatted %ld entries to file\n", result);
    
    // 方法 2: 输出到文件夹 (多个文件)
    // Method 2: Output to folder (multiple files)
    result = formatter.formatOutputFolder(
        "/data/local/tmp/raw_data",      // 输入的二进制文件
        "/data/local/tmp/output_folder"  // 输出文件夹路径
    );
    printf("Formatted %ld entries to folder\n", result);
    
    return 0;
}
```

## 方法说明 / Method Description

### getPointers()
获取内存范围内的指针。

Get pointers within a memory range.

**参数 / Parameters:**
- `start`: 起始地址 / Start address
- `end`: 结束地址 / End address
- `rest`: 是否重置 / Whether to reset
- `count`: 计数 / Count
- `size`: 大小 / Size

**返回值 / Returns:** 找到的指针数量 / Number of pointers found

### scanPointerChain()
扫描指针链并将结果输出到文件。

Scan pointer chain and output results to file.

**参数 / Parameters:**
- `addr`: 目标地址列表 / Target address list
- `depth`: 扫描深度(层数) / Scan depth (levels)
- `offset`: 偏移范围 / Offset range
- `limit`: 是否限制指针数量 / Whether to limit pointer count
- `plim`: 指针限制数 / Pointer limit count
- `output_file`: 输出文件路径 / Output file path

**返回值 / Returns:** 找到的指针链数量 / Number of pointer chains found

### formatOutputFile()
读取二进制文件并格式化输出到单个文件。

Read binary file and format output to a single file.

**参数 / Parameters:**
- `input_file`: 输入的二进制文件路径 / Input binary file path
- `output_file`: 输出的格式化文件路径 / Output formatted file path

**返回值 / Returns:** 格式化的条目数量 / Number of formatted entries

### formatOutputFolder()
读取二进制文件并格式化输出到文件夹。

Read binary file and format output to a folder.

**参数 / Parameters:**
- `input_file`: 输入的二进制文件路径 / Input binary file path
- `folder_path`: 输出文件夹路径 / Output folder path

**返回值 / Returns:** 格式化的条目数量 / Number of formatted entries

## 编译 / Building

使用 Android NDK 编译:

Build with Android NDK:

```bash
ndk-build
```

或者使用 CMake (如果配置了):

Or use CMake (if configured):

```bash
mkdir build
cd build
cmake ..
make
```

## 注意事项 / Notes

1. 模板参数 `T` 应根据目标架构选择:
   - 64位系统使用 `size_t`
   - 32位系统使用 `uint32_t`

   Template parameter `T` should be chosen based on target architecture:
   - Use `size_t` for 64-bit systems
   - Use `uint32_t` for 32-bit systems

2. 确保有足够的权限访问目标进程的内存。

   Ensure you have sufficient permissions to access target process memory.

3. 输出文件路径必须是可写的。

   Output file paths must be writable.

4. 在 Android 上运行时，可能需要 root 权限。

   Root permissions may be required when running on Android.
