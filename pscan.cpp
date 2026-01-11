//
// PScan wrapper class implementation
// Create by 青杉白衣 on 2023
//

#ifndef PSCAN_CPP
#define PSCAN_CPP

#include "pscan.h"
#include <cstdio>

template <class T>
pscan::PScan<T>::PScan()
{
}

template <class T>
pscan::PScan<T>::~PScan()
{
}

template <class T>
size_t pscan::PScan<T>::getPointers(T start, T end, bool rest, int count, int size)
{
    return scanner.get_pointers(start, end, rest, count, size);
}

template <class T>
size_t pscan::PScan<T>::scanPointerChain(std::vector<T> &addr, int depth, size_t offset, 
                                         bool limit, size_t plim, const char *output_file)
{
    FILE *f = fopen(output_file, "wb+");
    if (f == nullptr) {
        printf("Error: Cannot open output file %s\n", output_file);
        return 0;
    }

    size_t result = scanner.scan_pointer_chain(addr, depth, offset, limit, plim, f);
    fclose(f);

    return result;
}

template <class T>
size_t pscan::PScan<T>::formatOutputFile(const char *input_file, const char *output_file)
{
    FILE *f = fopen(input_file, "rb+");
    if (f == nullptr) {
        printf("Error: Cannot open input file %s\n", input_file);
        return 0;
    }

    size_t result = formatter.format_bin_chain_data(f, output_file, false);
    fclose(f);

    return result;
}

template <class T>
size_t pscan::PScan<T>::formatOutputFolder(const char *input_file, const char *folder_path)
{
    FILE *f = fopen(input_file, "rb+");
    if (f == nullptr) {
        printf("Error: Cannot open input file %s\n", input_file);
        return 0;
    }

    size_t result = formatter.format_bin_chain_data(f, folder_path, true);
    fclose(f);

    return result;
}

// 显式模板实例化
template class pscan::PScan<uint32_t>;
template class pscan::PScan<size_t>;

#endif
