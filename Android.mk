# Copyright (C) 2023 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# 定义当前文件路径
LOCAL_PATH := $(call my-dir)

# 清理所有 LOCAL_xxx 变量
include $(CLEAR_VARS)

# 编译模块的名称
LOCAL_MODULE := main

# 添加需要包含的头文件目录
# 这使得 #include "header.h" 能够找到相应的文件
LOCAL_C_INCLUDES := \
    $(LOCAL_PATH) \
    $(LOCAL_PATH)/chainer \
	$(LOCAL_PATH)/utils/threadtool \
    $(LOCAL_PATH)/utils

# 添加所有需要编译的 C/C++ 源文件
LOCAL_SRC_FILES := \
    main.cpp \
    chainer/ccformat.cpp \
	chainer/ccscan.cpp \
	utils/threadtool/threadpool.cpp \
	utils/sutils.cpp \

# 指定 C++ 标准为 C++17
# 现代 C++ 特性（如模板、auto 等）需要此设置
LOCAL_CPP_STANDARD := c++11

# 链接时需要的库
# -lpthread 用于支持多线程 (pthreads)
# LOCAL_LDLIBS := -lpthread

# 设置 C++ 编译器标志
# -O2 for optimization, -Wall to show all warnings
LOCAL_CPPFLAGS += -O2 -Wall
# 设置不显示编译警告warning信息
LOCAL_CFLAGS += -w

# 将模块编译为可执行文件
include $(BUILD_EXECUTABLE)