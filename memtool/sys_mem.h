#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include <unistd.h>
#include <sys/mman.h>

#define NEKO_H
#include <sys/fcntl.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <mutex>
#define FileCount 4
#include <regex.h>
#include <sys/sysmacros.h> // 对于 major 和 minor 宏
#include <sys/stat.h>
static std::mutex mtx1, mtx2;

class c_driver
{
private:
    // 调试
    bool is_dbg = 0;
    // 添加保存设备信息的结构
    struct DeviceInfo {
        unsigned int major;
        unsigned int minor;
        char path[256];
        char boot_id[64];   // 添加boot_id字段
    };
    
    DeviceInfo saved_info;
    bool info_saved = false;

    int has_upper = 0;
    int has_lower = 0;
    int has_symbol = 0;
    int has_digit = 0;
    int fd = -1;
    pid_t pid;

    typedef struct _COPY_MEMORY
    {
        pid_t pid;
        uintptr_t addr;
        void *buffer;
        size_t size;
    } COPY_MEMORY, *PCOPY_MEMORY;

    typedef struct _MODULE_BASE
    {
        pid_t pid;
        char *name;
        uintptr_t base;
    } MODULE_BASE, *PMODULE_BASE;

    enum OPERATIONS
    {
        OP_INIT_KEY = 0x800,
        OP_READ_MEM = 0x801,
        OP_WRITE_MEM = 0x802,
        OP_MODULE_BASE = 0x803,
    };

    // 从这
    char *execCom(const char *shell)
    {
        FILE *fp = popen(shell, "r");

        if (fp == NULL)
        {
            perror("popen failed");
            return NULL;
        }

        char buffer[256];
        char *result = (char *)malloc(1000); // allocate memory for the result string
        result[0] = '\0';                    // initialize as an empty string

        // Read and append output of the first command to result
        while (fgets(buffer, sizeof(buffer), fp) != NULL)
        {
            strcat(result, buffer);
        }
        pclose(fp);
        return result;
    }

    bool File_authority(mode_t mode)
    {
        if (mode & S_IRUSR && mode & S_IWUSR && mode & S_IRGRP && mode & S_IWGRP && mode & S_IROTH && mode & S_IWOTH)
            return true;
        return false;
    }

    int findFirstMatchingPath(const char *path, regex_t *regex, char *result)
    {
        DIR *dir;
        struct dirent *entry;

        if ((dir = opendir(path)) != NULL)
        {
            while ((entry = readdir(dir)) != NULL)
            {
                char fullpath[1024]; // 适当调整数组大小
                snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
                if (entry->d_type == DT_LNK)
                {
                    // 对链接文件进行处理
                    char linkpath[1024]; // 适当调整数组大小
                    ssize_t len = readlink(fullpath, linkpath, sizeof(linkpath) - 1);
                    if (len != -1)
                    {
                        linkpath[len] = '\0';
                        // if(is_dbg) printf("%s\n", linkpath);
                        // 对链接的实际路径进行正则匹配
                        if (regexec(regex, linkpath, 0, NULL, 0) == 0)
                        {
                            strcpy(result, fullpath);
                            closedir(dir);
                            return 1;
                        }
                    }
                    else
                    {
                        perror("readlink");
                    }
                }
            }
            closedir(dir);
        }
        else
        {
            perror("Unable to open directory");
        }

        return 0;
    }

    // 修复createDriverNode和removeDeviceNode函数
    void createDriverNode(char *path, int major_number, int minor_number)
    {
        std::string command = "mknod " + std::string(path) + " c " + std::to_string(major_number) + " " + std::to_string(minor_number);
        system(command.c_str());
        //   if(is_dbg) printf("\n[-] 驱动节点创建成功");
    }

    // 删除驱动节点
    // 新的函数，用于删除设备节点
    void removeDeviceNode(char *path)
    {
        // if(is_dbg) printf("%s\n",path);
        if (unlink(path) == 0)
        {
            //   if(is_dbg) printf("[-] 驱动节点删除成功\n");
            // cerr << "已删除设备节点：" << devicePath << endl;
        }
        else
        {
            //  if(is_dbg) printf("[-] 驱动节点删除失败\n");
            // perror("删除设备节点时发生错误");
        }
    }

    int getMEN(char *path)
    {
        FILE *file = fopen(path, "r");
        int zero, neko;
        if (file == NULL)
        {
            return 0;
        }
        char line[256];
        while (fgets(line, sizeof(line), file))
        {
            if (sscanf(line, "%d:%d", &neko, &zero) == 2 && zero == 0)
            {
                fclose(file);
                return neko;
            }
        }
        fclose(file);
        return 0;
    }

    int has_digit1(char *str)
    {
        int i, len;
        len = strlen(str);
        for (i = 0; i < len; i++)
        {
            if (isdigit((unsigned char)str[i]))
            {
                return 1;
            }
        }
        return 0;
    }

    int ioctl_str(const char *path)
    {
        int bsf = open(path, O_RDWR);
        if (bsf == -1)
        {
            return -1;
        }
        return bsf;
    }

public:
    int drivers_byte;
    bool is_open(){
        return fd!=-1;
    }
    char *driver_path()
    {
        const char *dev_path = "/dev";
        DIR *dir = opendir(dev_path);
        if (dir == NULL)
        {
            if(is_dbg) printf("无法打开/dev目录\n");
            return NULL;
        }

        const char *files[] = {"wanbai", "CheckMe", "Ckanri", "lanran", "video188"};
        struct dirent *entry;
        char *file_path = NULL;
        while ((entry = readdir(dir)) != NULL)
        {
            // 跳过当前目录和上级目录
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            {
                continue;
            }

            size_t path_length = strlen(dev_path) + strlen(entry->d_name) + 2;
            file_path = (char *)malloc(path_length);
            snprintf(file_path, path_length, "%s/%s", dev_path, entry->d_name);
            for (int i = 0; i < 5; i++)
            {
                if (strcmp(entry->d_name, files[i]) == 0)
                {
                    if(is_dbg) printf("驱动文件：%s\n", file_path);
                    closedir(dir);
                    return file_path;
                }
            }

            // 获取文件stat结构
            struct stat file_info;
            if (stat(file_path, &file_info) < 0)
            {
                free(file_path);
                file_path = NULL;
                continue;
            }

            // 跳过gpio接口
            if (strstr(entry->d_name, "gpiochip") != NULL)
            {
                free(file_path);
                file_path = NULL;
                continue;
            }
            // 跳过lpm、tty、ptmx
            if (strstr(entry->d_name, "lpm") != NULL)
            {
                free(file_path);
                file_path = NULL;
                continue;
            }
            if (strstr(entry->d_name, "tty") != NULL)
            {
                free(file_path);
                file_path = NULL;
                continue;
            }
            if (strstr(entry->d_name, "ptmx") != NULL)
            {
                free(file_path);
                file_path = NULL;
                continue;
            }
            if (strchr(entry->d_name, '0') != NULL || strchr(entry->d_name, '1') != NULL || strchr(entry->d_name, '2') != NULL || strchr(entry->d_name, '3') != NULL || strchr(entry->d_name, '4') != NULL || strchr(entry->d_name, '5') != NULL || strchr(entry->d_name, '6') != NULL || strchr(entry->d_name, '7') != NULL || strchr(entry->d_name, '8') != NULL || strchr(entry->d_name, '9') != NULL)
            {
                free(file_path);
                file_path = NULL;
                continue;
            }

            // 检查是否为驱动文件
            if ((S_ISCHR(file_info.st_mode) || S_ISBLK(file_info.st_mode)) && strchr(entry->d_name, '_') == NULL && strchr(entry->d_name, '-') == NULL && strchr(entry->d_name, ':') == NULL)
            {
                // 过滤标准输入输出
                if (strcmp(entry->d_name, "stdin") == 0 || strcmp(entry->d_name, "stdout") == 0 || strcmp(entry->d_name, "stderr") == 0)
                {
                    free(file_path);
                    file_path = NULL;
                    continue;
                }

                size_t file_name_length = strlen(entry->d_name);
                time_t current_time;
                time(&current_time);
                int current_year = localtime(&current_time)->tm_year + 1900;
                int file_year = localtime(&file_info.st_ctime)->tm_year + 1900;
                // 跳过1980年前的文件
                if (file_year <= 1980)
                {
                    free(file_path);
                    file_path = NULL;
                    continue;
                }

                time_t atime = file_info.st_atime;
                time_t ctime = file_info.st_ctime;
                // 检查最近访问时间和修改时间是否一致并且文件名是否是symbol文件
                if (atime == ctime)
                {
                    // 检查mode权限类型是否为S_IFREG(普通文件)和大小还有gid和uid是否为0(root)并且文件名称长度在7位或7位以下
                    if ((file_info.st_mode & S_IFMT) == 8192 && file_info.st_size == 0 && file_info.st_gid == 0 && file_info.st_uid == 0 && file_name_length <= 7)
                    {
                        if(is_dbg) printf("驱动文件：%s\n", file_path);
                        closedir(dir);
                        return file_path;
                    }
                }
            }
            free(file_path);
            file_path = NULL;
        }
        closedir(dir);
        return NULL;
    }

    int Neko_QxV8()
    {
        DIR *dir;
        struct dirent *Neko1;
        struct dirent *Neko2;
        char path[1024];
        char path2[1024];
        int count = 1;
        dir = opendir("/sys/devices/virtual/");
        if (dir == NULL)
        {
            return 1;
        }
        while ((Neko1 = readdir(dir)) != NULL)
        {
            snprintf(path, sizeof(path), "/sys/devices/virtual/%s/", Neko1->d_name);
            DIR *subdir = opendir(path);
            if (subdir != NULL)
            {
                while ((Neko2 = readdir(subdir)) != NULL)
                {
                    if (has_digit1(Neko2->d_name))
                    {
                        continue;
                    }
                    if (Neko2->d_type == DT_DIR)
                    {
                        int len = strlen(Neko2->d_name);
                        if (len == 6 && !(strchr(Neko2->d_name, '.') != NULL || strchr(Neko2->d_name, '_') != NULL || strchr(Neko2->d_name, '-') != NULL || strchr(Neko2->d_name, ':') != NULL))
                        {
                            char path3[1024];
                            snprintf(path3, sizeof(path3), "/sys/class/%s/%s/dev", Neko1->d_name,
                                     Neko2->d_name);
                            int MEN = getMEN(path3);
                            if (MEN != 0)
                            {
                                if (!(strcmp(Neko1->d_name, Neko2->d_name) == 0))
                                {

                                    char command[1024];
                                    snprintf(command, sizeof(command), "mknod /dev/%s c %d 0",
                                             Neko2->d_name, MEN);
                                    int result = system(command);
                                    if (result == -1)
                                    {
                                        perror("mknod");
                                        return -1;
                                    }

                                    char dev[1024];
                                    snprintf(dev, sizeof(dev), "/dev/%s", Neko2->d_name);
                                    int fd = open(dev, O_RDWR);
                                    if(is_dbg) printf("隐藏驱动%s\n", dev);
                                    if (fd == -1 && strlen(dev)<1)
                                    {
                                        perror("打开");
                                        return -1;
                                    }
                                    int rm = unlink(dev);
                                    if (rm == 0)
                                    {
                                        return fd;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            closedir(subdir);
        }

        closedir(dir);
        return -1;
    }

    char *dev_Sch()
    {
        const char *dev_path = "/dev";
        DIR *dir = opendir(dev_path);
        if (dir == NULL)
        {
            if(is_dbg) printf("无法打开/dev目录\n");
            return NULL;
        }

        struct dirent *entry;
        char file_path[256];
        while ((entry = readdir(dir)) != NULL)
        {

            if (strstr(entry->d_name, "std") != NULL || strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strstr(entry->d_name, "gpiochip") != NULL)
            {
                continue;
            }

            if (strchr(entry->d_name, '_') != NULL && strchr(entry->d_name, '-') != NULL && strchr(entry->d_name, ':') != NULL)
            {
                continue;
            }

            sprintf(file_path, "%s/%s", dev_path, entry->d_name);

            struct stat file_info;
            if (stat(file_path, &file_info) < 0)
                continue;

            if ((localtime(&file_info.st_ctime)->tm_year + 1900) <= 1980)
                continue;

            if (strlen(entry->d_name) > 7 || strlen(entry->d_name) < 5)
                continue;

            if (file_info.st_gid != 0 || file_info.st_uid != 0)
                continue;

            if (S_ISCHR(file_info.st_mode) || S_ISBLK(file_info.st_mode))
            {
                if (file_info.st_gid == 0 && file_info.st_uid == 0)
                {
                    if(is_dbg) printf("%s\n", file_path);
                    char *devpath = (char *)malloc(32);
                    strcpy(devpath, file_path);
                    closedir(dir);
                    return devpath;
                }
            }
        }
        closedir(dir);
        return NULL;
    }

    char *gtqwq()
    {
        struct dirent *de;
        DIR *dr = opendir("/proc");
        char *device_path = NULL;

        if (dr == NULL)
        {
            if(is_dbg) printf("Could not open /proc directory");
            return NULL;
        }

        while ((de = readdir(dr)) != NULL)
        {
            if (strlen(de->d_name) != 6 || strcmp(de->d_name, "NVISPI") == 0 || strcmp(de->d_name, "aputag") == 0 || strcmp(de->d_name, "asound") == 0 || strcmp(de->d_name, "clkdbg") == 0 || strcmp(de->d_name, "crypto") == 0 || strcmp(de->d_name, "driver") == 0 || strcmp(de->d_name, "mounts") == 0 || strcmp(de->d_name, "pidmap") == 0)
            {
                continue;
            }
            int is_valid = 1;
            for (int i = 0; i < 6; i++)
            {
                if (!isalnum(de->d_name[i]))
                {
                    is_valid = 0;
                    break;
                }
            }
            if (is_valid)
            {
                device_path = (char *)malloc(11 + strlen(de->d_name));
                sprintf(device_path, "/proc/%s", de->d_name);
                struct stat sb;
                if (stat(device_path, &sb) == 0 && S_ISREG(sb.st_mode))
                {
                    break;
                }
                else
                {
                    free(device_path);
                    device_path = NULL;
                }
            }
        }
        puts(device_path);
        closedir(dr);
        return device_path;
    }

    char *proc_hide_Sch()
    {
        const char *command = "dir=$(ls -l /proc/*/exe 2>/dev/null | grep -E '/data/[^/]* \\(deleted\\)' | sed 's/ /\\n/g' | grep '/proc' | sed 's/\\/[^/]*$//g');if [[ \"$dir\" ]]; then sbwj=$(head -n 1 \"$dir/comm\");open_file=\"\";for file in \"$dir\"/fd/*; do link=$(readlink \"$file\");if [[ \"$link\" == \"/dev/$sbwj (deleted)\" ]]; then open_file=\"$file\";break;fi;done;if [[ -n \"$open_file\" ]]; then nhjd=$(echo \"$open_file\");sbid=$(ls -L -l \"$nhjd\" | sed 's/\\([^,]*\\).*/\\1/' | sed 's/.*root //');echo \"/dev/$sbwj\";rm -rf \"/dev/$sbwj\";mknod \"/dev/$sbwj\" c \"$sbid\" 0;fi;fi;";
        FILE *file = popen(command, "r");
        if (file == NULL)
        {
            return NULL;
        }
        static char result[512];
        if (fgets(result, sizeof(result), file) == NULL)
        {
            return NULL;
        }
        pclose(file);
        result[strlen(result) - 1] = '\0';
        return result;
    }

    // must内核对接
    char *qx8()
    {
        // 打开目录
        char name[128], path[256];
        static char file_path[256];
        DIR *dir = opendir("/sys/devices/virtual/");
        if (dir == NULL)
            return NULL;
        struct dirent *Neko1;
        while ((Neko1 = readdir(dir)) != NULL)
        {
            // 跳过当前目录和上级目录
            if (strcmp(Neko1->d_name, ".") == 0 || strcmp(Neko1->d_name, "..") == 0)
                continue;

            if (strcmp(Neko1->d_name, "usbmon") == 0)
                continue;

            int ret = 0;
            sprintf(path, "/sys/devices/virtual/%s/", Neko1->d_name);
            DIR *subdir = opendir(path);
            if (subdir == NULL)
                continue;
            struct dirent *Neko2;
            while ((Neko2 = readdir(subdir)) != NULL)
            {
                // 跳过当前目录和上级目录
                if (strcmp(Neko2->d_name, ".") == 0 || strcmp(Neko2->d_name, "..") == 0)
                    continue;
                ret++;
                if (ret == 1)
                    sprintf(name, "%s", Neko2->d_name);
            }
            closedir(subdir);
            if (ret > 1)
                continue;

            sprintf(file_path, "/sys/devices/virtual/%s/%s/dev", Neko1->d_name, name);
            if (access(file_path, F_OK) != 0)
                continue;

            int neko, zero;
            FILE *file = fopen(file_path, "r");
            if (file == NULL)
                continue;
            char line[256];
            while (fgets(line, sizeof(line), file))
            {
                if (sscanf(line, "%d:%d", &neko, &zero) == 2)
                    break;
            }
            fclose(file);
            if (zero != 0)
                continue;

            sprintf(file_path, "/dev/%s", name);
            if (access(file_path, F_OK) != 0)
            {
                mode_t mode = S_IFCHR | 0600;
                int ret = mknod(file_path, mode, (neko << 8) | 0);
                if (ret == 0)
                {
                    return file_path;
                }
            }
        }
        return NULL;
    }

    char *qx10()
    {
        const char *command = "dir=$(ls -l /proc/*/exe 2>/dev/null | grep -E '/data/[^/]* \\(deleted\\)' | sed 's/ /\\n/g' | grep '/proc' | sed 's/\\/[^/]*$//g');if [[ \"$dir\" ]]; then sbwj=$(head -n 1 \"$dir/comm\");open_file=\"\";for file in \"$dir\"/fd/*; do link=$(readlink \"$file\");if [[ \"$link\" == \"/dev/$sbwj (deleted)\" ]]; then open_file=\"$file\";break;fi;done;if [[ -n \"$open_file\" ]]; then nhjd=$(echo \"$open_file\");sbid=$(ls -L -l \"$nhjd\" | sed 's/\\([^,]*\\).*/\\1/' | sed 's/.*root //');echo \"/dev/$sbwj\";rm -rf \"/dev/$sbwj\";mknod \"/dev/$sbwj\" c \"$sbid\" 0;fi;fi;";
        FILE *file = popen(command, "r");
        if (file == NULL)
        {
            return NULL;
        }
        static char result[512];
        if (fgets(result, sizeof(result), file) == NULL)
        {
            return NULL;
        }
        pclose(file);
        result[strlen(result) - 1] = '\0';
        return result;
    }
    // must内核对接

    char *fsyfsbl()
    {
        struct dirent *de;
        DIR *dr = opendir("/proc");
        char *device_path = NULL;

        if (dr == NULL)
        {
            if(is_dbg) printf("Could not open /proc directory");
            return NULL;
        }

        while ((de = readdir(dr)) != NULL)
        {
            if (strlen(de->d_name) != 6 || strcmp(de->d_name, "aputag") == 0 || strcmp(de->d_name, "asound") == 0 || strcmp(de->d_name, "clkdbg") == 0 || strcmp(de->d_name, "crypto") == 0 || strcmp(de->d_name, "driver") == 0 || strcmp(de->d_name, "mounts") == 0 || strcmp(de->d_name, "pidmap") == 0)
            {
                continue;
            }
            int is_valid = 1;
            for (int i = 0; i < 6; i++)
            {
                if (!isalnum(de->d_name[i]))
                {
                    is_valid = 0;
                    break;
                }
            }
            if (is_valid)
            {
                device_path = (char *)malloc(11 + strlen(de->d_name));
                sprintf(device_path, "/proc/%s", de->d_name);
                struct stat sb;
                if (stat(device_path, &sb) == 0 && S_ISREG(sb.st_mode))
                {
                    break;
                }
                else
                {
                    free(device_path);
                    device_path = NULL;
                }
            }
        }
        puts(device_path);
        closedir(dr);
        return device_path;
    }

    const char *get_dev()
    {
        const char *command = "for dir in /proc/*/; do cmdline_file=\"cmdline\"; comm_file=\"comm\"; proclj=\"$dir$cmdline_file\"; proclj2=\"$dir$comm_file\"; if [[ -f \"$proclj\" && -f \"$proclj2\" ]]; then cmdline=$(head -n 1 \"$proclj\"); comm=$(head -n 1 \"$proclj2\"); if echo \"$cmdline\" | grep -qE '^/data/[a-z]{6}$'; then sbwj=$(echo \"$comm\"); open_file=\"\"; for file in \"$dir\"/fd/*; do link=$(readlink \"$file\"); if [[ \"$link\" == \"/dev/$sbwj (deleted)\" ]]; then open_file=\"$file\"; break; fi; done; if [[ -n \"$open_file\" ]]; then nhjd=$(echo \"$open_file\"); sbid=$(ls -L -l \"$nhjd\" | sed 's/\\([^,]*\\).*/\\1/' | sed 's/.*root //'); echo \"/dev/$sbwj\"; rm -Rf \"/dev/$sbwj\"; mknod \"/dev/$sbwj\" c \"$sbid\" 0; break; fi; fi; fi; done";
        FILE *file = popen(command, "r");
        if (file == NULL)
        {
            return NULL;
        }

        char result[512];
        if (fgets(result, sizeof(result), file) == NULL)
        {
            pclose(file);
            return NULL;
        }
        pclose(file);

        int len = strlen(result);
        if (len > 0 && result[len - 1] == '\n')
        {
            result[len - 1] = '\0';
        }
        return strdup(result);
    }

    c_driver(int num_tmp = 0)
    {
        // init(0);
    }

    bool init(int num_tmp = 0){
        int 选择值 = num_tmp;
        if (num_tmp == 0)
        {
            // 设置文本颜色为紫色
            printf("\n [FanShui]1------QXv9-11.4驱动\n");
            system("sleep 0.1");
            printf("\n [FanShui]2------QXv9-11.4备用驱动\n");
            system("sleep 0.1");
            printf("\n [FanShui]3------自研独家驱动 \n");
            system("sleep 0.1");
            printf("\n [FanShui]4------must驱动\n");
            system("sleep 0.1");
            printf("\n [FanShui]5------GT驱动2.0\n");
            system("sleep 0.1");
            printf("\n [FanShui]6------安全使用Dev目录驱动[qx,gt]\n");
            printf("\n[从上往下] 请输入序号(请输入1～6)：");
            fflush(stdout);
            scanf("%d", &选择值);
        }
        if (选择值 == 7)
        {
            char *search = driver_path();
            fd = open(search, O_RDWR);
            if (fd == -1)
            {
                if(is_dbg) printf("%s", "\n[-]QXv5 不支持紫砂吧\n");
                exit(0);
            }
            if (fd != -1)
            {
                if(is_dbg) printf("%s", "\n[+]QXv5 链接成功\n");
            }
        }

        if (选择值 == 3)
        {
            // 恢复设备信息
            if (restore_device_node()) {
                if(is_dbg) printf("设备节点恢复成功！\n");
                // 现在可以打开设备
                int fd = open(saved_info.path, O_RDWR);
                if (fd > 0) {
                    if(is_dbg) printf("成功打开恢复的设备\n");
                    close(fd);
                }
            } else {
                if(is_dbg) printf("设备节点恢复失败\n");
            }
            char *dev_path1 = driver_path();
            if (dev_path1 != NULL)
            {
                fd = open(dev_path1, O_RDWR);
                if (fd > 0)
                {
                    // 获取并保存设备信息
                    struct stat st;
                    if (fstat(fd, &st) == 0) {
                        saved_info.major = major(st.st_rdev);
                        saved_info.minor = minor(st.st_rdev);
                        strncpy(saved_info.path, dev_path1, sizeof(saved_info.path) - 1);
                        info_saved = true;
                        
                        // 将信息保存到共享位置（文件）
                        save_device_info();
                        
                        if(is_dbg) printf("Saved device info: %s (major=%u, minor=%u)\n", 
                            saved_info.path, saved_info.major, saved_info.minor);
                    }
                    printf("dbg[%s]\n", dev_path1);
                    unlink(dev_path1);
                    if(is_dbg) printf("设备节点已删除\n");
                }else{
                    printf("驱动打开失败!\n");
                    exit(0);
                }
            }else{
                printf("驱动未安装哦!\n");
                exit(0);
            }
            // return 0;
        }

        if (选择值 == 6)
        {
            char *Devstr = this->dev_Sch();
            if (Devstr == NULL)
            {
                if(is_dbg) printf("未寻找到dev方案驱动\n");
                char *Proc_H = this->proc_hide_Sch();
                if (Proc_H == NULL)
                {
                    if(is_dbg) printf("未寻找到被删除的dev方案驱动\n");
                }
                else
                {
                    fd = this->ioctl_str(Proc_H);
                    if (fd > 0)
                    {
                        if(is_dbg) printf("被删除的dev方案驱动 %s\n", Proc_H);
                        unlink(Proc_H);
                        this->drivers_byte = 3;
                    }
                }
            }
            else
            {
                fd = this->ioctl_str(Devstr);
                if (fd > 0)
                {
                    if(is_dbg) printf("dev方案驱动 %s\n", Devstr);
                    free(Devstr);
                    this->drivers_byte = 2;
                }
            }
        }
        if (选择值 == 8)
        { // v8

            fd = Neko_QxV8();
            if (fd == -1)
            {
                if(is_dbg) printf("%s", "\n[-]QXv8 不支持\n");
                exit(0);
            }
            else
            {
                if(is_dbg) printf("%s", "\n[+]QXv8 链接成功\n");
            }
        }
        if (选择值 == 1)
        { // v8

            char *output = execCom("ls -l /proc/*/exe 2>/dev/null | grep -E \"/data/[a-z]{6} \\(deleted\\)\"");
            char filePath[256];
            char pid[56];
            if (output != NULL)
            {
                char *procStart = strstr(output, "/proc/");

                // Extracting process ID
                char *pidStart = procStart + 6; // Move to the position after "/proc/"
                char *pidEnd = strchr(pidStart, '/');

                strncpy(pid, pidStart, pidEnd - pidStart);
                pid[pidEnd - pidStart] = '\0';

                char *arrowStart = strstr(output, "->");
                // Extracting file path
                char *start = arrowStart + 3;        // Move to the position after "->"
                char *end = strchr(output, '(') - 1; // Find the position before '('
                strncpy(filePath, start, end - start + 1);
                filePath[end - start] = '\0';

                // Replace "data" with "dev" in filePath
                char *replacePtr = strstr(filePath, "data");
                if (replacePtr != NULL)
                {
                    memmove(replacePtr + 2, replacePtr + 3, strlen(replacePtr + 3) + 1);
                    memmove(replacePtr, "dev", strlen("dev"));
                }
                // Print the results
                // if(is_dbg) printf("Driver Path: %s\n", filePath);
            }
            else
            {
                if(is_dbg) printf("Error executing scripts.\n");
            }
            char fdPath[256]; // fd路径

            char pattern[100];
            snprintf(pattern, sizeof(pattern), ".*%s.*", filePath + 5); // 从字符串 "/dev/abcdef" 中提取 "abcdef"
            int major_number = 0;
            int minor_number = 0;
            snprintf(fdPath, sizeof(fdPath), "/proc/%s/fd", pid);
            // if(is_dbg) printf("fdpath:%s\n",fdPath);
            regex_t regex;
            if (regcomp(&regex, pattern, 0) != 0)
            {
                fprintf(stderr, "Failed to compile regex\n");
            }
            char result[1024]; // 适当调整数组大小
            if (findFirstMatchingPath(fdPath, &regex, result))
            {
                char cmd[256];
                // Construct the command to get fdInfo using the extracted pid
                sprintf(cmd, "ls -AL -l  %s | grep -Eo '[0-9]{3},' | grep  -Eo '[0-9]{3}'", result);
                // Execute the command and get fdInfo
                char *fdInfo = execCom(cmd);
                fdInfo[strlen(fdInfo) - 1] = '\0';
                major_number = atoi(fdInfo);
                // 释放动态分配的内存
                free(fdInfo);
            }
            else
            {
                if(is_dbg) printf("草拟吗你刷驱动了吗.\n");
            }
            regfree(&regex);
            if (filePath[0] != '\0')
            {
                // std::cout << "创建 /dev/" << driverInfo.deviceID << std::endl;

                // if(is_dbg) printf("\n[-] 驱动信息载入成功");
                createDriverNode(filePath, major_number, 0);
                sleep(1);
                fd = open(filePath, O_RDWR); // Use c_str() to get a C-style string
                // if(is_dbg) printf("%d",fd);
                if (fd == -1)
                {

                    //  if(is_dbg) printf("\n[-] 驱动链接启动\n");
                    removeDeviceNode(filePath);
                }
                else
                {
                    //  if(is_dbg) printf("\n[-] 驱动已经启动\n");
                    removeDeviceNode(filePath);
                }
            }
        }
        // // 自己的驱动
        // if (选择值 == 9999)
        // {
        //     char dev_path[64] = "/dev/NBYBBY";
        //     // strcpy(dev_path,get_dev());
        //     fd = open(dev_path, O_RDWR);
        //     if (fd > 0)
        //     {
        //         if(is_dbg) printf("驱动文件：%s\n", dev_path);
        //         // unlink(dev_path);
        //         return;
        //     }
        //     else
        //     {
        //         if(is_dbg) printf("无法找到驱动文件！\n");
        //         exit(0);
        //         // return -1;
        //     }
        // }

        if (选择值 == 2)
        { // 备用例子
            char dev_path[64];
            strcpy(dev_path, get_dev());
            fd = open(dev_path, O_RDWR);
            if (fd > 0)
            {
                if(is_dbg) printf("驱动文件：%s\n", dev_path);
                unlink(dev_path);
                // return 0;
            }
            else
            {
                if(is_dbg) printf("无法找到驱动文件！\n");
                exit(0);
                // return -1;
            }
        }

        if (选择值 == 6)
        { // 备用例子
        }

        if (选择值 == 5)
        { // gt
            char *device_name = driver_path();
            fd = open(device_name, O_RDWR);

            if (fd == -1)
            {
                if(is_dbg) printf("[-] open driver failed\n");
                free(device_name);
                exit(0);
            }
            free(device_name);
        }
        if (选择值 == 4)
        {

            char *dev_path3 = qx10();
            if (dev_path3 != NULL)
            {
                fd = open(dev_path3, O_RDWR);
                if (fd > 0)
                {
                    if(is_dbg) printf("隐藏驱动：%s\n", dev_path3);
                    unlink(dev_path3);
                    //	return 1;
                }
            }
            char *dev_path1 = driver_path();
            if (dev_path1 != NULL)
            {
                fd = open(dev_path1, O_RDWR);
                if (fd > 0)
                {
                    if(is_dbg) printf("must驱动文件：%s\n", dev_path1);
                    //	return 1;
                }
                if(is_dbg) printf("[-] 打开驱动程序失败，请重新刷入must内核驱动\n");
            }
            char *dev_path2 = qx8();
            if (dev_path2 != NULL)
            {
                fd = open(dev_path2, O_RDWR);
                if (fd > 0)
                {
                    if(is_dbg) printf("隐藏驱动：%s\n", dev_path2);
                    unlink(dev_path2);
                    //		return 1;
                }
            }
            //		return 0;
        }
        if(is_dbg) printf("\033[0m"); // 重置文本颜色到默认值
        if (选择值 == 5)
        {
            char *device_name = driver_path();
            fd = open(device_name, O_RDWR);

            if (fd == -1)
            {
                if(is_dbg) printf("[-] open driver failed\n");
                free(device_name);
                exit(0);
            }
            free(device_name);
        }
        // if (选择值 ==3){
        // char *output = execCom("ls -l /proc/*/exe 2>/dev/null | grep -E \"/data/[a-z]{6} \\(deleted\\)\"");
        // char filePath[256];
        // char pid[56];
        // if (output != NULL) {
        // if(is_dbg) printf("\n\n调试输出:\n%s\n", output);
        // char *procStart = strstr(output, "/proc/");

        // // Extracting process ID
        // char *pidStart = procStart + 6; // Move to the position after "/proc/"
        // char *pidEnd = strchr(pidStart, '/');

        // strncpy(pid, pidStart, pidEnd - pidStart);
        // pid[pidEnd - pidStart] = '\0';

        // char *arrowStart = strstr(output, "->");
        // // Extracting file path
        // char *start = arrowStart + 3; // Move to the position after "->"
        // char *end = strchr(output, '(') - 1; // Find the position before '('
        // strncpy(filePath, start, end - start + 1);
        // filePath[end - start] = '\0';

        // // Replace "data" with "dev" in filePath

        // char *replacePtr = strstr(filePath, "data");

        // if (replacePtr != NULL ) {
        // memmove(replacePtr + 2, replacePtr + 3, strlen(replacePtr + 3) + 1);
        // memmove(replacePtr, "dev", strlen("dev"));
        // }

        // } else {
        // if(is_dbg) printf("执行脚本时出错\n");
        // }

        // char cmd[256];
        // // Construct the command to get fdInfo using the extracted pid
        // sprintf(cmd, "ls -al -L /proc/%s/fd/3", pid);
        // // Execute the command and get fdInfo
        // char *fdInfo = execCom(cmd);
        // int major_number, minor_number;
        // sscanf(fdInfo, "%*s %*d %*s %*s %d, %d", &major_number, &minor_number);

        // if (filePath!="\0") {
        // createDriverNode(filePath, major_number, minor_number);
        // }
        // sleep(1);
        // char *search2 = filePath;
        // fd = open(search2, O_RDWR); // Use c_str() to get a C-style string
        // if (fd == -1) {
        // if(is_dbg) printf("\033[31m[X] 驱动连接失败 \033[0m\n");
        // if(is_dbg) printf("%s", "\n[-]QXv10 不支持  换v8\n");
        // //  removeDeviceNode(filePath);
        // exit(0);
        // } else {
        // if(is_dbg) printf("%s", "\n[+] QXv10-11.4 链接成功\n");
        // if(is_dbg) printf("\033[32m[✓] 驱动连接成功 \033[0m\n");
        // if(is_dbg) printf("\n[-] 驱动文件：%s\n",filePath);
        // removeDeviceNode(filePath);
        // }
        // }*/
        return is_open();
    }

    // 到这
    ~c_driver()
    {
        // wont be called
        if (fd > 0)
            close(fd);
    }

    uintptr_t get_module_base(char *name)
    {
        MODULE_BASE mb;
        char buf[0x100];
        strcpy(buf, name);
        mb.pid = this->pid;
        mb.name = buf;

        if (ioctl(fd, OP_MODULE_BASE, &mb) != 0)
        {
            return 0;
        }
        return mb.base;
    }

    void initialize(pid_t pid)
    {
        this->pid = pid;
    }

    bool init_key(char *key)
    {
        char buf[0x100];
        strcpy(buf, key);
        if (ioctl(fd, OP_INIT_KEY, buf) != 0)
        {
            return false;
        }
        return true;
    }

    // 定义一个函数来处理内存区域
    void processMemory(void *buffer, size_t size)
    {
        uint64_t *ptr = (uint64_t *)buffer;
        size_t numInts = size / sizeof(uint64_t); // 计算buffer中可以容纳的64位整数的数量

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

    bool read(uintptr_t addr, void *buffer, size_t size)
    {
        mtx1.lock();
        COPY_MEMORY cm;
        cm.pid = this->pid;
        cm.addr = addr;
        cm.buffer = buffer;
        cm.size = size;
        if (ioctl(fd, OP_READ_MEM, &cm) != 0)
        {
            mtx1.unlock();
            return false;
        }
        if (size == 8)
            processMemory(buffer, size);
        mtx1.unlock();
        return true;
    }

    bool write(uintptr_t addr, void *buffer, size_t size)
    {
        mtx2.lock();
        COPY_MEMORY cm;
        cm.pid = this->pid;
        cm.addr = addr;
        cm.buffer = buffer;
        cm.size = size;
        if (ioctl(fd, OP_WRITE_MEM, &cm) != 0)
        {
            mtx2.unlock();
            return false;
        }
        mtx2.unlock();
        return true;
    }

    template <typename T>
    T read(uintptr_t addr)
    {
        T res;
        if (this->read(addr, &res, sizeof(T)))
            return res;
        return {};
    }

    template <typename T>
    bool write(uintptr_t addr, T value)
    {
        return this->write(addr, &value, sizeof(T));
    }

    int 是否可读(uintptr_t addr)
    {
        if (addr < 0x1000000000 || addr > 0xefffffffff || addr % 0x8 != 0)
            return 0;
        return 1;
    }

    long 读取指针(long 地址)
    {
        long res;
        if (this->read(地址, &res, sizeof(uintptr_t)))
        {
            return res;
        }
        return {};
    }

    int 读取整数(long 地址)
    {
        int data;

        if (this->read(地址, &data, sizeof(data)))
        {
            return data;
        }
        return {};
    }

    char 读取字符类(long 地址)
    {
        char var;

        if (this->read(地址, &var, sizeof(var)))
        {
            return var;
        }
        return {};
    }
    uint8_t 读取短字符(long 地址)
    {
        uint8_t var;

        if (this->read(地址, &var, sizeof(var)))
        {
            return var;
        }
        return {};
    }

    float 读取浮点数(long 地址)
    {
        float var;

        if (this->read(地址, &var, sizeof(var)))
        {
            return var;
        }
        return {};
    }

    unsigned long long 读取指针(unsigned long long 地址)
    {
        unsigned long long val = 0;
        if (!this->read(地址, &val, sizeof(val)))
        {
            val = 0;
        }
        return val;
    }

    pid_t 获取进程ID(const char *packageName)
    {
        int id = -1;
        DIR *dir;
        FILE *fp;
        char filename[64];
        char cmdline[64];
        struct dirent *entry;
        dir = opendir("/proc");
        while ((entry = readdir(dir)) != NULL)
        {
            id = atoi(entry->d_name);
            if (id != 0)
            {
                sprintf(filename, "/proc/%d/cmdline", id);
                fp = fopen(filename, "r");
                if (fp)
                {
                    fgets(cmdline, sizeof(cmdline), fp);
                    fclose(fp);
                    if (strcmp(packageName, cmdline) == 0)
                    {
                        return id;
                    }
                }
            }
        }
        closedir(dir);
        return -1;
    }

    uintptr_t 获取基址头(char *name)
    {
        MODULE_BASE mb;
        char buf[0x100];
        strcpy(buf, name);
        mb.pid = this->pid;
        mb.name = buf;

        if (ioctl(fd, OP_MODULE_BASE, &mb) != 0)
        {
            return 0;
        }
        return mb.base;
    }

    // 获取当前 boot_id
    const char* get_current_boot_id() {
        static char boot_id[64] = {0};
        FILE *fp = fopen("/proc/sys/kernel/random/boot_id", "r");
        if (fp) {
            if (fgets(boot_id, sizeof(boot_id), fp)) {
                // 移除换行符
                char *pos = strchr(boot_id, '\n');
                if (pos) *pos = '\0';
            }
            fclose(fp);
        }
        return boot_id;
    }

    // 保存设备信息到文件（供其他进程使用）
    void save_device_info() {
        if (!info_saved) return;
        
        // 获取当前 boot_id 并保存
        const char *current_boot_id = get_current_boot_id();
        strncpy(saved_info.boot_id, current_boot_id, sizeof(saved_info.boot_id)-1);
        saved_info.boot_id[sizeof(saved_info.boot_id)-1] = '\0';
        
        FILE *fp = fopen("/data/local/tmp/device_info.dat", "wb");
        if (fp) {
            fwrite(&saved_info, sizeof(DeviceInfo), 1, fp);
            fclose(fp);
            if(is_dbg) printf("设备信息已保存到 /data/local/tmp/device_info.dat\n");
        }
    }
    
    // 从文件加载设备信息
    bool load_device_info() {
        FILE *fp = fopen("/data/local/tmp/device_info.dat", "rb");
        if (fp) {
            fread(&saved_info, sizeof(DeviceInfo), 1, fp);
            fclose(fp);
            info_saved = true;
            return true;
        }
        return false;
    }
    
    // 恢复设备节点（可在任何进程中调用）
    bool restore_device_node() {
        if (!info_saved && !load_device_info()) {
            if(is_dbg) printf("没有可用的设备信息\n");
            return false;
        }
        
        // 检查 boot_id 是否匹配
        const char *current_boot_id = get_current_boot_id();
        if (strcmp(current_boot_id, saved_info.boot_id) != 0) {
            if(is_dbg) printf("boot_id 不一致，设备已重启，删除设备信息文件\n");
            unlink("/data/local/tmp/device_info.dat");
            return false;
        }
        
        // 使用 mknod 重新创建设备节点
        if (mknod(saved_info.path, S_IFCHR | 0666, 
                 makedev(saved_info.major, saved_info.minor))) {
            perror("恢复设备节点失败");
            return false;
        }
        
        if(is_dbg) printf("设备节点 %s 已成功恢复\n", saved_info.path);
        return true;
    }
};
// static c_driver *sys_mem = new c_driver(1);
