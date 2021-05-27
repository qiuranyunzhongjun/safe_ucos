# safe_ucos

本文针对嵌入式操作系统μC/OS-Ⅱ的运行时验证问题开展研究，具有较大的研究价值和应用价值，主要研究内容包括：

（1）针对μC/OS-Ⅱ中动态内存分配机制的灵活性和安全性不足的问题，提出了一种基于伙伴系统的改进算法，在移植的μC/OS-Ⅱ系统上进行了实验，并通过SPIN进行建模验证，具有分配回收效率高、内存利用率和安全性高的优势。

（2）针对C语言程序中变量的内存安全问题，提出了安全变量的理念。在SARD测试集上进行了实验，有效解决了缓冲区溢出等内存安全问题。

（3）针对多变量耦合的系统中关键变量的运行时监控问题，提出了一种变量规则的解析和计算方法。结合上述有关内存和安全变量的改进，共同设计实现了μC/OS-Ⅱ上的安全数据区，大大提高了嵌入式系统上的软件可靠性，为未来嵌入式系统的广泛应用打下基础。

代码分布：

为安全数据区增加的宏定义ucosii.h

为安全数据区增加的全局变量os_cfg_r.h

安全数据区内存管理相关代码os_safe_mem.c

安全数据区变量管理相关代码os_safe_var.c

安全数据区规则管理相关代码os_safe_rule.c

在SARD测试集上测试安全数据区的普通代码写法test_case.c

在SARD测试集上测试安全数据区调用安全数据区接口的代码写法test_mycase.c

测试安全数据区的规则管理和多任务运行的代码test.c

对安全数据区的内存管理算法进行形式化建模的promela代码newbuddy.pml
