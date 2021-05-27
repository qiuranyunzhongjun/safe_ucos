/*
*********************************************************************************************************
*                                                uC/OS-II
*                                          The Real-Time Kernel
*                                            MEMORY MANAGEMENT
*
*                              (c) Copyright 1992-2009, Micrium, Weston, FL
*                                           All Rights Reserved
*
* File    : OS_SAFE_MEM.C
* By      : 宋立军
* Version : V1.0
*
* LICENSING TERMS:
* ---------------
*  用于构建安全数据区的函数
*********************************************************************************************************
*/

#ifndef  OS_MASTER_FILE
#include <ucos_ii.h>
#endif

#if (OS_SAFE_MEM_EN > 0u)
/*
*********************************************************************************************************
*                                        CREATE A MEMORY PARTITION
*
* Description : Create a fixed-sized memory partition that will be managed by uC/OS-II.
*
* Arguments   : addr     is the starting address of the memory partition
*
*               nblks    is the number of memory blocks to create from the partition.
*
*               blksize  is the size (in bytes) of each block in the memory partition.
*
*               perr     is a pointer to a variable containing an error message which will be set by
*                        this function to either:
*
*                        OS_ERR_NONE              if the memory partition has been created correctly.
*                        OS_ERR_MEM_INVALID_ADDR  if you are specifying an invalid address for the memory
*                                                 storage of the partition or, the block does not align
*                                                 on a pointer boundary
*                        OS_ERR_MEM_INVALID_PART  no free partitions available
*                        OS_ERR_MEM_INVALID_BLKS  user specified an invalid number of blocks (must be >= 2)
*                        OS_ERR_MEM_INVALID_SIZE  user specified an invalid block size
*                                                   - must be greater than the size of a pointer
*                                                   - must be able to hold an integral number of pointers
* Returns    : != (OS_MEM *)0  is the partition was created
*              == (OS_MEM *)0  if the partition was not created because of invalid arguments or, no
*                              free partition is available.
*********************************************************************************************************
*/

OS_SAFE_MEM  *OSSafeVarMemInit(INT8U  *perr)
{
	OS_SAFE_MEM    *pmem;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */

#endif
	OS_ENTER_CRITICAL();
	pmem = malloc(OS_SAFE_MEM_TOTAL_SIZE);                             /* 动态分配一块内存作为安全数据区，先暂时用malloc代替，之后可以直接申请好在参数中传递进来 */
	OS_EXIT_CRITICAL();
	if (pmem == (OS_SAFE_MEM *)0) {                        /* 内存没有分配成功             */
		*perr = OS_ERR_SAFE_NO_MEM;
		return ((OS_SAFE_MEM *)0);
	}
	*perr = OS_ERR_NONE;
	return (pmem);
}
#endif                                                    /* OS_SAFE_MEM_EN                                 */

