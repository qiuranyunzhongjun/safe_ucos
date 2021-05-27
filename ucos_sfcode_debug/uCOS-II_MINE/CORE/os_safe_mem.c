
/*
*********************************************************************************************************
*                                                uC/OS-II
*                                          The Real-Time Kernel
*                                            MEMORY MANAGEMENT
*
*                              (c) Copyright 2020-2025, Micrium, Weston, FL
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
#include <assert.h>

#if (OS_SAFE_MEM_EN > 0u)

#if OS_SAFE_MEM_MERGE_EN == 1u
/*设定翻倍内存区的每种大小的内存块的初始数量，在回收内存块时会合并大于此值的一半的内存块*/
INT32U  const  OSSafeBlockNum[(OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1] = {3,3,3,3};
#endif

/*根据安全数据区首地址获取该数据区的有效空间大小*/
INT32S getBlkSize(void *pblk) {
	if (((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk == (void*)0) {
#if OS_SAFE_MEM_MERGE_EN == 0u
		return  (INT8U*)OSSafeMem->OSSafeMemAddr + 5*OS_SAFE_MEM_TOTAL_SIZE - (INT8U*)pblk - sizeof(OS_SAFE_MEM_BLOCK);
#else
		return  (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE - (INT8U*)pblk - sizeof(OS_SAFE_MEM_BLOCK);
#endif
	}
	else {
		return  (INT8U*)((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk - (INT8U*)pblk - sizeof(OS_SAFE_MEM_BLOCK);
	}
}

/*根据安全数据区首地址获取该数据区的有效空间大小，然后返回其在安全数据中所属的链表下标*/
INT32S getBlkIndex(void *pblk) {
	INT32S size, blkNo, blkSize;
	size = getBlkSize(pblk);
	if (size <= OS_SAFE_MEM_BLOCK_MAX) {
		return (size - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl;
	}
	else {
		blkSize = OS_SAFE_MEM_BLOCK_MAX * 2;
		blkNo = (OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1;
		while (blkSize < size) {
			blkSize *= 2;
			blkNo += 1;
		}
		if (blkNo > OS_SAFE_MEM_BLOCK_COUNT - 1) {
			blkNo = OS_SAFE_MEM_BLOCK_COUNT - 1;
		}
		return blkNo;
	}
}

/*输出该内存块的调试信息*/
void memlog(INT8U  *pblk) {

	if (pblk != NULL) {
		if (((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk == NULL) {
			//printf("安全数据区起始地址为0X%d，大小为%d,结束地址为0X%X", OSSafeMem->OSSafeMemAddr, OS_SAFE_MEM_TOTAL_SIZE, (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE);

#if OS_SAFE_MEM_MERGE_EN == 0u
			sprintf(log_info, "地址0X%X -- 0X%X 已存储的数值为0X%X（物理相邻的上一块），%d(内存块可用大小)，0X%X（物理相邻的下一块），0X%X（链表相邻的下一块），0X%X（链表相邻的上一块）；", pblk, (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE, ((OS_SAFE_MEM_BLOCK *)pblk)->OSLastPhyMemBlk, (INT8U*)OSSafeMem->OSSafeMemAddr + 5*OS_SAFE_MEM_TOTAL_SIZE - pblk - sizeof(OS_SAFE_MEM_BLOCK), ((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk, *(void **)(pblk + sizeof(OS_SAFE_MEM_BLOCK)), *(void **)(pblk + sizeof(OS_SAFE_MEM_BLOCK) + sizeof(INT8U*)));
#else
			sprintf(log_info, "安全内存0X%X -- 0X%X，用户可用内存%4d 字节，实链两端0X%7X <---> 0X%7X，虚链数据0X%7X  <---> 0X%7X", pblk, (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE, (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE - pblk - sizeof(OS_SAFE_MEM_BLOCK), ((OS_SAFE_MEM_BLOCK *)pblk)->OSLastPhyMemBlk, ((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk, *(void **)(pblk + sizeof(OS_SAFE_MEM_BLOCK)), *(void **)(pblk + sizeof(OS_SAFE_MEM_BLOCK) + sizeof(INT8U*)));
#endif
			recordLog("内存",log_info);
		}
		else {
			sprintf(log_info, "安全内存0X%X -- 0X%X，用户可用内存%4d 字节，实链两端0X%7X <---> 0X%7X，虚链数据0X%7X  <---> 0X%7X", pblk, ((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk, (INT8U*)((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk - pblk - sizeof(OS_SAFE_MEM_BLOCK), ((OS_SAFE_MEM_BLOCK *)pblk)->OSLastPhyMemBlk, ((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk, *(void **)(pblk + sizeof(OS_SAFE_MEM_BLOCK)), *(void **)(pblk + sizeof(OS_SAFE_MEM_BLOCK) + sizeof(INT8U*)));
			recordLog("内存",log_info);
		}
	}
	else
		recordLog("内存", "空指针");
}

/*
*********************************************************************************************************
*                                        CREATE A MEMORY PARTITION
*
* Description : Create a fixed-sized safe data memory partition that will be managed by uC/OS-II.
*
* Arguments   : perr     is a pointer to a variable containing an error message which will be set by
*                        this function to either:
* Returns    : != (OS_SAFE_MEM *)0  is the partition was created
*              == (OS_SAFE_MEM *)0  if the partition was not created because of invalid arguments or, no
*                              free partition is available.
*********************************************************************************************************
*/

void  OSSafeVarMemInit(INT8U  *perr)
{
	void             *pmem;
	OS_SAFE_MEM      *pSafeMem;
	INT32U             part;/*用来遍历不同大小的内存块*/
	INT32U             list;/*用来遍历相同大小的内存块*/
	INT32U             memSize = 0;/*用来记录初始化之后总的有效空间*/
	INT32U             leftMemSize;
	INT32U             blkSize;
	INT8U            *pblk;
	void            **plink;
	void             *lastPhyBlk;
	void             *lastListBlk;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */
	INT8U            n;
	if (OS_SAFE_MEM_BLOCK_MIN < sizeof(OS_SAFE_MEM_LIST_BLOCK)) {/*必须能存放两个指针*/
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_INVALID_BLK_MIN\n");
#endif
		*perr = OS_ERR_SAFE_INVALID_BLK_MIN;
		return;
	}
	if ((OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) % OS_SAFE_MEM_BLOCK_INERVAl != 0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_INVALID_INERVAl\n");
#endif
		*perr = OS_ERR_SAFE_INVALID_INERVAl;
		return;
	}
	n = (OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1;
	if (n + 1 > OS_SAFE_MEM_BLOCK_COUNT) {/*翻倍内存块的最后一个存放的内存块可能大于标识的数字*/
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_SMALL_BLOCK_COUNT\n");
#endif
		*perr = OS_ERR_SAFE_SMALL_BLOCK_COUNT;
		return;
	}
	/*总大小必须能足够分配设定的各个安全数据区数量*/
	leftMemSize = 0;
	for (part = 0; part < (OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1; part += 1) {
		leftMemSize += OSSafeBlockNum[part] * (sizeof(OS_SAFE_MEM_BLOCK) + OS_SAFE_MEM_BLOCK_MIN + OS_SAFE_MEM_BLOCK_INERVAl * part);
	}
	/*blkSize = OS_SAFE_MEM_BLOCK_MAX * 2;
	for (; part < OS_SAFE_MEM_BLOCK_COUNT; part++) {
		leftMemSize += OSSafeBlockNum[part] * (sizeof(OS_SAFE_MEM_BLOCK) + blkSize);
		blkSize *= 2;
	}*/
	if (leftMemSize > OS_SAFE_MEM_TOTAL_SIZE) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_SMALL_TOTAL_SIZE\n");
#endif
		*perr = OS_ERR_SAFE_SMALL_TOTAL_SIZE;
		return;
	}
#endif
	/*printf("%d %d", sizeof(INT8U*), sizeof(INT32S));*/
	OS_ENTER_CRITICAL();
	pSafeMem = malloc(sizeof(OS_SAFE_MEM));
#if OS_SAFE_MEM_MERGE_EN == 0u
	pmem = malloc(OS_SAFE_MEM_TOTAL_SIZE*5);                             /* 动态分配一块内存作为安全数据区，如果不支持合并，则需要多分配几倍大小备用，先暂时用malloc代替，之后可以直接申请好在参数中传递进来，ucos中一般都是直接用数组申请静态地址 */
#else
	pmem = malloc(OS_SAFE_MEM_TOTAL_SIZE);                               /* 动态分配一块内存作为安全数据区，先暂时用malloc代替，之后可以直接申请好在参数中传递进来，ucos中一般都是直接用数组申请静态地址 */
#endif
	OS_EXIT_CRITICAL();
	if (pSafeMem == (OS_SAFE_MEM*)0 || pmem == (void *)0) {                        /* 内存没有分配成功             */
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_NO_MEM\n");
#endif
		*perr = OS_ERR_SAFE_NO_MEM;
		return;
	}
	//plink = (void **)pmem;

	OSSafeMem = pSafeMem;
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	sprintf(log_info, "安全数据区内存首地址为:0X%X", pmem);
	recordLog("内存",log_info);
#endif
	pblk = (INT8U *)pmem;
	lastPhyBlk = NULL;
#if OS_SAFE_MEM_MERGE_EN == 0u
	for (part = 0; part < (OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1; part += 1) {
		blkSize = OS_SAFE_MEM_BLOCK_MIN + part * OS_SAFE_MEM_BLOCK_INERVAl;
		pSafeMem->SafeMemParts[part].OSafeMemPartBlkSize = blkSize;
		pSafeMem->SafeMemParts[part].OSSafeMemPartNFree = 0;
		pSafeMem->SafeMemParts[part].OSafeMemPartUsedCount = 0;                    /* 统计域                                     */
	}
	leftMemSize = OS_SAFE_MEM_TOTAL_SIZE * 5;
#else
	for (part = 0; part < (OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1; part += 1) {
		blkSize = OS_SAFE_MEM_BLOCK_MIN + part * OS_SAFE_MEM_BLOCK_INERVAl;
		//pSafeMem->SafeMemParts[part].OSSafeMemPartAddr = pblk;
		pSafeMem->SafeMemParts[part].OSafeMemPartBlkSize = blkSize;
		pSafeMem->SafeMemParts[part].OSSafeMemPartFreeList = pblk;
		pSafeMem->SafeMemParts[part].OSSafeMemPartNFree = OSSafeBlockNum[part];
		lastListBlk = NULL;
		for (list = 0u; list < OSSafeBlockNum[part]; list++) {
			((OS_SAFE_MEM_BLOCK *)pblk)->OSLastPhyMemBlk = lastPhyBlk;
			//((OS_SAFE_MEM_BLOCK *)pblk)->OSafeMemBlkSize = blkSize;
			((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk = pblk + sizeof(OS_SAFE_MEM_BLOCK) + blkSize;/*把用于记录前后物理上相连的内存块的数据结构写入*/
			lastPhyBlk = pblk;
			pblk += sizeof(OS_SAFE_MEM_BLOCK);
			plink = (void **)pblk;
			if (list == OSSafeBlockNum[part] - 1) {
				((OS_SAFE_MEM_LIST_BLOCK*)pblk)->OSNextListMemBlk = NULL;
			}
			else {
				((OS_SAFE_MEM_LIST_BLOCK*)pblk)->OSNextListMemBlk = (void *)(pblk + blkSize);/*把链表中下一块内存块的地址存在本块有效空间开始处*/
			}
			((OS_SAFE_MEM_LIST_BLOCK*)pblk)->OSLastListMemBlk = lastListBlk;/*把链表中上一块内存块的地址存在 下一块内存块的地址 之后*/
			lastListBlk = lastPhyBlk;
			pblk += blkSize;/*指针移动到未分配的空间处*/
			memSize += blkSize;/*更新有效空间大小*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			memlog(pblk - blkSize - sizeof(OS_SAFE_MEM_BLOCK));
#endif
		}
	}
	leftMemSize = (INT8U*)pmem - pblk + OS_SAFE_MEM_TOTAL_SIZE;
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	sprintf(log_info, "OSSafeVarMemInit函数中，分配完递增内存块之后剩余空间为: %d", leftMemSize);
	recordLog("内存",log_info);
#endif
#endif /*OS_SAFE_MEM_MERGE_EN == 0u*/
	leftMemSize -= sizeof(OS_SAFE_MEM_BLOCK);
	for (; part < OS_SAFE_MEM_BLOCK_COUNT; part++) {
		if ((part == OS_SAFE_MEM_BLOCK_COUNT - 1) || leftMemSize <= blkSize) {
			((OS_SAFE_MEM_BLOCK *)pblk)->OSLastPhyMemBlk = lastPhyBlk;
			//((OS_SAFE_MEM_BLOCK *)pblk)->OSafeMemBlkSize = leftMemSize;
			((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk = NULL;
			//pSafeMem->SafeMemParts[part].OSSafeMemPartAddr = pblk;
			pSafeMem->SafeMemParts[part].OSafeMemPartBlkSize = blkSize;
			pSafeMem->SafeMemParts[part].OSSafeMemPartFreeList = pblk;
			pSafeMem->SafeMemParts[part].OSSafeMemPartNFree = 1;
			pblk += sizeof(OS_SAFE_MEM_BLOCK);
			((OS_SAFE_MEM_LIST_BLOCK*)pblk)->OSNextListMemBlk = NULL;/*把链表中下一块内存块的地址存在本块有效空间开始处*/
			((OS_SAFE_MEM_LIST_BLOCK*)pblk)->OSLastListMemBlk = NULL;/*把链表中上一块内存块的地址存在本块有效空间开始处*/
#if OS_SAFE_MEM_MERGE_EN == 0u
			pSafeMem->SafeMemParts[part].OSafeMemPartUsedCount = 0;                    /* 统计域                                     */
#endif
			memSize += leftMemSize;/*更新有效空间大小*/
			pSafeMem->OSSafeMemPartMaxIndex = part;

			/*输出调试信息*/
			//printf("OSSafeVarMemInit中翻倍内存块的信息为： ");
			//log(pblk - sizeof(OS_SAFE_MEM_BLOCK));

			for (part=part+1 ; part < OS_SAFE_MEM_BLOCK_COUNT; part++) {
				//pSafeMem->SafeMemParts[part].OSSafeMemPartAddr = NULL;
				blkSize *= 2;
				pSafeMem->SafeMemParts[part].OSafeMemPartBlkSize = blkSize;
				pSafeMem->SafeMemParts[part].OSSafeMemPartFreeList = NULL;
				pSafeMem->SafeMemParts[part].OSSafeMemPartNFree = 0;
#if OS_SAFE_MEM_MERGE_EN == 0u
				pSafeMem->SafeMemParts[part].OSafeMemPartUsedCount = 0;                    /* 统计域                                     */
#endif
			}
			break;
		}
		else {
			blkSize *= 2;
			//pSafeMem->SafeMemParts[part].OSSafeMemPartAddr = NULL;
			pSafeMem->SafeMemParts[part].OSafeMemPartBlkSize = blkSize;
			pSafeMem->SafeMemParts[part].OSSafeMemPartFreeList = NULL;
			pSafeMem->SafeMemParts[part].OSSafeMemPartNFree = 0;
#if OS_SAFE_MEM_MERGE_EN == 0u
			pSafeMem->SafeMemParts[part].OSafeMemPartUsedCount = 0;                    /* 统计域                                     */
#endif
		}
	}
#if OS_SAFE_MEM_MERGE_EN == 0u
	pSafeMem->OSSafeMemTotalSize = 5*OS_SAFE_MEM_TOTAL_SIZE;
#else
	pSafeMem->OSSafeMemTotalSize = OS_SAFE_MEM_TOTAL_SIZE;
#endif
	pSafeMem->OSSafeMemFreeSize = memSize;
	pSafeMem->OSSafeMemAddr = pmem;
	*perr = OS_ERR_NONE;
}
/*
*********************************************************************************************************
*                                          GET A SAFE MEMORY BLOCK
*
* Description : Get a safe memory block from safe data memory
*
* Arguments   : size    is size of block
*
*               perr    is a pointer to a variable containing an error message which will be set by this
*                       function to either:
*
*                       OS_ERR_NONE             if the memory partition has been created correctly.
*
* Returns     : A pointer to a memory block if no error is detected
*               A pointer to NULL if an error is detected
*********************************************************************************************************
*/

void  *OSSafeVarMemGet(INT8U  size,
					   INT8U   *perr)
{

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif
	
	void      *pblk = 0u;
	INT8U     *pLeftBlk=NULL,*pLastBlk=NULL;
	INT8U     *pTempBlk = NULL;
	INT32U      blkSize;  /*应当在哪个下标下的内存块中取*/
	INT32U      leftSize;
	INT32U      useSize;
	INT32U      blockSize;/*用来替代之前的数据结构保存安全内存块大小*/

#if OS_ARG_CHK_EN > 0u
	if (OSSafeMem == (OS_SAFE_MEM *)0) {                        /* Must point to a valid safe memory partition        */
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_INVALID_PMEM\n");
#endif
		*perr = OS_ERR_SAFE_INVALID_PMEM;
		return ((void *)0);
	}
	if (size <= 0u) {                        /* Must point to a valid memory partition        */
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_INVALID_SIZE\n");
#endif
		*perr = OS_ERR_SAFE_INVALID_SIZE;
		return ((void *)0);
	}
#endif
	if (size > OSSafeMem->OSSafeMemFreeSize) {/*申请的空间大于安全数据区的总有效空间*/
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_TOO_LARGE_SIZE\n");
#endif
		*perr = OS_ERR_SAFE_TOO_LARGE_SIZE;
		return ((void *)0);
	}
	if (size <= OS_SAFE_MEM_BLOCK_MAX) {
		blkSize = (size - OS_SAFE_MEM_BLOCK_MIN) % OS_SAFE_MEM_BLOCK_INERVAl == 0 ? (size - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl : (size - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1;
		for (; blkSize < (OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1; blkSize += 1) {
			if (OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree > 0) {/*从递增内存块中找到了合适的分块，直接分配*/
				OS_ENTER_CRITICAL();
				pblk = OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList;
				blockSize = getBlkSize(pblk);
				OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree--;
				OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList = *(void **)((INT8U *)(OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList) + sizeof(OS_SAFE_MEM_BLOCK));
				OSSafeMem->OSSafeMemFreeSize -= blockSize;
				OSSafeMem->OSSafeMemTotalSize -= blockSize + sizeof(OS_SAFE_MEM_BLOCK);
				OS_EXIT_CRITICAL();
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				/*输出调试信息
				sprintf(log_info,"OSSafeVarMemGet中，第%d个内存标签大小为%d,剩余内存块个数为%d；后两个内存块的信息为：", blkSize, OSSafeMem->SafeMemParts[blkSize].OSafeMemPartBlkSize, OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree);
				recordLog("内存",log_info);
				pTempBlk = OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList;
				memlog(pTempBlk);
				if (pTempBlk == NULL) {
					recordLog("上一块指针已经是空指针啦！");
				}
				else {
					pTempBlk = ((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk;
					memlog(pTempBlk);
				}*/
				/*输出调试信息*/
				recordLog("内存","OSSafeVarMemGet中取出的内存块的信息为：");
				memlog(pblk);
				sprintf(log_info, "OSSafeVarMemGet结束后，安全内存区剩余的可供分配的有效空间为%dB。", OSSafeMem->OSSafeMemFreeSize);
				recordLog("内存",log_info);
#endif

				((OS_SAFE_MEM_LIST_BLOCK*)((INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk=NULL;
				//((OS_SAFE_MEM_USED_BLOCK*)((INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK)))->prio = OSPrioCur;
				//recordLog("OSSafeVarMemGet取出的内存块中写入优先级之后内存块的信息为： \n");
				//memlog(pblk);
#if OS_SAFE_MEM_MERGE_EN == 0
				OSSafeMem->SafeMemParts[blkSize].OSafeMemPartUsedCount++;                    /* 统计域                                     */
				sprintf(log_info, "OSSafeVarMemGet中，申请内存标签大小为%d,统计域变为%d", OSSafeMem->SafeMemParts[blkSize].OSafeMemPartBlkSize, OSSafeMem->SafeMemParts[blkSize].OSafeMemPartUsedCount);
				recordLog("内存",log_info);
#endif
				*perr = OS_ERR_NONE;                          /*      No error                                 */
				return (pblk);                                /*      Return memory block to caller            */
			}
		}
	}
	else {
		useSize = OS_SAFE_MEM_BLOCK_MAX * 2;
		blkSize = (OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl +1;
		while (useSize < size) {
			useSize *= 2;
			blkSize += 1;
		}
	}
	for (; blkSize < OS_SAFE_MEM_BLOCK_COUNT; blkSize++) {
		OS_ENTER_CRITICAL();
		pblk = OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList;
		for (useSize = 0; useSize < OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree; useSize++) {
			blockSize = getBlkSize(pblk);
			if (blockSize >= size) {
				OSSafeMem->OSSafeMemFreeSize -= blockSize;
				OSSafeMem->OSSafeMemTotalSize -= blockSize + sizeof(OS_SAFE_MEM_BLOCK);
				pTempBlk = (INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK);/*取出的内存块中存储链表内存块链接数据结构的地址*/
				if (useSize == 0u) {
					OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList = ((OS_SAFE_MEM_LIST_BLOCK*)pTempBlk)->OSNextListMemBlk;
					if (((OS_SAFE_MEM_LIST_BLOCK*)pTempBlk)->OSNextListMemBlk != (void*)0) {
						pLeftBlk = (INT8U*)((OS_SAFE_MEM_LIST_BLOCK*)pTempBlk)->OSNextListMemBlk + sizeof(OS_SAFE_MEM_BLOCK);/*链表相邻的下一个指针*/
						((OS_SAFE_MEM_LIST_BLOCK*)pLeftBlk)->OSLastListMemBlk = NULL;
					}
				}
				else {
					pLeftBlk = (INT8U*)((OS_SAFE_MEM_LIST_BLOCK*)pTempBlk)->OSLastListMemBlk + sizeof(OS_SAFE_MEM_BLOCK);/*链表相邻的上一个指针*/
					((OS_SAFE_MEM_LIST_BLOCK*)pLeftBlk)->OSNextListMemBlk = ((OS_SAFE_MEM_LIST_BLOCK*)pTempBlk)->OSNextListMemBlk;
					if (((OS_SAFE_MEM_LIST_BLOCK*)pTempBlk)->OSNextListMemBlk != NULL) {
						pLeftBlk = (INT8U*)((OS_SAFE_MEM_LIST_BLOCK*)pTempBlk)->OSNextListMemBlk + sizeof(OS_SAFE_MEM_BLOCK);/*链表相邻的下一个指针*/
						((OS_SAFE_MEM_LIST_BLOCK*)pLeftBlk)->OSLastListMemBlk = ((OS_SAFE_MEM_LIST_BLOCK*)pTempBlk)->OSLastListMemBlk;
					}
				}
				OS_EXIT_CRITICAL();
				leftSize = blockSize - size;

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				/*输出调试信息*/
				sprintf(log_info, "OSSafeVarMemGet中，第%d个内存标签大小为%d,剩余内存块个数为%d；相邻两个内存块的信息为：", blkSize, OSSafeMem->SafeMemParts[blkSize].OSafeMemPartBlkSize, OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree);
				recordLog("内存",log_info);
				if (useSize == 0u) {
					pTempBlk = OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList;
					memlog(pTempBlk);
					if (pTempBlk == NULL) {
						recordLog("内存","空指针");
					}
					else {
						pTempBlk = *(void **)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK));
						memlog(pTempBlk);
					}
				}
				else {
					memlog(pLeftBlk);
					memlog(pTempBlk);
				}
#endif
				break;
			}
			else {
				pblk = (INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK);
				pblk = *(void **)pblk;
			}
		}
		if (useSize < OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree) {
			OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree--;
			break;
		}
		OS_EXIT_CRITICAL();
	}
	if (blkSize >= OS_SAFE_MEM_BLOCK_COUNT) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_NO_SUIT_BLKS\n");
#endif
		*perr = OS_ERR_SAFE_NO_SUIT_BLKS;                  /* No,  Notify caller of empty memory partition  */
		return ((void *)0);                               /*      Return NULL pointer to caller            */
	}
	else {

		/*下面是拆分内存块程序*/
		if (leftSize > OS_SAFE_MEM_BLOCK_MAX + sizeof(OS_SAFE_MEM_BLOCK)) {/*分配完之后的剩余空间还可以再插入翻倍内存块中*/
			leftSize -= sizeof(OS_SAFE_MEM_BLOCK);
			useSize = OS_SAFE_MEM_BLOCK_MAX * 2;
			blkSize = (OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1;
			while (useSize < leftSize) {
				useSize *= 2;
				blkSize += 1;
			}
			if (blkSize >= OS_SAFE_MEM_BLOCK_COUNT) {/*跟之前的拆分内存块程序相比只是多了这一步*/
				blkSize = OS_SAFE_MEM_BLOCK_COUNT-1;
			}
			pLeftBlk = (INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK) + size;/*记录分隔后的内存块的首地址*/
			((OS_SAFE_MEM_BLOCK *)(pLeftBlk))->OSLastPhyMemBlk = pblk;
			//((OS_SAFE_MEM_BLOCK *)pLeftBlk)->OSafeMemBlkSize = leftSize;
			((OS_SAFE_MEM_BLOCK *)pLeftBlk)->OSNextPhyMemBlk = ((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk;
			//((OS_SAFE_MEM_BLOCK *)pblk)->OSafeMemBlkSize = size;
			((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk = pLeftBlk;
			OS_ENTER_CRITICAL();
			if (OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree == 0) {
				((OS_SAFE_MEM_LIST_BLOCK*)(pLeftBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = NULL;
				((OS_SAFE_MEM_LIST_BLOCK*)(pLeftBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk = NULL;
				OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList = pLeftBlk;
			}
			else {
				pTempBlk = OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList;
				for (useSize = 0; useSize < OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree; useSize++) {
					blockSize = getBlkSize(pTempBlk);
					if (blockSize < leftSize) {
						if (useSize == OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree - 1) {
							((OS_SAFE_MEM_LIST_BLOCK*)(pLeftBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = pTempBlk;
							((OS_SAFE_MEM_LIST_BLOCK*)(pLeftBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk = NULL;
							((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk = pLeftBlk;
						}
						else {
							pTempBlk = (INT8U*)pTempBlk + sizeof(OS_SAFE_MEM_BLOCK);
							pTempBlk = *(void **)pTempBlk;
						}
					}
					else {
						/*将分割后剩下的内存块pLeftBlk插入pTempBlk之前*/
						if (useSize == 0u) {
							((OS_SAFE_MEM_LIST_BLOCK*)(pLeftBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = NULL;
							((OS_SAFE_MEM_LIST_BLOCK*)(pLeftBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk = pTempBlk;
							((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = pLeftBlk;
							OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList = pLeftBlk;
						}
						else {
							pLastBlk = ((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk;/*链表相邻的上一块*/
							((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = pLeftBlk;
							((OS_SAFE_MEM_LIST_BLOCK*)(pLeftBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = pLastBlk;
							((OS_SAFE_MEM_LIST_BLOCK*)(pLeftBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk = pTempBlk;
							((OS_SAFE_MEM_LIST_BLOCK*)(pLastBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk = pLeftBlk;
						}
						break;
					}
				}
			}
			OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree++;
			OSSafeMem->OSSafeMemFreeSize += leftSize;
			OSSafeMem->OSSafeMemTotalSize += leftSize + sizeof(OS_SAFE_MEM_BLOCK);
			OS_EXIT_CRITICAL();

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			/*输出调试信息*/
			sprintf(log_info,"OSSafeVarMemGet中，第%d个内存标签大小为%d,剩余内存块个数为%d；本块和下一个内存块的信息为：", blkSize, OSSafeMem->SafeMemParts[blkSize].OSafeMemPartBlkSize, OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree);
			recordLog("内存",log_info);
			memlog(OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList);
			memlog(pTempBlk);
#endif

		}
		else if (leftSize > OS_SAFE_MEM_BLOCK_MIN + sizeof(OS_SAFE_MEM_BLOCK)) {
			while (leftSize >= OS_SAFE_MEM_BLOCK_MIN + sizeof(OS_SAFE_MEM_BLOCK)) {/*分配完之后的剩余空间还可以再再插入递增内存块中*/
				blkSize = (leftSize - sizeof(OS_SAFE_MEM_BLOCK) - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl;
				useSize = OS_SAFE_MEM_BLOCK_MIN + blkSize * OS_SAFE_MEM_BLOCK_INERVAl;
				pLeftBlk = (INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK) + (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - useSize);
				leftSize -= sizeof(OS_SAFE_MEM_BLOCK) + useSize;
				if ((INT32S)(leftSize - sizeof(OS_SAFE_MEM_BLOCK)) < (INT32S)OS_SAFE_MEM_BLOCK_MIN) {
					((OS_SAFE_MEM_BLOCK *)pLeftBlk)->OSLastPhyMemBlk = pblk;
					((OS_SAFE_MEM_BLOCK *)pLeftBlk)->OSNextPhyMemBlk = ((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk;
					((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk = pLeftBlk;
				}
				else {
					((OS_SAFE_MEM_BLOCK *)pLeftBlk)->OSNextPhyMemBlk = ((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk;
					((OS_SAFE_MEM_BLOCK *)pLeftBlk)->OSLastPhyMemBlk = (INT8U)pLeftBlk - (OS_SAFE_MEM_BLOCK_MIN + ((leftSize - sizeof(OS_SAFE_MEM_BLOCK) - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl)* OS_SAFE_MEM_BLOCK_INERVAl);/*计算分隔出useSize大小的内存块之后剩下的空间可以分隔的最大内存块大小*/
				}
				//((OS_SAFE_MEM_BLOCK *)pLeftBlk)->OSafeMemBlkSize = useSize;
				//((OS_SAFE_MEM_BLOCK *)pblk)->OSafeMemBlkSize -= sizeof(OS_SAFE_MEM_BLOCK) + useSize;
				pTempBlk = pLeftBlk + sizeof(OS_SAFE_MEM_BLOCK);
				OS_ENTER_CRITICAL();
				((OS_SAFE_MEM_LIST_BLOCK*)pTempBlk)->OSNextListMemBlk = OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList;/*指明新划分出的内存块链表的位置中的下一块内存块，由于插入到链表头部，所以下一块为原来的链表头内存块*/
				pTempBlk = OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList;
				if (OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree != 0) {
					pTempBlk += sizeof(OS_SAFE_MEM_BLOCK);
					((OS_SAFE_MEM_LIST_BLOCK*)pTempBlk)->OSLastListMemBlk = pLeftBlk;
				}
				OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList = pLeftBlk;
				OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree++;
				OSSafeMem->OSSafeMemFreeSize += useSize;
				OSSafeMem->OSSafeMemTotalSize += useSize + sizeof(OS_SAFE_MEM_BLOCK);

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				/*输出调试信息*/
				sprintf(log_info,"OSSafeVarMemGet中，第%d个内存标签大小为%d,剩余内存块个数为%d；本块和下一个内存块的信息为：", blkSize,OSSafeMem->SafeMemParts[blkSize].OSafeMemPartBlkSize, OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree);
				recordLog("内存",log_info);
				memlog(OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList);
				memlog(pTempBlk);
#endif
				OS_EXIT_CRITICAL();
			}
		}
#if OS_SAFE_MEM_MERGE_EN == 0u
		blkSize = getBlkIndex(pblk);
		OSSafeMem->SafeMemParts[blkSize].OSafeMemPartUsedCount++;                    /* 统计域                                     */
		sprintf(log_info, "OSSafeVarMemGet中，申请内存标签大小为%d,统计域变为%d", OSSafeMem->SafeMemParts[blkSize].OSafeMemPartBlkSize, OSSafeMem->SafeMemParts[blkSize].OSafeMemPartUsedCount);
		recordLog("内存",log_info);
#endif

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
		/*输出调试信息*/
		recordLog("内存","OSSafeVarMemGet中取出的内存块的信息为：");
		memlog(pblk);
		sprintf(log_info, "OSSafeVarMemGet结束后，安全内存区剩余的可供分配的有效空间为%dB。", OSSafeMem->OSSafeMemFreeSize);
		recordLog("内存",log_info);
#endif
		//assert();断言分配的内存块与剩余内存块大小相加等于总的内存大小
		*perr = OS_ERR_NONE;                          /*      No error                                 */
		return (pblk);
	}
}

void  *OSSafeVarMemPend(INT8U  size, INT32U *timeout,INT8U   *perr)
{
	void      *pblk = OSSafeVarMemGet(size, perr);
	if (*perr == OS_ERR_SAFE_NO_SUIT_BLKS || *perr == OS_ERR_SAFE_TOO_LARGE_SIZE) {
		OS_ENTER_CRITICAL();
		/*说明没有合适的内存块，需要等待*/
		OSTCBCur->OSTCBDly = *timeout;
		/*将当前任务从就绪任务表中删除*/
		if ((OSRdyTbl[OSTCBCur->OSTCBY] &= ~OSTCBCur->OSTCBBitX) == 0) {
				OSRdyGrp &= ~OSTCBCur->OSTCBBitY;
		}
		OSSafeVarSizes[OSPrioCur] = size;
		OSSafeMemTbl[OSTCBCur->OSTCBY] |= OSTCBCur->OSTCBBitX;
		OSSafeMemGrp |= OSTCBCur->OSTCBBitY;
		OS_EXIT_CRITICAL();
		OS_Sched();
		pblk = OSSafeVarMemGet(size, perr);
		if (*perr == OS_ERR_SAFE_NO_SUIT_BLKS || *perr == OS_ERR_SAFE_TOO_LARGE_SIZE) {
			OS_ENTER_CRITICAL();
			OSSafeVarSizes[OSPrioCur] = 0;
			/*从安全内存的等待任务列表里将任务删除*/
			if ((OSSafeMemTbl[OSTCBCur->OSTCBY] &= ~OSTCBCur->OSTCBBitX) == 0)
			{
				OSSafeMemGrp &= ~OSTCBCur->OSTCBBitY;
			}
			*timeout = OSTCBCur->OSTCBDly;
			OSTCBCur->OSTCBDly = 0;
			OS_EXIT_CRITICAL();
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_TIMEOUT\n");
#endif
			*perr = OS_ERR_TIMEOUT;
		}
		else {
			OS_ENTER_CRITICAL();
			*timeout = OSTCBCur->OSTCBDly;
			OSTCBCur->OSTCBDly = 0;
			OS_EXIT_CRITICAL();
		}
		return pblk;
	}
	else {
		return pblk;
	}
}
/*
void  *SafeVarMemGet(INT8U  size,
	INT8U   *perr)
{
	void      *pblk = 0u;
	size += sizeof(OS_SAFE_MEM_USED_BLOCK);//加上前面用于保存优先级等信息的空间，以后可能会删掉
	pblk = OSSafeVarMemGet(size, perr);
	if (perr == OS_ERR_NONE) {
		((OS_SAFE_MEM_USED_BLOCK*)((INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK)))->prio = OSPrioCur;
		printf("OSSafeVarMemGet取出的内存块中写入优先级之后内存块的信息为： ");
		log(pblk);
	}
	return pblk;
}
*/

/*$PAGE*/
/*
*********************************************************************************************************
*                                         RELEASE A SAFE MEMORY BLOCK
*
* Description : Returns a memory block to a partition
*
* Arguments   : pmem    is a pointer to the memory partition control block
*
*               pblk    is a pointer to the memory block being released.
*
* Returns     : OS_ERR_NONE              if the memory block was inserted into the partition
*               OS_ERR_MEM_FULL          if you are returning a memory block to an already FULL memory
*                                        partition (You freed more blocks than you allocated!)
*               OS_ERR_MEM_INVALID_PMEM  if you passed a NULL pointer for 'pmem'
*               OS_ERR_MEM_INVALID_PBLK  if you passed a NULL pointer for the block to release.
*********************************************************************************************************
*/

INT8U OSSafeVarMemPut(void * pblk)
{
#if OS_CRITICAL_METHOD == 3u                     /* Allocate storage for CPU status register           */
	OS_CPU_SR  cpu_sr = 0u;
#endif

	INT8U     *pTempBlk;
	INT8U     *pLeftBlk;
	INT8U     *pRightBlk;
	INT32U      blkSize;  /*应当在哪个下标下的内存块中取*/
	INT32U      useSize;
	INT32U      blockSize;/*用来替代之前的数据结构保存安全内存块大小*/
	INT32U      tmpBlockSize;/*用来替代之前的数据结构保存安全内存块大小*/
	/*用于使一个任务进入就绪状态*/
	OS_TCB *ptcb;
#if OS_SAFE_MEM_SIZE_PRIOR == 0u
	INT8U x;
#endif
	INT8U y;
	INT8U prio;
#if OS_ARG_CHK_EN > 0u
	if (OSSafeMem == (OS_SAFE_MEM *)0) {                        /* Must point to a valid safe memory partition        */
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_INVALID_PMEM\n");
#endif
		return OS_ERR_SAFE_INVALID_PMEM;
	}
	if (pblk == (void *)0) {                     /* Must release a valid block                         */
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_INVALID_PBLK\n");
#endif
		return (OS_ERR_SAFE_INVALID_PBLK);
	}
#endif
	blockSize = getBlkSize(pblk);
	OS_ENTER_CRITICAL();
#if OS_SAFE_MEM_MERGE_EN == 0u
	if (OSSafeMem->OSSafeMemTotalSize + blockSize > 5*OS_SAFE_MEM_TOTAL_SIZE) {  /* Make sure all blocks not already returned          */
#else	
	if (OSSafeMem->OSSafeMemTotalSize + blockSize > OS_SAFE_MEM_TOTAL_SIZE) {  /* Make sure all blocks not already returned          */
#endif
		OS_EXIT_CRITICAL();
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_MEM_FULL\n");
#endif
		return OS_ERR_SAFE_MEM_FULL;
	}
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	/*输出调试信息*/
	recordLog("内存","OSSafeVarMemPut中准备插入的内存块的信息为： ");
	memlog(pblk);
#endif
#if OS_SAFE_MEM_MERGE_EN > 0u
	pTempBlk = ((OS_SAFE_MEM_BLOCK*)pblk)->OSLastPhyMemBlk;/*先合并左边的所有内存块*/
	while (pTempBlk != NULL) {
		pRightBlk = ((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk;
		pLeftBlk = ((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk;
		blkSize = getBlkIndex(pTempBlk);
		/*如果内存块前两个指针保存的数据，即假设保存的链表相邻的内存块，大小必须跟当前大小一致，说明是空闲的，需要在使用安全数据区的内存块时保证这一属性*/
		if (pLeftBlk == NULL && pRightBlk == NULL
			|| (pRightBlk == NULL && pLeftBlk != NULL && pLeftBlk >= (INT8U*)(OSSafeMem->OSSafeMemAddr) &&pLeftBlk < (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE) && getBlkIndex(pLeftBlk) == blkSize
			|| (pLeftBlk == NULL && pRightBlk != NULL && pRightBlk >= (INT8U*)(OSSafeMem->OSSafeMemAddr)  &&pRightBlk < (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE) && getBlkIndex(pRightBlk) == blkSize
			|| (pLeftBlk >= (INT8U*)(OSSafeMem->OSSafeMemAddr)  &&pLeftBlk < (INT8U*)(OSSafeMem->OSSafeMemAddr) + OS_SAFE_MEM_TOTAL_SIZE && pRightBlk >= (INT8U*)(OSSafeMem->OSSafeMemAddr)  &&pRightBlk < (INT8U*)(OSSafeMem->OSSafeMemAddr) + OS_SAFE_MEM_TOTAL_SIZE) && getBlkIndex(pLeftBlk) == blkSize && getBlkIndex(pRightBlk) == blkSize) {

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			recordLog("内存","OSSafeVarMemPut中准备合并左边的内存块：");
			memlog(pTempBlk);
#endif
			if (blkSize <((OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1) && OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree <= OSSafeBlockNum[blkSize]) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				recordLog("内存","现有的该大小的内存块不多（小于等于设定值），取消合并");
#endif
				break;
			}
			tmpBlockSize = (INT8U*)((OS_SAFE_MEM_BLOCK *)pTempBlk)->OSNextPhyMemBlk - pTempBlk - sizeof(OS_SAFE_MEM_BLOCK);
			if (tmpBlockSize <= OS_SAFE_MEM_BLOCK_MAX) {
				blkSize = (tmpBlockSize - OS_SAFE_MEM_BLOCK_MIN) % OS_SAFE_MEM_BLOCK_INERVAl == 0 ? (tmpBlockSize - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl : (tmpBlockSize - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1;
			}
			else {
				useSize = OS_SAFE_MEM_BLOCK_MAX * 2;
				blkSize = (OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1;
				while (useSize < tmpBlockSize) {
					useSize *= 2;
					blkSize += 1;
				}
				if (blkSize >= OS_SAFE_MEM_BLOCK_COUNT) {
					blkSize = OS_SAFE_MEM_BLOCK_COUNT-1;
				}
			}
			if (OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree > 0) {
				OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree--;
				OSSafeMem->OSSafeMemFreeSize -= tmpBlockSize;
				OSSafeMem->OSSafeMemTotalSize -= tmpBlockSize + sizeof(OS_SAFE_MEM_BLOCK);
				/*更改内存块链表*/
				if (pLeftBlk == NULL) {
					OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList = pRightBlk;
				}
				else {
					((OS_SAFE_MEM_LIST_BLOCK*)(pLeftBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk = pRightBlk;
				}
				if (pRightBlk != NULL) {
					((OS_SAFE_MEM_LIST_BLOCK*)(pRightBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = pLeftBlk;
				}
				/*更改合并后的内存块前后物理相邻块,此处跟下面不同*/
				((OS_SAFE_MEM_BLOCK*)pTempBlk)->OSNextPhyMemBlk = ((OS_SAFE_MEM_BLOCK*)pblk)->OSNextPhyMemBlk;
				blockSize += tmpBlockSize + sizeof(OS_SAFE_MEM_BLOCK);
				pblk = pTempBlk;
				pTempBlk = ((OS_SAFE_MEM_BLOCK*)pTempBlk)->OSLastPhyMemBlk;
			}
			else {
#if OS_SAFE_MEM_DETAIL_OUT_EN
				OS_Printf("OS_ERR_SAFE_CONFLICT_STRUCT\n");
#endif
				return (OS_ERR_SAFE_CONFLICT_STRUCT);
			}
		}
		else break;
	}
	/*if (pTempBlk != NULL&&((OS_SAFE_MEM_BLOCK*)pTempBlk)->OSNextPhyMemBlk != pblk) {
		((OS_SAFE_MEM_BLOCK*)pTempBlk)->OSNextPhyMemBlk = pblk;
	}*/

	pTempBlk = ((OS_SAFE_MEM_BLOCK*)pblk)->OSNextPhyMemBlk;/*合并右边的所有内存块*/
	while (pTempBlk != NULL) {
		pRightBlk = ((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk;
		pLeftBlk = ((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk;
		blkSize = getBlkIndex(pTempBlk);
		/*如果内存块前两个指针保存的数据，即假设保存的链表相邻的内存块，大小必须跟当前大小一致，说明是空闲的，需要在使用安全数据区的内存块时保证这一属性*/
		if (pLeftBlk == NULL && pRightBlk == NULL
			|| (pRightBlk == NULL && pLeftBlk != NULL && pLeftBlk >= (INT8U*)(OSSafeMem->OSSafeMemAddr) &&pLeftBlk < (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE) && getBlkIndex(pLeftBlk) == blkSize
			|| (pLeftBlk == NULL && pRightBlk != NULL && pRightBlk >= (INT8U*)(OSSafeMem->OSSafeMemAddr)  &&pRightBlk < (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE) && getBlkIndex(pRightBlk) == blkSize
			|| (pLeftBlk >= (INT8U*)(OSSafeMem->OSSafeMemAddr)  &&pLeftBlk < (INT8U*)(OSSafeMem->OSSafeMemAddr) + OS_SAFE_MEM_TOTAL_SIZE && pRightBlk >= (INT8U*)(OSSafeMem->OSSafeMemAddr)  &&pRightBlk < (INT8U*)(OSSafeMem->OSSafeMemAddr) + OS_SAFE_MEM_TOTAL_SIZE) && getBlkIndex(pLeftBlk) == blkSize && getBlkIndex(pRightBlk) == blkSize) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			recordLog("内存", "OSSafeVarMemPut中准备合并右边的内存块：");
			memlog(pTempBlk);
#endif
			if (blkSize < ((OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1) && OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree <= OSSafeBlockNum[blkSize]) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				recordLog("内存", "现有的该大小的内存块不多（小于等于设定值），取消合并");
#endif
				break;
			}
			tmpBlockSize = getBlkSize(pTempBlk);
			if (tmpBlockSize <= OS_SAFE_MEM_BLOCK_MAX) {
				blkSize = (tmpBlockSize - OS_SAFE_MEM_BLOCK_MIN) % OS_SAFE_MEM_BLOCK_INERVAl == 0 ? (tmpBlockSize - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl : (tmpBlockSize - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1;
			}
			else {
				useSize = OS_SAFE_MEM_BLOCK_MAX * 2;
				blkSize = (OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1;
				while (useSize < tmpBlockSize) {
					useSize *= 2;
					blkSize += 1;
				}
				if (blkSize >= OS_SAFE_MEM_BLOCK_COUNT) {
					blkSize = OS_SAFE_MEM_BLOCK_COUNT-1;
				}
			}
			if (OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree > 0) {
				OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree--;
				OSSafeMem->OSSafeMemFreeSize -= tmpBlockSize;
				OSSafeMem->OSSafeMemTotalSize -= tmpBlockSize + sizeof(OS_SAFE_MEM_BLOCK);
				/*更改内存块链表*/
				if (pLeftBlk == NULL) {
					OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList = pRightBlk;
				}
				else {
					((OS_SAFE_MEM_LIST_BLOCK*)(pLeftBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk = pRightBlk;
				}
				if (pRightBlk != NULL) {
					((OS_SAFE_MEM_LIST_BLOCK*)(pRightBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = pLeftBlk;
				}
				/*更改合并后的内存块前后物理相邻块,此处跟上面不同*/
				((OS_SAFE_MEM_BLOCK*)pblk)->OSNextPhyMemBlk = ((OS_SAFE_MEM_BLOCK*)pTempBlk)->OSNextPhyMemBlk;
				blockSize += tmpBlockSize + sizeof(OS_SAFE_MEM_BLOCK);

				pTempBlk = ((OS_SAFE_MEM_BLOCK*)pTempBlk)->OSNextPhyMemBlk;
			}
			else {
#if OS_SAFE_MEM_DETAIL_OUT_EN
				OS_Printf("OS_ERR_SAFE_CONFLICT_STRUCT\n");
#endif
				return (OS_ERR_SAFE_CONFLICT_STRUCT);
			}
		}
		else {
			break;
		}
	}
	 if (pTempBlk != NULL&&((OS_SAFE_MEM_BLOCK*)pTempBlk)->OSLastPhyMemBlk != pblk) {
		 ((OS_SAFE_MEM_BLOCK*)pTempBlk)->OSLastPhyMemBlk = pblk;
	 }
#endif
	if (blockSize > OS_SAFE_MEM_BLOCK_MAX) {/*合并之后的剩余空间可以插入翻倍内存块中*/
		useSize = OS_SAFE_MEM_BLOCK_MAX * 2;
		blkSize = (OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1;
		while (useSize < blockSize) {
			useSize *= 2;
			blkSize += 1;
		}
		if (blkSize >=OS_SAFE_MEM_BLOCK_COUNT) {
			blkSize = OS_SAFE_MEM_BLOCK_COUNT-1;
		}
	}
	else{
		blkSize = (blockSize - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl;
	}
	/*确定了插入下标之后,将合并后产生的内存块pblk插入pTempBlk之前*/
	if (OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree == 0) {
		((OS_SAFE_MEM_LIST_BLOCK*)((INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = NULL;
		((OS_SAFE_MEM_LIST_BLOCK*)((INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk = NULL;
		OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList = pblk;
	}
	else {
		pTempBlk = OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList;
		for (useSize = 0; useSize < OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree; useSize++) {
			tmpBlockSize = getBlkSize(pTempBlk);
			if (tmpBlockSize < blockSize) {
				if (useSize == OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree - 1) {
					((OS_SAFE_MEM_LIST_BLOCK*)((INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = pTempBlk;
					((OS_SAFE_MEM_LIST_BLOCK*)((INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk = NULL;
					((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk = pblk;
				}
				else {
					pTempBlk = (INT8U*)pTempBlk + sizeof(OS_SAFE_MEM_BLOCK);
					pTempBlk = *(void **)pTempBlk;
				}
			}
			else {
				/*将合并后产生的内存块pblk插入pTempBlk之前*/
				if (useSize == 0u) {
					((OS_SAFE_MEM_LIST_BLOCK*)((INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = NULL;
					((OS_SAFE_MEM_LIST_BLOCK*)((INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk = pTempBlk;
					((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = pblk;
					OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList = pblk;
				}
				else {
					pLeftBlk = ((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk;/*链表相邻的上一块*/
					((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = pblk;
					((OS_SAFE_MEM_LIST_BLOCK*)((INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = pLeftBlk;
					((OS_SAFE_MEM_LIST_BLOCK*)((INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk = pTempBlk;
					((OS_SAFE_MEM_LIST_BLOCK*)(pLeftBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk = pblk;
				}
				break;
			}
		}
	}
	OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree++;
	OSSafeMem->OSSafeMemFreeSize += blockSize;
	OSSafeMem->OSSafeMemTotalSize += blockSize + sizeof(OS_SAFE_MEM_BLOCK);
	if (blkSize > OSSafeMem->OSSafeMemPartMaxIndex) {
		OSSafeMem->OSSafeMemPartMaxIndex = blkSize;
	}

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	/*输出调试信息*/
	recordLog("内存", "OSSafeVarMemPut中最终插入的内存块的信息为： ");
	memlog(pblk);
#endif

	if (OSSafeMemGrp) {/*说明有任务正在等待分配安全区内存*/
#if OS_SAFE_MEM_SIZE_PRIOR > 0u
		for (prio = 0u; prio < OS_LOWEST_PRIO; prio++) {
#else
#if OS_LOWEST_PRIO <= 63u
		y = OSUnMapTbl[OSSafeMemGrp];              /* Find HPT waiting for message                */
		x = OSUnMapTbl[OSSafeMemTbl[y]];
		prio = (INT8U)((y << 3u) + x);                      /* Find priority of task getting the msg       */
#else
		if ((pevent->OSEventGrp & 0xFFu) != 0u) {           /* Find HPT waiting for message                */
			y = OSUnMapTbl[pevent->OSEventGrp & 0xFFu];
		}
		else {
			y = OSUnMapTbl[(OS_PRIO)(pevent->OSEventGrp >> 8u) & 0xFFu] + 8u;
		}
		ptbl = &pevent->OSEventTbl[y];
		if ((*ptbl & 0xFFu) != 0u) {
			x = OSUnMapTbl[*ptbl & 0xFFu];
		}
		else {
			x = OSUnMapTbl[(OS_PRIO)(*ptbl >> 8u) & 0xFFu] + 8u;
		}
		prio = (INT8U)((y << 4u) + x);                      /* Find priority of task getting the msg       */
#endif
#endif/*OS_SAFE_MEM_SIZE_PRIOR*/
		if (OSSafeVarSizes[prio] <= blockSize) {/*回收之后的内存大小可以满足等待分配的最高优先级的任务*/
			ptcb = OSTCBPrioTbl[prio];

			y = ptcb->OSTCBY;
			OSSafeMemTbl[y] &= (OS_PRIO)~ptcb->OSTCBBitX;    /* Remove task from wait list              */
			if (OSSafeMemTbl[y] == 0u) {
				OSSafeMemGrp &= (OS_PRIO)~ptcb->OSTCBBitY;
			}
			if ((ptcb->OSTCBStat &   OS_STAT_SUSPEND) == OS_STAT_RDY) {
				OSRdyGrp |= ptcb->OSTCBBitY;           /* Put task in the ready to run list           */
				OSRdyTbl[y] |= ptcb->OSTCBBitX;
				//ptcb->OSTCBDly = 0;
				OS_EXIT_CRITICAL();
				OS_Sched();
			}
			else {
				OS_EXIT_CRITICAL();
			}
#if OS_SAFE_MEM_SIZE_PRIOR > 0u
			break;
		}
#endif
		}
	}
	else {
		OS_EXIT_CRITICAL();
	}

	return (OS_ERR_NONE);                        /* Notify caller that memory block was released       */
}
/*$PAGE*/

/*$PAGE*/
/*
*********************************************************************************************************
*                                          QUERY SAFE MEMORY PARTITION
*
* Description : This function is used to determine the number of free memory blocks and the number of
*               used memory blocks from a memory partition.
*
* Arguments   : pmem        is a pointer to the memory partition control block
*
*               p_mem_data  is a pointer to a structure that will contain information about the memory
*                           partition.
*
* Returns     : OS_ERR_NONE               if no errors were found.
*               OS_ERR_MEM_INVALID_PMEM   if you passed a NULL pointer for 'pmem'
*               OS_ERR_MEM_INVALID_PDATA  if you passed a NULL pointer to the data recipient.
*********************************************************************************************************
*/
INT8U  OSSafeVarMemQuery(OS_SAFE_MEM_DATA  *p_safe_mem_data)
{
#if OS_CRITICAL_METHOD == 3u                     /* Allocate storage for CPU status register           */
		OS_CPU_SR  cpu_sr = 0u;
#endif

		INT32S      i;
#if OS_ARG_CHK_EN > 0u
		if (OSSafeMem == (OS_SAFE_MEM *)0) {                   /* Must point to a valid safe memory partition             */
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_INVALID_PMEM\n");
#endif
			return (OS_ERR_SAFE_INVALID_PMEM);
		}
		if (p_safe_mem_data == (OS_SAFE_MEM_DATA *)0) {        /* Must release a valid storage area for the data     */
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_INVALID_PDATA\n");
#endif
			return (OS_ERR_SAFE_INVALID_PDATA);
		}
#endif
		OS_ENTER_CRITICAL();
		p_safe_mem_data->SafeMemAddr = OSSafeMem->OSSafeMemAddr;
		for (i = 0; i < OS_SAFE_MEM_BLOCK_COUNT; i++) {
			p_safe_mem_data->Parts[i].PartBlkSize = OSSafeMem->SafeMemParts[i].OSafeMemPartBlkSize;
			p_safe_mem_data->Parts[i].PartNFree = OSSafeMem->SafeMemParts[i].OSSafeMemPartNFree;

#if OS_SAFE_MEM_MERGE_EN == 0u
			/*统计各种大小的安全内存的最大使用次数*/
			p_safe_mem_data->Parts[i].PartUsedCount = OSSafeMem->SafeMemParts[i].OSafeMemPartUsedCount;                    /* 统计域                                     */
#endif
		}
		p_safe_mem_data->TotalSize = OSSafeMem->OSSafeMemTotalSize;
		p_safe_mem_data->FreeSize = OSSafeMem->OSSafeMemFreeSize;
		p_safe_mem_data->PartCount = OSSafeMem->OSSafeMemPartMaxIndex + 1;
		OS_EXIT_CRITICAL(); 
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
		OSSafeMemLog();/*输出安全数据区详细信息*/
#endif
		return (OS_ERR_NONE);
}
/*$PAGE*/

/*$PAGE*/
/*
*********************************************************************************************************
*                                          QUERY SAFE MEMORY PARTITION
*
* Description : 内存回收.
*
* Arguments   : pmem        is a pointer to the memory partition control block
*
*               p_mem_data  is a pointer to a structure that will contain information about the memory
*                           partition.
*
* Returns     : OS_ERR_NONE               if no errors were found.
*               OS_ERR_MEM_INVALID_PMEM   if you passed a NULL pointer for 'pmem'
*               OS_ERR_MEM_INVALID_PDATA  if you passed a NULL pointer to the data recipient.
*********************************************************************************************************
*/
void  OSSafeVarMemRecycle()
{
#if OS_CRITICAL_METHOD == 3u                     /* Allocate storage for CPU status register           */
	OS_CPU_SR  cpu_sr = 0u;
#endif

	INT8U      prio;
	INT32S     i;
	INT8U     *pTempBlk;
	INT8U     *pRightBlk;

#if OS_ARG_CHK_EN > 0u
	if (OSSafeMem == (OS_SAFE_MEM *)0) {                   /* Must point to a valid safe memory partition             */
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_INVALID_PMEM\n");
#endif
		return;
	}
#endif
	pTempBlk = OSSafeMem->OSSafeMemAddr;

	OS_ENTER_CRITICAL();
	while (pTempBlk < (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE) {
		if (pTempBlk == NULL) {
			OS_EXIT_CRITICAL();
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info,"起始地址为0X%X的内存块没有内存泄漏，恭喜！", pTempBlk);
			recordLog("内存",log_info);
#endif
			return;
		}
		else if (pTempBlk < (INT8U*)OSSafeMem->OSSafeMemAddr) {
			OS_EXIT_CRITICAL();
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info,"\n0X%X内存回收过程中指针指向出现了问题！", pTempBlk);
			recordLog("内存",log_info);
#endif
			return;
		}
		/*OS_ENTER_CRITICAL();这种情况之下test.c中的延时函数不生效了，为啥呢？*/
		pRightBlk = ((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk;
		if (pRightBlk!=NULL && (pRightBlk < (INT8U*)OSSafeMem->OSSafeMemAddr || pRightBlk >(INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE)) {/*应该说明本块内存已经被申请了*/
			prio = ((OS_SAFE_MEM_USED_BLOCK*)((INT8U*)pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->prio;
			if(prio>0) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				/*输出调试信息*/
				sprintf(log_info,"当前执行任务的优先级为%d,现在处于就绪状态的任务为:", OSPrioCur);
				recordLog("内存",log_info);
				log_info[0] = '\0';
				for (i = 0; i < OS_LOWEST_PRIO; i++) {
					if (OSRdyTbl[i])
						sprintf(log_info,"%s%d ；", log_info,i);
				}
				recordLog("内存",log_info);
#endif
				if (OSRdyTbl[prio]) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
					sprintf(log_info,"起始地址为0X%X的内存块是被优先级为%d的任务申请的，仍然处于就绪状态，无法回收（也有可能是后来创建的相同优先级的任务？通过任务控制块记录的创建时间来对比吧！）。", pTempBlk, prio);
					recordLog("内存",log_info);
#endif
				}
				else {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
					sprintf(log_info,"起始地址为0X%X的内存块是被优先级为%d的任务申请的，不处于就绪状态，可以回收。", pTempBlk, prio);
					recordLog("内存",log_info);
#endif
					OSSafeVarMemPut(pTempBlk);
					break;
				}
			}
		}
		pTempBlk = ((OS_SAFE_MEM_BLOCK*)pTempBlk)->OSNextPhyMemBlk;
		//OS_EXIT_CRITICAL();
	}

	OS_EXIT_CRITICAL();
}
/*$PAGE*/

void OSSafeMemLog() {
#if OS_CRITICAL_METHOD == 3u                     /* Allocate storage for CPU status register           */
	OS_CPU_SR  cpu_sr = 0u;
#endif

	INT8U     *pTempBlk;
	if (OSSafeMem == NULL|| OSSafeMem->OSSafeMemAddr==NULL) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
		recordLog("内存", "未成功分配安全数据区内存。");
#endif
	}
	else {
		OS_ENTER_CRITICAL();
		pTempBlk = OSSafeMem->OSSafeMemAddr;
		while (pTempBlk < (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			memlog(pTempBlk);
#endif
			if (pTempBlk == NULL) {
				OS_EXIT_CRITICAL();
				return;
			}
			pTempBlk = ((OS_SAFE_MEM_BLOCK*)pTempBlk)->OSNextPhyMemBlk;
		}
		OS_EXIT_CRITICAL();
	}
}


#endif                                                    /* OS_SAFE_MEM_EN                                 */

