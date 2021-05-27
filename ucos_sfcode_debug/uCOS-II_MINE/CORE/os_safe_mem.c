
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
* By      : ������
* Version : V1.0
*
* LICENSING TERMS:
* ---------------
*  ���ڹ�����ȫ�������ĺ���
*********************************************************************************************************
*/

#ifndef  OS_MASTER_FILE
#include <ucos_ii.h>
#endif
#include <assert.h>

#if (OS_SAFE_MEM_EN > 0u)

#if OS_SAFE_MEM_MERGE_EN == 1u
/*�趨�����ڴ�����ÿ�ִ�С���ڴ��ĳ�ʼ�������ڻ����ڴ��ʱ��ϲ����ڴ�ֵ��һ����ڴ��*/
INT32U  const  OSSafeBlockNum[(OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1] = {3,3,3,3};
#endif

/*���ݰ�ȫ�������׵�ַ��ȡ������������Ч�ռ��С*/
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

/*���ݰ�ȫ�������׵�ַ��ȡ������������Ч�ռ��С��Ȼ�󷵻����ڰ�ȫ�����������������±�*/
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

/*������ڴ��ĵ�����Ϣ*/
void memlog(INT8U  *pblk) {

	if (pblk != NULL) {
		if (((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk == NULL) {
			//printf("��ȫ��������ʼ��ַΪ0X%d����СΪ%d,������ַΪ0X%X", OSSafeMem->OSSafeMemAddr, OS_SAFE_MEM_TOTAL_SIZE, (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE);

#if OS_SAFE_MEM_MERGE_EN == 0u
			sprintf(log_info, "��ַ0X%X -- 0X%X �Ѵ洢����ֵΪ0X%X���������ڵ���һ�飩��%d(�ڴ����ô�С)��0X%X���������ڵ���һ�飩��0X%X���������ڵ���һ�飩��0X%X���������ڵ���һ�飩��", pblk, (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE, ((OS_SAFE_MEM_BLOCK *)pblk)->OSLastPhyMemBlk, (INT8U*)OSSafeMem->OSSafeMemAddr + 5*OS_SAFE_MEM_TOTAL_SIZE - pblk - sizeof(OS_SAFE_MEM_BLOCK), ((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk, *(void **)(pblk + sizeof(OS_SAFE_MEM_BLOCK)), *(void **)(pblk + sizeof(OS_SAFE_MEM_BLOCK) + sizeof(INT8U*)));
#else
			sprintf(log_info, "��ȫ�ڴ�0X%X -- 0X%X���û������ڴ�%4d �ֽڣ�ʵ������0X%7X <---> 0X%7X����������0X%7X  <---> 0X%7X", pblk, (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE, (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE - pblk - sizeof(OS_SAFE_MEM_BLOCK), ((OS_SAFE_MEM_BLOCK *)pblk)->OSLastPhyMemBlk, ((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk, *(void **)(pblk + sizeof(OS_SAFE_MEM_BLOCK)), *(void **)(pblk + sizeof(OS_SAFE_MEM_BLOCK) + sizeof(INT8U*)));
#endif
			recordLog("�ڴ�",log_info);
		}
		else {
			sprintf(log_info, "��ȫ�ڴ�0X%X -- 0X%X���û������ڴ�%4d �ֽڣ�ʵ������0X%7X <---> 0X%7X����������0X%7X  <---> 0X%7X", pblk, ((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk, (INT8U*)((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk - pblk - sizeof(OS_SAFE_MEM_BLOCK), ((OS_SAFE_MEM_BLOCK *)pblk)->OSLastPhyMemBlk, ((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk, *(void **)(pblk + sizeof(OS_SAFE_MEM_BLOCK)), *(void **)(pblk + sizeof(OS_SAFE_MEM_BLOCK) + sizeof(INT8U*)));
			recordLog("�ڴ�",log_info);
		}
	}
	else
		recordLog("�ڴ�", "��ָ��");
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
	INT32U             part;/*����������ͬ��С���ڴ��*/
	INT32U             list;/*����������ͬ��С���ڴ��*/
	INT32U             memSize = 0;/*������¼��ʼ��֮���ܵ���Ч�ռ�*/
	INT32U             leftMemSize;
	INT32U             blkSize;
	INT8U            *pblk;
	void            **plink;
	void             *lastPhyBlk;
	void             *lastListBlk;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* ��������Ч�� */
	INT8U            n;
	if (OS_SAFE_MEM_BLOCK_MIN < sizeof(OS_SAFE_MEM_LIST_BLOCK)) {/*�����ܴ������ָ��*/
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
	if (n + 1 > OS_SAFE_MEM_BLOCK_COUNT) {/*�����ڴ������һ����ŵ��ڴ����ܴ��ڱ�ʶ������*/
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_SMALL_BLOCK_COUNT\n");
#endif
		*perr = OS_ERR_SAFE_SMALL_BLOCK_COUNT;
		return;
	}
	/*�ܴ�С�������㹻�����趨�ĸ�����ȫ����������*/
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
	pmem = malloc(OS_SAFE_MEM_TOTAL_SIZE*5);                             /* ��̬����һ���ڴ���Ϊ��ȫ�������������֧�ֺϲ�������Ҫ����伸����С���ã�����ʱ��malloc���棬֮�����ֱ��������ڲ����д��ݽ�����ucos��һ�㶼��ֱ�����������뾲̬��ַ */
#else
	pmem = malloc(OS_SAFE_MEM_TOTAL_SIZE);                               /* ��̬����һ���ڴ���Ϊ��ȫ������������ʱ��malloc���棬֮�����ֱ��������ڲ����д��ݽ�����ucos��һ�㶼��ֱ�����������뾲̬��ַ */
#endif
	OS_EXIT_CRITICAL();
	if (pSafeMem == (OS_SAFE_MEM*)0 || pmem == (void *)0) {                        /* �ڴ�û�з���ɹ�             */
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_NO_MEM\n");
#endif
		*perr = OS_ERR_SAFE_NO_MEM;
		return;
	}
	//plink = (void **)pmem;

	OSSafeMem = pSafeMem;
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	sprintf(log_info, "��ȫ�������ڴ��׵�ַΪ:0X%X", pmem);
	recordLog("�ڴ�",log_info);
#endif
	pblk = (INT8U *)pmem;
	lastPhyBlk = NULL;
#if OS_SAFE_MEM_MERGE_EN == 0u
	for (part = 0; part < (OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1; part += 1) {
		blkSize = OS_SAFE_MEM_BLOCK_MIN + part * OS_SAFE_MEM_BLOCK_INERVAl;
		pSafeMem->SafeMemParts[part].OSafeMemPartBlkSize = blkSize;
		pSafeMem->SafeMemParts[part].OSSafeMemPartNFree = 0;
		pSafeMem->SafeMemParts[part].OSafeMemPartUsedCount = 0;                    /* ͳ����                                     */
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
			((OS_SAFE_MEM_BLOCK *)pblk)->OSNextPhyMemBlk = pblk + sizeof(OS_SAFE_MEM_BLOCK) + blkSize;/*�����ڼ�¼ǰ���������������ڴ������ݽṹд��*/
			lastPhyBlk = pblk;
			pblk += sizeof(OS_SAFE_MEM_BLOCK);
			plink = (void **)pblk;
			if (list == OSSafeBlockNum[part] - 1) {
				((OS_SAFE_MEM_LIST_BLOCK*)pblk)->OSNextListMemBlk = NULL;
			}
			else {
				((OS_SAFE_MEM_LIST_BLOCK*)pblk)->OSNextListMemBlk = (void *)(pblk + blkSize);/*����������һ���ڴ��ĵ�ַ���ڱ�����Ч�ռ俪ʼ��*/
			}
			((OS_SAFE_MEM_LIST_BLOCK*)pblk)->OSLastListMemBlk = lastListBlk;/*����������һ���ڴ��ĵ�ַ���� ��һ���ڴ��ĵ�ַ ֮��*/
			lastListBlk = lastPhyBlk;
			pblk += blkSize;/*ָ���ƶ���δ����Ŀռ䴦*/
			memSize += blkSize;/*������Ч�ռ��С*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			memlog(pblk - blkSize - sizeof(OS_SAFE_MEM_BLOCK));
#endif
		}
	}
	leftMemSize = (INT8U*)pmem - pblk + OS_SAFE_MEM_TOTAL_SIZE;
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	sprintf(log_info, "OSSafeVarMemInit�����У�����������ڴ��֮��ʣ��ռ�Ϊ: %d", leftMemSize);
	recordLog("�ڴ�",log_info);
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
			((OS_SAFE_MEM_LIST_BLOCK*)pblk)->OSNextListMemBlk = NULL;/*����������һ���ڴ��ĵ�ַ���ڱ�����Ч�ռ俪ʼ��*/
			((OS_SAFE_MEM_LIST_BLOCK*)pblk)->OSLastListMemBlk = NULL;/*����������һ���ڴ��ĵ�ַ���ڱ�����Ч�ռ俪ʼ��*/
#if OS_SAFE_MEM_MERGE_EN == 0u
			pSafeMem->SafeMemParts[part].OSafeMemPartUsedCount = 0;                    /* ͳ����                                     */
#endif
			memSize += leftMemSize;/*������Ч�ռ��С*/
			pSafeMem->OSSafeMemPartMaxIndex = part;

			/*���������Ϣ*/
			//printf("OSSafeVarMemInit�з����ڴ�����ϢΪ�� ");
			//log(pblk - sizeof(OS_SAFE_MEM_BLOCK));

			for (part=part+1 ; part < OS_SAFE_MEM_BLOCK_COUNT; part++) {
				//pSafeMem->SafeMemParts[part].OSSafeMemPartAddr = NULL;
				blkSize *= 2;
				pSafeMem->SafeMemParts[part].OSafeMemPartBlkSize = blkSize;
				pSafeMem->SafeMemParts[part].OSSafeMemPartFreeList = NULL;
				pSafeMem->SafeMemParts[part].OSSafeMemPartNFree = 0;
#if OS_SAFE_MEM_MERGE_EN == 0u
				pSafeMem->SafeMemParts[part].OSafeMemPartUsedCount = 0;                    /* ͳ����                                     */
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
			pSafeMem->SafeMemParts[part].OSafeMemPartUsedCount = 0;                    /* ͳ����                                     */
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
	INT32U      blkSize;  /*Ӧ�����ĸ��±��µ��ڴ����ȡ*/
	INT32U      leftSize;
	INT32U      useSize;
	INT32U      blockSize;/*�������֮ǰ�����ݽṹ���氲ȫ�ڴ���С*/

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
	if (size > OSSafeMem->OSSafeMemFreeSize) {/*����Ŀռ���ڰ�ȫ������������Ч�ռ�*/
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_TOO_LARGE_SIZE\n");
#endif
		*perr = OS_ERR_SAFE_TOO_LARGE_SIZE;
		return ((void *)0);
	}
	if (size <= OS_SAFE_MEM_BLOCK_MAX) {
		blkSize = (size - OS_SAFE_MEM_BLOCK_MIN) % OS_SAFE_MEM_BLOCK_INERVAl == 0 ? (size - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl : (size - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1;
		for (; blkSize < (OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1; blkSize += 1) {
			if (OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree > 0) {/*�ӵ����ڴ�����ҵ��˺��ʵķֿ飬ֱ�ӷ���*/
				OS_ENTER_CRITICAL();
				pblk = OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList;
				blockSize = getBlkSize(pblk);
				OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree--;
				OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList = *(void **)((INT8U *)(OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList) + sizeof(OS_SAFE_MEM_BLOCK));
				OSSafeMem->OSSafeMemFreeSize -= blockSize;
				OSSafeMem->OSSafeMemTotalSize -= blockSize + sizeof(OS_SAFE_MEM_BLOCK);
				OS_EXIT_CRITICAL();
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				/*���������Ϣ
				sprintf(log_info,"OSSafeVarMemGet�У���%d���ڴ��ǩ��СΪ%d,ʣ���ڴ�����Ϊ%d���������ڴ�����ϢΪ��", blkSize, OSSafeMem->SafeMemParts[blkSize].OSafeMemPartBlkSize, OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree);
				recordLog("�ڴ�",log_info);
				pTempBlk = OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList;
				memlog(pTempBlk);
				if (pTempBlk == NULL) {
					recordLog("��һ��ָ���Ѿ��ǿ�ָ������");
				}
				else {
					pTempBlk = ((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk;
					memlog(pTempBlk);
				}*/
				/*���������Ϣ*/
				recordLog("�ڴ�","OSSafeVarMemGet��ȡ�����ڴ�����ϢΪ��");
				memlog(pblk);
				sprintf(log_info, "OSSafeVarMemGet�����󣬰�ȫ�ڴ���ʣ��Ŀɹ��������Ч�ռ�Ϊ%dB��", OSSafeMem->OSSafeMemFreeSize);
				recordLog("�ڴ�",log_info);
#endif

				((OS_SAFE_MEM_LIST_BLOCK*)((INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk=NULL;
				//((OS_SAFE_MEM_USED_BLOCK*)((INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK)))->prio = OSPrioCur;
				//recordLog("OSSafeVarMemGetȡ�����ڴ����д�����ȼ�֮���ڴ�����ϢΪ�� \n");
				//memlog(pblk);
#if OS_SAFE_MEM_MERGE_EN == 0
				OSSafeMem->SafeMemParts[blkSize].OSafeMemPartUsedCount++;                    /* ͳ����                                     */
				sprintf(log_info, "OSSafeVarMemGet�У������ڴ��ǩ��СΪ%d,ͳ�����Ϊ%d", OSSafeMem->SafeMemParts[blkSize].OSafeMemPartBlkSize, OSSafeMem->SafeMemParts[blkSize].OSafeMemPartUsedCount);
				recordLog("�ڴ�",log_info);
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
				pTempBlk = (INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK);/*ȡ�����ڴ���д洢�����ڴ���������ݽṹ�ĵ�ַ*/
				if (useSize == 0u) {
					OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList = ((OS_SAFE_MEM_LIST_BLOCK*)pTempBlk)->OSNextListMemBlk;
					if (((OS_SAFE_MEM_LIST_BLOCK*)pTempBlk)->OSNextListMemBlk != (void*)0) {
						pLeftBlk = (INT8U*)((OS_SAFE_MEM_LIST_BLOCK*)pTempBlk)->OSNextListMemBlk + sizeof(OS_SAFE_MEM_BLOCK);/*�������ڵ���һ��ָ��*/
						((OS_SAFE_MEM_LIST_BLOCK*)pLeftBlk)->OSLastListMemBlk = NULL;
					}
				}
				else {
					pLeftBlk = (INT8U*)((OS_SAFE_MEM_LIST_BLOCK*)pTempBlk)->OSLastListMemBlk + sizeof(OS_SAFE_MEM_BLOCK);/*�������ڵ���һ��ָ��*/
					((OS_SAFE_MEM_LIST_BLOCK*)pLeftBlk)->OSNextListMemBlk = ((OS_SAFE_MEM_LIST_BLOCK*)pTempBlk)->OSNextListMemBlk;
					if (((OS_SAFE_MEM_LIST_BLOCK*)pTempBlk)->OSNextListMemBlk != NULL) {
						pLeftBlk = (INT8U*)((OS_SAFE_MEM_LIST_BLOCK*)pTempBlk)->OSNextListMemBlk + sizeof(OS_SAFE_MEM_BLOCK);/*�������ڵ���һ��ָ��*/
						((OS_SAFE_MEM_LIST_BLOCK*)pLeftBlk)->OSLastListMemBlk = ((OS_SAFE_MEM_LIST_BLOCK*)pTempBlk)->OSLastListMemBlk;
					}
				}
				OS_EXIT_CRITICAL();
				leftSize = blockSize - size;

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				/*���������Ϣ*/
				sprintf(log_info, "OSSafeVarMemGet�У���%d���ڴ��ǩ��СΪ%d,ʣ���ڴ�����Ϊ%d�����������ڴ�����ϢΪ��", blkSize, OSSafeMem->SafeMemParts[blkSize].OSafeMemPartBlkSize, OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree);
				recordLog("�ڴ�",log_info);
				if (useSize == 0u) {
					pTempBlk = OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList;
					memlog(pTempBlk);
					if (pTempBlk == NULL) {
						recordLog("�ڴ�","��ָ��");
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

		/*�����ǲ���ڴ�����*/
		if (leftSize > OS_SAFE_MEM_BLOCK_MAX + sizeof(OS_SAFE_MEM_BLOCK)) {/*������֮���ʣ��ռ仹�����ٲ��뷭���ڴ����*/
			leftSize -= sizeof(OS_SAFE_MEM_BLOCK);
			useSize = OS_SAFE_MEM_BLOCK_MAX * 2;
			blkSize = (OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1;
			while (useSize < leftSize) {
				useSize *= 2;
				blkSize += 1;
			}
			if (blkSize >= OS_SAFE_MEM_BLOCK_COUNT) {/*��֮ǰ�Ĳ���ڴ��������ֻ�Ƕ�����һ��*/
				blkSize = OS_SAFE_MEM_BLOCK_COUNT-1;
			}
			pLeftBlk = (INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK) + size;/*��¼�ָ�����ڴ����׵�ַ*/
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
						/*���ָ��ʣ�µ��ڴ��pLeftBlk����pTempBlk֮ǰ*/
						if (useSize == 0u) {
							((OS_SAFE_MEM_LIST_BLOCK*)(pLeftBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = NULL;
							((OS_SAFE_MEM_LIST_BLOCK*)(pLeftBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk = pTempBlk;
							((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = pLeftBlk;
							OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList = pLeftBlk;
						}
						else {
							pLastBlk = ((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk;/*�������ڵ���һ��*/
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
			/*���������Ϣ*/
			sprintf(log_info,"OSSafeVarMemGet�У���%d���ڴ��ǩ��СΪ%d,ʣ���ڴ�����Ϊ%d���������һ���ڴ�����ϢΪ��", blkSize, OSSafeMem->SafeMemParts[blkSize].OSafeMemPartBlkSize, OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree);
			recordLog("�ڴ�",log_info);
			memlog(OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList);
			memlog(pTempBlk);
#endif

		}
		else if (leftSize > OS_SAFE_MEM_BLOCK_MIN + sizeof(OS_SAFE_MEM_BLOCK)) {
			while (leftSize >= OS_SAFE_MEM_BLOCK_MIN + sizeof(OS_SAFE_MEM_BLOCK)) {/*������֮���ʣ��ռ仹�������ٲ�������ڴ����*/
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
					((OS_SAFE_MEM_BLOCK *)pLeftBlk)->OSLastPhyMemBlk = (INT8U)pLeftBlk - (OS_SAFE_MEM_BLOCK_MIN + ((leftSize - sizeof(OS_SAFE_MEM_BLOCK) - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl)* OS_SAFE_MEM_BLOCK_INERVAl);/*����ָ���useSize��С���ڴ��֮��ʣ�µĿռ���Էָ�������ڴ���С*/
				}
				//((OS_SAFE_MEM_BLOCK *)pLeftBlk)->OSafeMemBlkSize = useSize;
				//((OS_SAFE_MEM_BLOCK *)pblk)->OSafeMemBlkSize -= sizeof(OS_SAFE_MEM_BLOCK) + useSize;
				pTempBlk = pLeftBlk + sizeof(OS_SAFE_MEM_BLOCK);
				OS_ENTER_CRITICAL();
				((OS_SAFE_MEM_LIST_BLOCK*)pTempBlk)->OSNextListMemBlk = OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList;/*ָ���»��ֳ����ڴ�������λ���е���һ���ڴ�飬���ڲ��뵽����ͷ����������һ��Ϊԭ��������ͷ�ڴ��*/
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
				/*���������Ϣ*/
				sprintf(log_info,"OSSafeVarMemGet�У���%d���ڴ��ǩ��СΪ%d,ʣ���ڴ�����Ϊ%d���������һ���ڴ�����ϢΪ��", blkSize,OSSafeMem->SafeMemParts[blkSize].OSafeMemPartBlkSize, OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree);
				recordLog("�ڴ�",log_info);
				memlog(OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList);
				memlog(pTempBlk);
#endif
				OS_EXIT_CRITICAL();
			}
		}
#if OS_SAFE_MEM_MERGE_EN == 0u
		blkSize = getBlkIndex(pblk);
		OSSafeMem->SafeMemParts[blkSize].OSafeMemPartUsedCount++;                    /* ͳ����                                     */
		sprintf(log_info, "OSSafeVarMemGet�У������ڴ��ǩ��СΪ%d,ͳ�����Ϊ%d", OSSafeMem->SafeMemParts[blkSize].OSafeMemPartBlkSize, OSSafeMem->SafeMemParts[blkSize].OSafeMemPartUsedCount);
		recordLog("�ڴ�",log_info);
#endif

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
		/*���������Ϣ*/
		recordLog("�ڴ�","OSSafeVarMemGet��ȡ�����ڴ�����ϢΪ��");
		memlog(pblk);
		sprintf(log_info, "OSSafeVarMemGet�����󣬰�ȫ�ڴ���ʣ��Ŀɹ��������Ч�ռ�Ϊ%dB��", OSSafeMem->OSSafeMemFreeSize);
		recordLog("�ڴ�",log_info);
#endif
		//assert();���Է�����ڴ����ʣ���ڴ���С��ӵ����ܵ��ڴ��С
		*perr = OS_ERR_NONE;                          /*      No error                                 */
		return (pblk);
	}
}

void  *OSSafeVarMemPend(INT8U  size, INT32U *timeout,INT8U   *perr)
{
	void      *pblk = OSSafeVarMemGet(size, perr);
	if (*perr == OS_ERR_SAFE_NO_SUIT_BLKS || *perr == OS_ERR_SAFE_TOO_LARGE_SIZE) {
		OS_ENTER_CRITICAL();
		/*˵��û�к��ʵ��ڴ�飬��Ҫ�ȴ�*/
		OSTCBCur->OSTCBDly = *timeout;
		/*����ǰ����Ӿ����������ɾ��*/
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
			/*�Ӱ�ȫ�ڴ�ĵȴ������б��ｫ����ɾ��*/
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
	size += sizeof(OS_SAFE_MEM_USED_BLOCK);//����ǰ�����ڱ������ȼ�����Ϣ�Ŀռ䣬�Ժ���ܻ�ɾ��
	pblk = OSSafeVarMemGet(size, perr);
	if (perr == OS_ERR_NONE) {
		((OS_SAFE_MEM_USED_BLOCK*)((INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK)))->prio = OSPrioCur;
		printf("OSSafeVarMemGetȡ�����ڴ����д�����ȼ�֮���ڴ�����ϢΪ�� ");
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
	INT32U      blkSize;  /*Ӧ�����ĸ��±��µ��ڴ����ȡ*/
	INT32U      useSize;
	INT32U      blockSize;/*�������֮ǰ�����ݽṹ���氲ȫ�ڴ���С*/
	INT32U      tmpBlockSize;/*�������֮ǰ�����ݽṹ���氲ȫ�ڴ���С*/
	/*����ʹһ������������״̬*/
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
	/*���������Ϣ*/
	recordLog("�ڴ�","OSSafeVarMemPut��׼��������ڴ�����ϢΪ�� ");
	memlog(pblk);
#endif
#if OS_SAFE_MEM_MERGE_EN > 0u
	pTempBlk = ((OS_SAFE_MEM_BLOCK*)pblk)->OSLastPhyMemBlk;/*�Ⱥϲ���ߵ������ڴ��*/
	while (pTempBlk != NULL) {
		pRightBlk = ((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk;
		pLeftBlk = ((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk;
		blkSize = getBlkIndex(pTempBlk);
		/*����ڴ��ǰ����ָ�뱣������ݣ������豣����������ڵ��ڴ�飬��С�������ǰ��Сһ�£�˵���ǿ��еģ���Ҫ��ʹ�ð�ȫ���������ڴ��ʱ��֤��һ����*/
		if (pLeftBlk == NULL && pRightBlk == NULL
			|| (pRightBlk == NULL && pLeftBlk != NULL && pLeftBlk >= (INT8U*)(OSSafeMem->OSSafeMemAddr) &&pLeftBlk < (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE) && getBlkIndex(pLeftBlk) == blkSize
			|| (pLeftBlk == NULL && pRightBlk != NULL && pRightBlk >= (INT8U*)(OSSafeMem->OSSafeMemAddr)  &&pRightBlk < (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE) && getBlkIndex(pRightBlk) == blkSize
			|| (pLeftBlk >= (INT8U*)(OSSafeMem->OSSafeMemAddr)  &&pLeftBlk < (INT8U*)(OSSafeMem->OSSafeMemAddr) + OS_SAFE_MEM_TOTAL_SIZE && pRightBlk >= (INT8U*)(OSSafeMem->OSSafeMemAddr)  &&pRightBlk < (INT8U*)(OSSafeMem->OSSafeMemAddr) + OS_SAFE_MEM_TOTAL_SIZE) && getBlkIndex(pLeftBlk) == blkSize && getBlkIndex(pRightBlk) == blkSize) {

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			recordLog("�ڴ�","OSSafeVarMemPut��׼���ϲ���ߵ��ڴ�飺");
			memlog(pTempBlk);
#endif
			if (blkSize <((OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1) && OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree <= OSSafeBlockNum[blkSize]) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				recordLog("�ڴ�","���еĸô�С���ڴ�鲻�ࣨС�ڵ����趨ֵ����ȡ���ϲ�");
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
				/*�����ڴ������*/
				if (pLeftBlk == NULL) {
					OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList = pRightBlk;
				}
				else {
					((OS_SAFE_MEM_LIST_BLOCK*)(pLeftBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk = pRightBlk;
				}
				if (pRightBlk != NULL) {
					((OS_SAFE_MEM_LIST_BLOCK*)(pRightBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = pLeftBlk;
				}
				/*���ĺϲ�����ڴ��ǰ���������ڿ�,�˴������治ͬ*/
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

	pTempBlk = ((OS_SAFE_MEM_BLOCK*)pblk)->OSNextPhyMemBlk;/*�ϲ��ұߵ������ڴ��*/
	while (pTempBlk != NULL) {
		pRightBlk = ((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk;
		pLeftBlk = ((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk;
		blkSize = getBlkIndex(pTempBlk);
		/*����ڴ��ǰ����ָ�뱣������ݣ������豣����������ڵ��ڴ�飬��С�������ǰ��Сһ�£�˵���ǿ��еģ���Ҫ��ʹ�ð�ȫ���������ڴ��ʱ��֤��һ����*/
		if (pLeftBlk == NULL && pRightBlk == NULL
			|| (pRightBlk == NULL && pLeftBlk != NULL && pLeftBlk >= (INT8U*)(OSSafeMem->OSSafeMemAddr) &&pLeftBlk < (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE) && getBlkIndex(pLeftBlk) == blkSize
			|| (pLeftBlk == NULL && pRightBlk != NULL && pRightBlk >= (INT8U*)(OSSafeMem->OSSafeMemAddr)  &&pRightBlk < (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE) && getBlkIndex(pRightBlk) == blkSize
			|| (pLeftBlk >= (INT8U*)(OSSafeMem->OSSafeMemAddr)  &&pLeftBlk < (INT8U*)(OSSafeMem->OSSafeMemAddr) + OS_SAFE_MEM_TOTAL_SIZE && pRightBlk >= (INT8U*)(OSSafeMem->OSSafeMemAddr)  &&pRightBlk < (INT8U*)(OSSafeMem->OSSafeMemAddr) + OS_SAFE_MEM_TOTAL_SIZE) && getBlkIndex(pLeftBlk) == blkSize && getBlkIndex(pRightBlk) == blkSize) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			recordLog("�ڴ�", "OSSafeVarMemPut��׼���ϲ��ұߵ��ڴ�飺");
			memlog(pTempBlk);
#endif
			if (blkSize < ((OS_SAFE_MEM_BLOCK_MAX - OS_SAFE_MEM_BLOCK_MIN) / OS_SAFE_MEM_BLOCK_INERVAl + 1) && OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartNFree <= OSSafeBlockNum[blkSize]) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				recordLog("�ڴ�", "���еĸô�С���ڴ�鲻�ࣨС�ڵ����趨ֵ����ȡ���ϲ�");
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
				/*�����ڴ������*/
				if (pLeftBlk == NULL) {
					OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList = pRightBlk;
				}
				else {
					((OS_SAFE_MEM_LIST_BLOCK*)(pLeftBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk = pRightBlk;
				}
				if (pRightBlk != NULL) {
					((OS_SAFE_MEM_LIST_BLOCK*)(pRightBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = pLeftBlk;
				}
				/*���ĺϲ�����ڴ��ǰ���������ڿ�,�˴������治ͬ*/
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
	if (blockSize > OS_SAFE_MEM_BLOCK_MAX) {/*�ϲ�֮���ʣ��ռ���Բ��뷭���ڴ����*/
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
	/*ȷ���˲����±�֮��,���ϲ���������ڴ��pblk����pTempBlk֮ǰ*/
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
				/*���ϲ���������ڴ��pblk����pTempBlk֮ǰ*/
				if (useSize == 0u) {
					((OS_SAFE_MEM_LIST_BLOCK*)((INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = NULL;
					((OS_SAFE_MEM_LIST_BLOCK*)((INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk = pTempBlk;
					((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk = pblk;
					OSSafeMem->SafeMemParts[blkSize].OSSafeMemPartFreeList = pblk;
				}
				else {
					pLeftBlk = ((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSLastListMemBlk;/*�������ڵ���һ��*/
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
	/*���������Ϣ*/
	recordLog("�ڴ�", "OSSafeVarMemPut�����ղ�����ڴ�����ϢΪ�� ");
	memlog(pblk);
#endif

	if (OSSafeMemGrp) {/*˵�����������ڵȴ����䰲ȫ���ڴ�*/
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
		if (OSSafeVarSizes[prio] <= blockSize) {/*����֮����ڴ��С��������ȴ������������ȼ�������*/
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
			/*ͳ�Ƹ��ִ�С�İ�ȫ�ڴ�����ʹ�ô���*/
			p_safe_mem_data->Parts[i].PartUsedCount = OSSafeMem->SafeMemParts[i].OSafeMemPartUsedCount;                    /* ͳ����                                     */
#endif
		}
		p_safe_mem_data->TotalSize = OSSafeMem->OSSafeMemTotalSize;
		p_safe_mem_data->FreeSize = OSSafeMem->OSSafeMemFreeSize;
		p_safe_mem_data->PartCount = OSSafeMem->OSSafeMemPartMaxIndex + 1;
		OS_EXIT_CRITICAL(); 
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
		OSSafeMemLog();/*�����ȫ��������ϸ��Ϣ*/
#endif
		return (OS_ERR_NONE);
}
/*$PAGE*/

/*$PAGE*/
/*
*********************************************************************************************************
*                                          QUERY SAFE MEMORY PARTITION
*
* Description : �ڴ����.
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
			sprintf(log_info,"��ʼ��ַΪ0X%X���ڴ��û���ڴ�й©����ϲ��", pTempBlk);
			recordLog("�ڴ�",log_info);
#endif
			return;
		}
		else if (pTempBlk < (INT8U*)OSSafeMem->OSSafeMemAddr) {
			OS_EXIT_CRITICAL();
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info,"\n0X%X�ڴ���չ�����ָ��ָ����������⣡", pTempBlk);
			recordLog("�ڴ�",log_info);
#endif
			return;
		}
		/*OS_ENTER_CRITICAL();�������֮��test.c�е���ʱ��������Ч�ˣ�Ϊɶ�أ�*/
		pRightBlk = ((OS_SAFE_MEM_LIST_BLOCK*)(pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->OSNextListMemBlk;
		if (pRightBlk!=NULL && (pRightBlk < (INT8U*)OSSafeMem->OSSafeMemAddr || pRightBlk >(INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE)) {/*Ӧ��˵�������ڴ��Ѿ���������*/
			prio = ((OS_SAFE_MEM_USED_BLOCK*)((INT8U*)pTempBlk + sizeof(OS_SAFE_MEM_BLOCK)))->prio;
			if(prio>0) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				/*���������Ϣ*/
				sprintf(log_info,"��ǰִ����������ȼ�Ϊ%d,���ڴ��ھ���״̬������Ϊ:", OSPrioCur);
				recordLog("�ڴ�",log_info);
				log_info[0] = '\0';
				for (i = 0; i < OS_LOWEST_PRIO; i++) {
					if (OSRdyTbl[i])
						sprintf(log_info,"%s%d ��", log_info,i);
				}
				recordLog("�ڴ�",log_info);
#endif
				if (OSRdyTbl[prio]) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
					sprintf(log_info,"��ʼ��ַΪ0X%X���ڴ���Ǳ����ȼ�Ϊ%d����������ģ���Ȼ���ھ���״̬���޷����գ�Ҳ�п����Ǻ�����������ͬ���ȼ�������ͨ��������ƿ��¼�Ĵ���ʱ�����ԱȰɣ�����", pTempBlk, prio);
					recordLog("�ڴ�",log_info);
#endif
				}
				else {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
					sprintf(log_info,"��ʼ��ַΪ0X%X���ڴ���Ǳ����ȼ�Ϊ%d����������ģ������ھ���״̬�����Ի��ա�", pTempBlk, prio);
					recordLog("�ڴ�",log_info);
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
		recordLog("�ڴ�", "δ�ɹ����䰲ȫ�������ڴ档");
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

