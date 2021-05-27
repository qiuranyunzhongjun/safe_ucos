#include "includes.h"
#include <time.h>
#include <assert.h>

#define MainTask_Prio 5
#define App1Task_Prio 7
#define App2Task_Prio 9
#define MainTask_StkSize 1024
#define App1Task_StkSize 1024
#define App2Task_StkSize 1024
/* 定义堆栈*/
OS_STK MainTask_Stk[MainTask_StkSize];
OS_STK App1Task_Stk[App1Task_StkSize];
OS_STK App2Task_Stk[App2Task_StkSize];
OS_STK RecycleTask_Stk[1024];

/* 测试自己的函数 */
void RecycleSafeMemTask()
{
	OS_SAFE_MEM_DATA *psmf = malloc(sizeof(OS_SAFE_MEM_DATA));
	INT32U i;
	while (1)
	{
		OSSafeVarMemRecycle();
		OSSafeVarMemQuery(psmf);
		printf("\n在RecycleSafeMemTask函数中，回收之后安全数据区的首地址为：0X%X，总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:\n", psmf->SafeMemAddr, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
		for (i = 0; i < psmf->PartCount; i++) {
			printf("%d :标签大小为%d的内存块剩余%d块；\n", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		}
		printf("在RecycleSafeMemTask函数中开始等待\n");
		OSTimeDlyHMSM(0, 1, 0, 0); /* 任务调度*/
		printf("在RecycleSafeMemTask函数中结束等待\n");
	}
}
void testMemTask(void *name)
{
	INT8U err;
	INT32U i;
	OSSafeVarMemInit(&err);
	OS_SAFE_MEM_DATA *psmf = malloc(sizeof(OS_SAFE_MEM_DATA));
	void *pblk;
	printf("在testMyTask函数中，OSSafeVarMemInit函数错误代码为: %d\n", err);
	if (err == 0) {/*创建用于回收内存的任务*/
		OSTaskCreate(RecycleSafeMemTask, (void *)0, &RecycleTask_Stk[1023], 6);
		printf("创建优先级为%d的内存回收任务。\n", 6);
	}
	OSSafeVarMemQuery(psmf);
	printf("在testMyTask函数中，安全数据区的首地址为：0X%X，总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:\n", psmf->SafeMemAddr, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	for (i = 0; i < psmf->PartCount ; i++) {
		printf("%d :标签大小为%d的内存块剩余%d块；\n", i+1,psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
	}


	pblk = OSSafeVarMemGet(48, &err);
	OSSafeVarMemQuery( psmf);
	printf("\n申请1个8B的空间之后，函数返回错误代码为%d，总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:\n", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	for (i = 0; i < psmf->PartCount; i++) {
		printf("%d :标签大小为%d的内存块剩余%d块；\n", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
	}
	//*(void **)((INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK)) = 1;/*使用该内存块，主要是为了合并时可以通过判定这个数值决定是不是在内存控制表中*/
	pblk = OSSafeVarMemGet( 8, &err);
	OSSafeVarMemQuery(psmf);
	printf("\n申请2个8B的空间之后，函数返回错误代码为%d，总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:\n", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	for (i = 0; i < psmf->PartCount; i++) {
		printf("%d :标签大小为%d的内存块剩余%d块；\n", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
	}

	err = OSSafeVarMemPut( pblk);
	OSSafeVarMemQuery(psmf);
	printf("\n回收刚刚申请的空间之后，函数返回错误代码为%d，总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:\n", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	for (i = 0; i < psmf->PartCount; i++) {
		printf("%d :标签大小为%d的内存块剩余%d块；\n", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
	}

	printf("当前执行任务的优先级为%d,现在处于就绪状态的任务为:\n",OSPrioCur);
	for (i = 0; i < OS_LOWEST_PRIO; i++) {
		if(OSRdyTbl[i])
			printf("%d ；", i );
	}
	printf("\n");
	printf("准备挂起优先级为%d的主任务；\n", MainTask_Prio);
	printf("挂起任务的返回值为%d\n", OSTaskSuspend(MainTask_Prio));
	printf("成功挂起优先级为%d的主任务；\n", MainTask_Prio);
	/*OSSafeVarMemRecycle(psm);
	OSSafeVarMemQuery(psm, psmf);
	printf("\n在RecycleSafeMemTask函数中，回收之后安全数据区的首地址为：0X%X，总大小为：%dB，总有效大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:\n", psmf->SafeMemAddr, psmf->AllSize, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	for (i = 0; i < psmf->PartCount; i++) {
		printf("%d :标签大小为%d的内存块剩余%d块；\n", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
	}*/
	printf("准备删除优先级为%d的主任务；\n", MainTask_Prio);
	OSTaskDel(MainTask_Prio);
}

/*一个数值修复函数，针对变量赋值违背规则时的处理函数*/
OS_SAFE_VAR_DATA revise(OS_SAFE_VAR_DATA old_data, OS_SAFE_VAR_DATA new_data) {
	if (new_data.int_value > 10)
		new_data.int_value = 2;
	else if (new_data.int_value < 0)
		new_data.int_value = 0;
	else new_data.int_value = old_data.int_value;
	return new_data;
}

void testVarTask(void *name)
{
	INT8U err;
	INT32U i,blkcnt=0;
	OS_SAFE_VAR  *temp,*var_temp;
	OS_SAFE_VAR_DATA var_value;
	//OSSafeVarMemInit(&err);
	OS_SAFE_MEM_DATA *psmf = malloc(sizeof(OS_SAFE_MEM_DATA));
	void *pblk;

	//printf("在testVarTask函数中，OSSafeVarMemInit函数错误代码为: %d\n", err);
	//OSSafeVarMemQuery(psmf);
	//sprintf(log_info,"在testVarTask函数中，安全数据区的首地址为：0X%X，总大小为：%dB，总有效大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", psmf->SafeMemAddr, psmf->AllSize, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	//recordLog("任务",log_info);
	//for (i = 0; i < psmf->PartCount; i++) {
		//sprintf(log_info,"%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		//recordLog("任务",log_info);
	//}

	err = OSSafeVarCreate("var_temp", "int",0);
	OSSafeVarMemQuery(psmf);
	sprintf(log_info,"声明安全变量之后，函数返回错误代码为%d，总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info,"%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}
	
	for (i = 0; i < 64; i++) {
		if (OSSafeVars[i] != (OS_SAFE_VAR *)0) {
			sprintf(log_info,"优先级为%d的任务创建了安全变量：", i);
			recordLog("任务",log_info);
			for (temp = OSSafeVars[i]; temp != (OS_SAFE_VAR *)0; temp = temp->next) {
				var_temp = (OS_SAFE_VAR *)((INT8U*)temp+sizeof(OS_SAFE_MEM_BLOCK));
				sprintf(log_info,"安全变量名字为：%s,类型编码为%d", var_temp->name, var_temp->OSSafeVarType);
				recordLog("任务",log_info);
			}
		}
	}
	err = OSSafeArrayCreate("arr_temp", "int",10);
	OSSafeVarMemQuery(psmf);
	sprintf(log_info,"声明安全变量数组之后，函数返回错误代码为%d，总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err,psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info); 
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info,"%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}

	for (i = 0; i < 64; i++) {
		if (OSSafeVars[i] != (OS_SAFE_VAR *)0) {
			sprintf(log_info,"优先级为%d的任务创建了安全变量数组：", i);
			recordLog("任务",log_info);
			for (temp = OSSafeVars[i]; temp != (OS_SAFE_VAR *)0; temp = temp->next) {
				var_temp = (OS_SAFE_VAR *)((INT8U*)temp + sizeof(OS_SAFE_MEM_BLOCK));
				sprintf(log_info,"安全变量名字为：%s,类型编码为%d", var_temp->name, var_temp->OSSafeVarType);
				recordLog("任务",log_info);
			}
		}
	}
	err = OSSafeRuleInsert("var_temp + arr_temp[3] <= ln10");
	printf("testVarTask插入规则的返回值为%d\n", err);
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "插入规则之后，函数返回错误代码为%d，总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}

	err = OSSafeArraySet("arr_temp", 3, 1);
	printf("给安全数组赋值的返回值为%d\n", err);

	OSSafeArrayGet("arr_temp", 3, &err);
	printf("安全数组取值的的错误值为%d\n", err);
	printf("安全数组取值的返回值为%d\n", OSSafeArrayGet("arr_temp", 3, &err)->int_value);

	var_value.int_value = 10;
	err = OSSafeArrayNoCheckSet("arr_temp", 3, 2);
	printf("给安全数组赋值的返回值为%d\n", err);

	OSSafeArrayGet("arr_temp", 3, &err);
	printf("安全数组取值的的错误值为%d\n", err);
	printf("安全数组取值的返回值为%d\n", OSSafeArrayGet("arr_temp", 3, &err)->int_value);

	err = OSSafeVarCheck("arr_temp");
	printf("安全数组检查的返回值为%d\n", err);

	err = OSSafeVarDelete("arr_temp");
	printf("删除安全变量的返回值为%d\n", err);
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "删除安全变量之后，函数返回错误代码为%d，总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info); 
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}

	//err = OSSafeVarClear(OSPrioCur);
	//printf("清除安全变量的返回值为%d\n", err);
	//OSSafeVarMemQuery(psmf);
	//sprintf(log_info,"清除安全变量之后，函数返回错误代码为%d，总大小为：%dB，总有效大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err, psmf->AllSize, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	//recordLog("任务",log_info); 
	//for (i = 0; i < psmf->PartCount; i++) {
		//sprintf(log_info,"%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		//recordLog("任务",log_info);
	//}

	//OSTaskDel(OS_PRIO_SELF);

	recordLog("任务","testVarTask任务即将等待几秒");
	OSTimeDlyHMSM(0, 0, 1, 0);
	recordLog("任务","testVarTask任务等待结束，即将重新运行");

	OSSafeVarMemQuery(psmf);
	sprintf(log_info,"函数即将返回的时候，查询安全内存情况的函数返回错误代码为%d，总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info);

#if OS_SAFE_MEM_MERGE_EN == 0u
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块，共计申请%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree, psmf->Parts[i].PartUsedCount);
		blkcnt += psmf->Parts[i].PartNFree;
		recordLog("任务",log_info);
	}
#else
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		blkcnt += psmf->Parts[i].PartNFree;
		recordLog("任务",log_info);
	}
#endif
	sprintf(log_info, "安全内存总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d个内存块可供分配，每块内存块额外占用%d字节的数据:", psmf->TotalSize, psmf->FreeSize, blkcnt,sizeof(OS_SAFE_MEM_BLOCK));
	recordLog("任务",log_info);
	assert(psmf->TotalSize == psmf->FreeSize + blkcnt * sizeof(OS_SAFE_MEM_BLOCK));
	printf("testVarTask 函数执行结束\n");
}

void testTasksMem1(void *name)
{
	INT8U err;
	INT32U i;
	void *pblk;
	OS_SAFE_MEM_DATA *psmf = malloc(sizeof(OS_SAFE_MEM_DATA));
	//sprintf(log_info, "\n testTasksMem1: %d\n", OSTime);
	//recordLog("任务",log_info);

	//OSTaskDel(MainTask_Prio);
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "在testTasksMem1函数中，申请250字节的安全内存之前，总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}

	pblk = OSSafeVarMemPend(250, 10, &err);/*1s中100个时钟周期*/

	//sprintf(log_info, "\n testTasksMem1: %d\n", OSTime);
	//recordLog("任务",log_info);
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "在testTasksMem1函数中，申请250字节的安全内存之后，函数返回错误代码为%d，总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err,  psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}


	printf("testTasksMem1 函数执行结束\n");
}

void testTasksMem2(void *name)
{
	INT8U err;
	INT32U i;
	void *pblk;
	OS_SAFE_MEM_DATA *psmf = malloc(sizeof(OS_SAFE_MEM_DATA));

	//OSSafeVarMemInit(&err); 
	//printf("在testTasksMem2函数中，OSSafeVarMemInit函数错误代码为: %d\n", err);

	pblk = OSSafeVarMemGet(200, &err);
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "在testTasksMem2函数中，申请200字节的安全内存之后，函数返回错误代码为%d，总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}

	OSTaskCreate(testTasksMem1, (void *)0, &App1Task_Stk[App1Task_StkSize - 1], App1Task_Prio);
	OS_Sched();

	//sprintf(log_info, "\n testTasksMem2: %d\n", OSTime);
	//recordLog("任务",log_info);
	OSTimeDlyHMSM(0, 0, 0, 50);
	//sprintf(log_info, "\n testTasksMem2: %d\n", OSTime);
	//recordLog("任务",log_info);
	err = OSSafeVarMemPut(pblk);
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "在testTasksMem2函数中，回收刚刚申请的空间之后，函数返回错误代码为%d，总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err,psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}

	printf("testTasksMem2 函数执行结束\n");
}

void testVarTask1(void *name)
{
	INT8U err;
	INT32U i;
	OS_SAFE_VAR  *temp, *var_temp;
	OS_SAFE_VAR_DATA var_value;
	//OSSafeVarMemInit(&err);
	OS_SAFE_MEM_DATA *psmf = malloc(sizeof(OS_SAFE_MEM_DATA));
	void *pblk;

	err = OSSafeVarCreate("var_temp", "long");
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "testVarTask1声明安全变量之后，函数返回错误代码为%d，总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}

	for (i = 0; i < 64; i++) {
		if (OSSafeVars[i] != (OS_SAFE_VAR *)0) {
			sprintf(log_info, "优先级为%d的任务创建了安全变量：", i);
			recordLog("任务",log_info);
			for (temp = OSSafeVars[i]; temp != (OS_SAFE_VAR *)0; temp = temp->next) {
				var_temp = (OS_SAFE_VAR *)((INT8U*)temp + sizeof(OS_SAFE_MEM_BLOCK));
				sprintf(log_info, "安全变量名字为：%s,类型编码为%d", var_temp->name, var_temp->OSSafeVarType);
				recordLog("任务",log_info);
			}
		}
	}

	err = OSSafeRuleInsert("var_temp + @5 var_temp <= 5");
	printf("testVarTask1插入规则的返回值为%d\n", err);
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "插入规则之后，函数返回错误代码为%d，总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}

	int int_value = 6;
	err = OSSafeVarSet("var_temp", &int_value);
	printf("给安全变量赋值的返回值为%d\n", err);

	printf("testVarTask1 函数执行结束\n");
}

/*模拟进风口程序*/
void WindTask(void *name)
{
	INT8U err;
	INT32U i;
	OS_SAFE_VAR_DATA var_value;
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OS_SAFE_MEM_DATA *psmf = malloc(sizeof(OS_SAFE_MEM_DATA));
#endif

	err = OSSafeVarCreate("safe_rate", "int",4);
	printf("任务%d:模拟进风口程序WindTask声明安全变量(用于设定风机的转速)之后，函数返回错误代码为%d。\n", OSPrioCur, err);

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "模拟进风口程序WindTask声明安全变量之后，函数返回错误代码为%d，此时安全数据区总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err,  psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}
#endif

	printf("任务%d:模拟进风口程序WindTask声明安全变量之后，等待1秒钟。\n", OSPrioCur);
	OSTimeDlyHMSM(0, 0, 1, 0);

	err = OSSafeRuleInsert("safe_rate >= @5 safe_rates[2]");
	printf("任务%d:模拟进风口程序WindTask插入规则1（用于关联转速的下界）的返回值为%d\n", OSPrioCur, err);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "模拟进风口程序WindTask插入规则之后，函数返回错误代码为%d，此时安全数据区总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}
#endif
	err = OSSafeRuleInsert("safe_rate <= @5 safe_rates[3]");
	printf("任务%d:模拟进风口程序WindTask插入规则2（用于关联转速的上界）的返回值为%d\n", OSPrioCur, err);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "模拟进风口程序WindTask插入规则之后，函数返回错误代码为%d，此时安全数据区总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}
#endif

	printf("任务%d:模拟进风口程序WindTask插入规则之后，等待2秒钟。\n", OSPrioCur);
	OSTimeDlyHMSM(0, 0, 2, 0);
	err = OSSafeVarSet("safe_rate", 5);
	printf("任务%d:模拟进风口程序WindTask给安全变量赋值（更改风机转速）的返回值为%d\n", OSPrioCur, err);
	if (err != OS_ERR_NONE) {
		printf("任务%d:模拟进风口程序WindTask给安全变量赋值违反了规则，启动应急处理程序。\n", OSPrioCur);
	}

	printf("任务%d:模拟进风口程序WindTask等待2秒钟。\n", OSPrioCur);
	OSTimeDlyHMSM(0, 0, 2, 0);

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "模拟进风口程序WindTask准备结束之前，函数返回错误代码为%d，此时安全数据区总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}
#endif

	printf("任务%d:模拟进风口程序WindTask即将执行结束\n", OSPrioCur);
}

/*模拟加热程序*/
void FireTask(void *name)
{
	INT8U err;
	INT32U i;
	OS_SAFE_VAR_DATA var_value;
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OS_SAFE_MEM_DATA *psmf = malloc(sizeof(OS_SAFE_MEM_DATA));
#endif

	err = OSSafeVarCreate("safe_rate", "int",1);
	//printf("模拟加热程序FireTask变量值：%d\n", OSSafeVarGet("safe_rate", &err)->int_value);
	printf("任务%d:模拟加热程序FireTask声明安全变量(用于设定加热炉功率)之后，函数返回错误代码为%d。\n", OSPrioCur, err);

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "模拟加热程序FireTask声明安全变量之后，函数返回错误代码为%d，此时安全数据区总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}
#endif

	printf("任务%d:模拟加热程序FireTask声明安全变量之后，等待1秒钟。\n", OSPrioCur);
	OSTimeDlyHMSM(0, 0, 1, 0);

	err = OSSafeRuleInsert("safe_rate >= @5 safe_rates[0]");
	printf("任务%d:模拟加热程序FireTask插入规则1（用于关联功率的下界）的返回值为%d\n", OSPrioCur, err);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "模拟加热程序FireTask插入规则之后，函数返回错误代码为%d，此时安全数据区总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}
#endif
	err = OSSafeRuleInsert("safe_rate <= @5 safe_rates[1]");
	printf("任务%d:模拟加热程序FireTask插入规则2（用于关联功率的上界）的返回值为%d\n", OSPrioCur, err);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "模拟加热程序FireTask插入规则之后，函数返回错误代码为%d，此时安全数据区总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}
#endif

	printf("任务%d:模拟加热程序FireTask插入规则之后，模拟运行2秒钟。\n", OSPrioCur);
	OSTimeDlyHMSM(0, 0, 2, 0);
	err = OSSafeVarSet("safe_rate", 20);
	printf("任务%d:模拟加热程序FireTask给安全变量赋值（更改加热炉功率）的返回值为%d\n", OSPrioCur, err);
	if (err != OS_ERR_NONE) {
		printf("任务%d:模拟加热程序FireTask给安全变量赋值违反了规则，启动应急处理程序。\n", OSPrioCur);
	}

	printf("任务%d:模拟加热程序FireTask等待2秒。\n", OSPrioCur);
	OSTimeDlyHMSM(0, 0, 2, 0);

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "模拟加热程序FireTask准备结束之前，函数返回错误代码为%d，此时安全数据区总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}
#endif

	printf("任务%d:模拟加热程序FireTask即将执行结束\n", OSPrioCur);
}

/*模拟保温腔主程序*/
void WarmMainTask(void *name)
{
	INT8U err;
	INT32U i;
	OS_SAFE_VAR_DATA var_value;
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OS_SAFE_MEM_DATA *psmf = malloc(sizeof(OS_SAFE_MEM_DATA));
#endif

	err = OSSafeArrayCreate("safe_rates", "int",4);
	printf("任务%d:模拟主程序WarmMainTask声明安全数组(用于设定功率和转速的上下界)之后，函数返回错误代码为%d。\n", OSPrioCur,err);

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "模拟主程序WarmMainTask声明安全数组之后，函数返回错误代码为%d，此时安全数据区总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}
#endif

	printf("任务%d:模拟主程序WarmMainTask声明安全数组(用于设定功率和转速的上下界)之后，等待1秒钟。\n", OSPrioCur);
	OSTimeDlyHMSM(0, 0, 1, 0);

	for (i = 0; i < 4; i++) {
		var_value.int_value = 2*i;
		err = OSSafeArrayNoCheckSet("safe_rates", i ,var_value);
		printf("任务%d:模拟保温主程序WarmMainTask为安全数组第%d个元素赋值（无视规则）的返回值为%d\n", OSPrioCur, i,err);
	}

	printf("任务%d:模拟保温主程序WarmMainTask为安全数组赋值之后，等待5秒钟。\n", OSPrioCur);
	OSTimeDlyHMSM(0, 0, 5, 0);

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "模拟保温主程序WarmMainTask准备结束之前，函数返回错误代码为%d，此时安全数据区总大小为：%dB，剩余可供分配的有效空间为：%dB，共有%d种内存块可供分配,分别是:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("任务",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :标签大小为%d的内存块剩余%d块；", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("任务",log_info);
	}
#endif
	printf("任务%d:模拟保温主程序WarmMainTask即将执行结束\n", OSPrioCur);
}


int main_1(void)
{
	OSInit(); /* 系统初始化*/
			  /* 创建主任务*/

	//OSTaskCreate(testMemTask, (void *)0, &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);

	//OSTaskCreate(testVarTask, (void *)0, &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	//OSTaskCreate(testTasksMem1, (void *)0, &App1Task_Stk[App1Task_StkSize - 1], App1Task_Prio);
	//OSTaskCreate(testTasksMem2, (void *)0, &App2Task_Stk[App2Task_StkSize - 1], App2Task_Prio);

	//OSTaskCreateExt(testVarTask, (void *)0, &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio, MainTask_Prio, &MainTask_Stk[0], MainTask_StkSize, (void *)0, OS_TASK_OPT_STK_CHK);
	
	//OSTaskCreate(testVarTask1, (void *)0, &App1Task_Stk[App1Task_StkSize - 1], App1Task_Prio);
	//OSTaskCreate(testVarTask, (void *)0, &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);

	OSTaskCreate(WindTask, "模拟进风口程序", &App2Task_Stk[App2Task_StkSize - 1], App2Task_Prio);
	OSTaskCreate(FireTask, "模拟加热程序", &App1Task_Stk[App1Task_StkSize - 1], App1Task_Prio);
	OSTaskCreate(WarmMainTask, "模拟保温主程序", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);

	OSStart(); /* 开始任务调度*/

	return 0;
}
