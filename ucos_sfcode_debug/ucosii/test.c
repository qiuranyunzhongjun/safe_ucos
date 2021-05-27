#include "includes.h"
#include <time.h>
#include <assert.h>

#define MainTask_Prio 5
#define App1Task_Prio 7
#define App2Task_Prio 9
#define MainTask_StkSize 1024
#define App1Task_StkSize 1024
#define App2Task_StkSize 1024
/* �����ջ*/
OS_STK MainTask_Stk[MainTask_StkSize];
OS_STK App1Task_Stk[App1Task_StkSize];
OS_STK App2Task_Stk[App2Task_StkSize];
OS_STK RecycleTask_Stk[1024];

/* �����Լ��ĺ��� */
void RecycleSafeMemTask()
{
	OS_SAFE_MEM_DATA *psmf = malloc(sizeof(OS_SAFE_MEM_DATA));
	INT32U i;
	while (1)
	{
		OSSafeVarMemRecycle();
		OSSafeVarMemQuery(psmf);
		printf("\n��RecycleSafeMemTask�����У�����֮��ȫ���������׵�ַΪ��0X%X���ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:\n", psmf->SafeMemAddr, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
		for (i = 0; i < psmf->PartCount; i++) {
			printf("%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻\n", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		}
		printf("��RecycleSafeMemTask�����п�ʼ�ȴ�\n");
		OSTimeDlyHMSM(0, 1, 0, 0); /* �������*/
		printf("��RecycleSafeMemTask�����н����ȴ�\n");
	}
}
void testMemTask(void *name)
{
	INT8U err;
	INT32U i;
	OSSafeVarMemInit(&err);
	OS_SAFE_MEM_DATA *psmf = malloc(sizeof(OS_SAFE_MEM_DATA));
	void *pblk;
	printf("��testMyTask�����У�OSSafeVarMemInit�����������Ϊ: %d\n", err);
	if (err == 0) {/*�������ڻ����ڴ������*/
		OSTaskCreate(RecycleSafeMemTask, (void *)0, &RecycleTask_Stk[1023], 6);
		printf("�������ȼ�Ϊ%d���ڴ��������\n", 6);
	}
	OSSafeVarMemQuery(psmf);
	printf("��testMyTask�����У���ȫ���������׵�ַΪ��0X%X���ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:\n", psmf->SafeMemAddr, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	for (i = 0; i < psmf->PartCount ; i++) {
		printf("%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻\n", i+1,psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
	}


	pblk = OSSafeVarMemGet(48, &err);
	OSSafeVarMemQuery( psmf);
	printf("\n����1��8B�Ŀռ�֮�󣬺������ش������Ϊ%d���ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:\n", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	for (i = 0; i < psmf->PartCount; i++) {
		printf("%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻\n", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
	}
	//*(void **)((INT8U*)pblk + sizeof(OS_SAFE_MEM_BLOCK)) = 1;/*ʹ�ø��ڴ�飬��Ҫ��Ϊ�˺ϲ�ʱ����ͨ���ж������ֵ�����ǲ������ڴ���Ʊ���*/
	pblk = OSSafeVarMemGet( 8, &err);
	OSSafeVarMemQuery(psmf);
	printf("\n����2��8B�Ŀռ�֮�󣬺������ش������Ϊ%d���ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:\n", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	for (i = 0; i < psmf->PartCount; i++) {
		printf("%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻\n", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
	}

	err = OSSafeVarMemPut( pblk);
	OSSafeVarMemQuery(psmf);
	printf("\n���ոո�����Ŀռ�֮�󣬺������ش������Ϊ%d���ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:\n", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	for (i = 0; i < psmf->PartCount; i++) {
		printf("%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻\n", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
	}

	printf("��ǰִ����������ȼ�Ϊ%d,���ڴ��ھ���״̬������Ϊ:\n",OSPrioCur);
	for (i = 0; i < OS_LOWEST_PRIO; i++) {
		if(OSRdyTbl[i])
			printf("%d ��", i );
	}
	printf("\n");
	printf("׼���������ȼ�Ϊ%d��������\n", MainTask_Prio);
	printf("��������ķ���ֵΪ%d\n", OSTaskSuspend(MainTask_Prio));
	printf("�ɹ��������ȼ�Ϊ%d��������\n", MainTask_Prio);
	/*OSSafeVarMemRecycle(psm);
	OSSafeVarMemQuery(psm, psmf);
	printf("\n��RecycleSafeMemTask�����У�����֮��ȫ���������׵�ַΪ��0X%X���ܴ�СΪ��%dB������Ч��СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:\n", psmf->SafeMemAddr, psmf->AllSize, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	for (i = 0; i < psmf->PartCount; i++) {
		printf("%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻\n", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
	}*/
	printf("׼��ɾ�����ȼ�Ϊ%d��������\n", MainTask_Prio);
	OSTaskDel(MainTask_Prio);
}

/*һ����ֵ�޸���������Ա�����ֵΥ������ʱ�Ĵ�����*/
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

	//printf("��testVarTask�����У�OSSafeVarMemInit�����������Ϊ: %d\n", err);
	//OSSafeVarMemQuery(psmf);
	//sprintf(log_info,"��testVarTask�����У���ȫ���������׵�ַΪ��0X%X���ܴ�СΪ��%dB������Ч��СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", psmf->SafeMemAddr, psmf->AllSize, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	//recordLog("����",log_info);
	//for (i = 0; i < psmf->PartCount; i++) {
		//sprintf(log_info,"%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		//recordLog("����",log_info);
	//}

	err = OSSafeVarCreate("var_temp", "int",0);
	OSSafeVarMemQuery(psmf);
	sprintf(log_info,"������ȫ����֮�󣬺������ش������Ϊ%d���ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info,"%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}
	
	for (i = 0; i < 64; i++) {
		if (OSSafeVars[i] != (OS_SAFE_VAR *)0) {
			sprintf(log_info,"���ȼ�Ϊ%d�����񴴽��˰�ȫ������", i);
			recordLog("����",log_info);
			for (temp = OSSafeVars[i]; temp != (OS_SAFE_VAR *)0; temp = temp->next) {
				var_temp = (OS_SAFE_VAR *)((INT8U*)temp+sizeof(OS_SAFE_MEM_BLOCK));
				sprintf(log_info,"��ȫ��������Ϊ��%s,���ͱ���Ϊ%d", var_temp->name, var_temp->OSSafeVarType);
				recordLog("����",log_info);
			}
		}
	}
	err = OSSafeArrayCreate("arr_temp", "int",10);
	OSSafeVarMemQuery(psmf);
	sprintf(log_info,"������ȫ��������֮�󣬺������ش������Ϊ%d���ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err,psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info); 
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info,"%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}

	for (i = 0; i < 64; i++) {
		if (OSSafeVars[i] != (OS_SAFE_VAR *)0) {
			sprintf(log_info,"���ȼ�Ϊ%d�����񴴽��˰�ȫ�������飺", i);
			recordLog("����",log_info);
			for (temp = OSSafeVars[i]; temp != (OS_SAFE_VAR *)0; temp = temp->next) {
				var_temp = (OS_SAFE_VAR *)((INT8U*)temp + sizeof(OS_SAFE_MEM_BLOCK));
				sprintf(log_info,"��ȫ��������Ϊ��%s,���ͱ���Ϊ%d", var_temp->name, var_temp->OSSafeVarType);
				recordLog("����",log_info);
			}
		}
	}
	err = OSSafeRuleInsert("var_temp + arr_temp[3] <= ln10");
	printf("testVarTask�������ķ���ֵΪ%d\n", err);
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "�������֮�󣬺������ش������Ϊ%d���ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}

	err = OSSafeArraySet("arr_temp", 3, 1);
	printf("����ȫ���鸳ֵ�ķ���ֵΪ%d\n", err);

	OSSafeArrayGet("arr_temp", 3, &err);
	printf("��ȫ����ȡֵ�ĵĴ���ֵΪ%d\n", err);
	printf("��ȫ����ȡֵ�ķ���ֵΪ%d\n", OSSafeArrayGet("arr_temp", 3, &err)->int_value);

	var_value.int_value = 10;
	err = OSSafeArrayNoCheckSet("arr_temp", 3, 2);
	printf("����ȫ���鸳ֵ�ķ���ֵΪ%d\n", err);

	OSSafeArrayGet("arr_temp", 3, &err);
	printf("��ȫ����ȡֵ�ĵĴ���ֵΪ%d\n", err);
	printf("��ȫ����ȡֵ�ķ���ֵΪ%d\n", OSSafeArrayGet("arr_temp", 3, &err)->int_value);

	err = OSSafeVarCheck("arr_temp");
	printf("��ȫ������ķ���ֵΪ%d\n", err);

	err = OSSafeVarDelete("arr_temp");
	printf("ɾ����ȫ�����ķ���ֵΪ%d\n", err);
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "ɾ����ȫ����֮�󣬺������ش������Ϊ%d���ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info); 
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}

	//err = OSSafeVarClear(OSPrioCur);
	//printf("�����ȫ�����ķ���ֵΪ%d\n", err);
	//OSSafeVarMemQuery(psmf);
	//sprintf(log_info,"�����ȫ����֮�󣬺������ش������Ϊ%d���ܴ�СΪ��%dB������Ч��СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err, psmf->AllSize, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	//recordLog("����",log_info); 
	//for (i = 0; i < psmf->PartCount; i++) {
		//sprintf(log_info,"%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		//recordLog("����",log_info);
	//}

	//OSTaskDel(OS_PRIO_SELF);

	recordLog("����","testVarTask���񼴽��ȴ�����");
	OSTimeDlyHMSM(0, 0, 1, 0);
	recordLog("����","testVarTask����ȴ�������������������");

	OSSafeVarMemQuery(psmf);
	sprintf(log_info,"�����������ص�ʱ�򣬲�ѯ��ȫ�ڴ�����ĺ������ش������Ϊ%d���ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info);

#if OS_SAFE_MEM_MERGE_EN == 0u
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飬��������%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree, psmf->Parts[i].PartUsedCount);
		blkcnt += psmf->Parts[i].PartNFree;
		recordLog("����",log_info);
	}
#else
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		blkcnt += psmf->Parts[i].PartNFree;
		recordLog("����",log_info);
	}
#endif
	sprintf(log_info, "��ȫ�ڴ��ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ����䣬ÿ���ڴ�����ռ��%d�ֽڵ�����:", psmf->TotalSize, psmf->FreeSize, blkcnt,sizeof(OS_SAFE_MEM_BLOCK));
	recordLog("����",log_info);
	assert(psmf->TotalSize == psmf->FreeSize + blkcnt * sizeof(OS_SAFE_MEM_BLOCK));
	printf("testVarTask ����ִ�н���\n");
}

void testTasksMem1(void *name)
{
	INT8U err;
	INT32U i;
	void *pblk;
	OS_SAFE_MEM_DATA *psmf = malloc(sizeof(OS_SAFE_MEM_DATA));
	//sprintf(log_info, "\n testTasksMem1: %d\n", OSTime);
	//recordLog("����",log_info);

	//OSTaskDel(MainTask_Prio);
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "��testTasksMem1�����У�����250�ֽڵİ�ȫ�ڴ�֮ǰ���ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}

	pblk = OSSafeVarMemPend(250, 10, &err);/*1s��100��ʱ������*/

	//sprintf(log_info, "\n testTasksMem1: %d\n", OSTime);
	//recordLog("����",log_info);
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "��testTasksMem1�����У�����250�ֽڵİ�ȫ�ڴ�֮�󣬺������ش������Ϊ%d���ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err,  psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}


	printf("testTasksMem1 ����ִ�н���\n");
}

void testTasksMem2(void *name)
{
	INT8U err;
	INT32U i;
	void *pblk;
	OS_SAFE_MEM_DATA *psmf = malloc(sizeof(OS_SAFE_MEM_DATA));

	//OSSafeVarMemInit(&err); 
	//printf("��testTasksMem2�����У�OSSafeVarMemInit�����������Ϊ: %d\n", err);

	pblk = OSSafeVarMemGet(200, &err);
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "��testTasksMem2�����У�����200�ֽڵİ�ȫ�ڴ�֮�󣬺������ش������Ϊ%d���ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}

	OSTaskCreate(testTasksMem1, (void *)0, &App1Task_Stk[App1Task_StkSize - 1], App1Task_Prio);
	OS_Sched();

	//sprintf(log_info, "\n testTasksMem2: %d\n", OSTime);
	//recordLog("����",log_info);
	OSTimeDlyHMSM(0, 0, 0, 50);
	//sprintf(log_info, "\n testTasksMem2: %d\n", OSTime);
	//recordLog("����",log_info);
	err = OSSafeVarMemPut(pblk);
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "��testTasksMem2�����У����ոո�����Ŀռ�֮�󣬺������ش������Ϊ%d���ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err,psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}

	printf("testTasksMem2 ����ִ�н���\n");
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
	sprintf(log_info, "testVarTask1������ȫ����֮�󣬺������ش������Ϊ%d���ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}

	for (i = 0; i < 64; i++) {
		if (OSSafeVars[i] != (OS_SAFE_VAR *)0) {
			sprintf(log_info, "���ȼ�Ϊ%d�����񴴽��˰�ȫ������", i);
			recordLog("����",log_info);
			for (temp = OSSafeVars[i]; temp != (OS_SAFE_VAR *)0; temp = temp->next) {
				var_temp = (OS_SAFE_VAR *)((INT8U*)temp + sizeof(OS_SAFE_MEM_BLOCK));
				sprintf(log_info, "��ȫ��������Ϊ��%s,���ͱ���Ϊ%d", var_temp->name, var_temp->OSSafeVarType);
				recordLog("����",log_info);
			}
		}
	}

	err = OSSafeRuleInsert("var_temp + @5 var_temp <= 5");
	printf("testVarTask1�������ķ���ֵΪ%d\n", err);
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "�������֮�󣬺������ش������Ϊ%d���ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}

	int int_value = 6;
	err = OSSafeVarSet("var_temp", &int_value);
	printf("����ȫ������ֵ�ķ���ֵΪ%d\n", err);

	printf("testVarTask1 ����ִ�н���\n");
}

/*ģ�����ڳ���*/
void WindTask(void *name)
{
	INT8U err;
	INT32U i;
	OS_SAFE_VAR_DATA var_value;
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OS_SAFE_MEM_DATA *psmf = malloc(sizeof(OS_SAFE_MEM_DATA));
#endif

	err = OSSafeVarCreate("safe_rate", "int",4);
	printf("����%d:ģ�����ڳ���WindTask������ȫ����(�����趨�����ת��)֮�󣬺������ش������Ϊ%d��\n", OSPrioCur, err);

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "ģ�����ڳ���WindTask������ȫ����֮�󣬺������ش������Ϊ%d����ʱ��ȫ�������ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err,  psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}
#endif

	printf("����%d:ģ�����ڳ���WindTask������ȫ����֮�󣬵ȴ�1���ӡ�\n", OSPrioCur);
	OSTimeDlyHMSM(0, 0, 1, 0);

	err = OSSafeRuleInsert("safe_rate >= @5 safe_rates[2]");
	printf("����%d:ģ�����ڳ���WindTask�������1�����ڹ���ת�ٵ��½磩�ķ���ֵΪ%d\n", OSPrioCur, err);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "ģ�����ڳ���WindTask�������֮�󣬺������ش������Ϊ%d����ʱ��ȫ�������ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}
#endif
	err = OSSafeRuleInsert("safe_rate <= @5 safe_rates[3]");
	printf("����%d:ģ�����ڳ���WindTask�������2�����ڹ���ת�ٵ��Ͻ磩�ķ���ֵΪ%d\n", OSPrioCur, err);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "ģ�����ڳ���WindTask�������֮�󣬺������ش������Ϊ%d����ʱ��ȫ�������ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}
#endif

	printf("����%d:ģ�����ڳ���WindTask�������֮�󣬵ȴ�2���ӡ�\n", OSPrioCur);
	OSTimeDlyHMSM(0, 0, 2, 0);
	err = OSSafeVarSet("safe_rate", 5);
	printf("����%d:ģ�����ڳ���WindTask����ȫ������ֵ�����ķ��ת�٣��ķ���ֵΪ%d\n", OSPrioCur, err);
	if (err != OS_ERR_NONE) {
		printf("����%d:ģ�����ڳ���WindTask����ȫ������ֵΥ���˹�������Ӧ���������\n", OSPrioCur);
	}

	printf("����%d:ģ�����ڳ���WindTask�ȴ�2���ӡ�\n", OSPrioCur);
	OSTimeDlyHMSM(0, 0, 2, 0);

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "ģ�����ڳ���WindTask׼������֮ǰ���������ش������Ϊ%d����ʱ��ȫ�������ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}
#endif

	printf("����%d:ģ�����ڳ���WindTask����ִ�н���\n", OSPrioCur);
}

/*ģ����ȳ���*/
void FireTask(void *name)
{
	INT8U err;
	INT32U i;
	OS_SAFE_VAR_DATA var_value;
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OS_SAFE_MEM_DATA *psmf = malloc(sizeof(OS_SAFE_MEM_DATA));
#endif

	err = OSSafeVarCreate("safe_rate", "int",1);
	//printf("ģ����ȳ���FireTask����ֵ��%d\n", OSSafeVarGet("safe_rate", &err)->int_value);
	printf("����%d:ģ����ȳ���FireTask������ȫ����(�����趨����¯����)֮�󣬺������ش������Ϊ%d��\n", OSPrioCur, err);

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "ģ����ȳ���FireTask������ȫ����֮�󣬺������ش������Ϊ%d����ʱ��ȫ�������ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}
#endif

	printf("����%d:ģ����ȳ���FireTask������ȫ����֮�󣬵ȴ�1���ӡ�\n", OSPrioCur);
	OSTimeDlyHMSM(0, 0, 1, 0);

	err = OSSafeRuleInsert("safe_rate >= @5 safe_rates[0]");
	printf("����%d:ģ����ȳ���FireTask�������1�����ڹ������ʵ��½磩�ķ���ֵΪ%d\n", OSPrioCur, err);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "ģ����ȳ���FireTask�������֮�󣬺������ش������Ϊ%d����ʱ��ȫ�������ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}
#endif
	err = OSSafeRuleInsert("safe_rate <= @5 safe_rates[1]");
	printf("����%d:ģ����ȳ���FireTask�������2�����ڹ������ʵ��Ͻ磩�ķ���ֵΪ%d\n", OSPrioCur, err);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "ģ����ȳ���FireTask�������֮�󣬺������ش������Ϊ%d����ʱ��ȫ�������ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}
#endif

	printf("����%d:ģ����ȳ���FireTask�������֮��ģ������2���ӡ�\n", OSPrioCur);
	OSTimeDlyHMSM(0, 0, 2, 0);
	err = OSSafeVarSet("safe_rate", 20);
	printf("����%d:ģ����ȳ���FireTask����ȫ������ֵ�����ļ���¯���ʣ��ķ���ֵΪ%d\n", OSPrioCur, err);
	if (err != OS_ERR_NONE) {
		printf("����%d:ģ����ȳ���FireTask����ȫ������ֵΥ���˹�������Ӧ���������\n", OSPrioCur);
	}

	printf("����%d:ģ����ȳ���FireTask�ȴ�2�롣\n", OSPrioCur);
	OSTimeDlyHMSM(0, 0, 2, 0);

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "ģ����ȳ���FireTask׼������֮ǰ���������ش������Ϊ%d����ʱ��ȫ�������ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}
#endif

	printf("����%d:ģ����ȳ���FireTask����ִ�н���\n", OSPrioCur);
}

/*ģ�Ᵽ��ǻ������*/
void WarmMainTask(void *name)
{
	INT8U err;
	INT32U i;
	OS_SAFE_VAR_DATA var_value;
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OS_SAFE_MEM_DATA *psmf = malloc(sizeof(OS_SAFE_MEM_DATA));
#endif

	err = OSSafeArrayCreate("safe_rates", "int",4);
	printf("����%d:ģ��������WarmMainTask������ȫ����(�����趨���ʺ�ת�ٵ����½�)֮�󣬺������ش������Ϊ%d��\n", OSPrioCur,err);

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "ģ��������WarmMainTask������ȫ����֮�󣬺������ش������Ϊ%d����ʱ��ȫ�������ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}
#endif

	printf("����%d:ģ��������WarmMainTask������ȫ����(�����趨���ʺ�ת�ٵ����½�)֮�󣬵ȴ�1���ӡ�\n", OSPrioCur);
	OSTimeDlyHMSM(0, 0, 1, 0);

	for (i = 0; i < 4; i++) {
		var_value.int_value = 2*i;
		err = OSSafeArrayNoCheckSet("safe_rates", i ,var_value);
		printf("����%d:ģ�Ᵽ��������WarmMainTaskΪ��ȫ�����%d��Ԫ�ظ�ֵ�����ӹ��򣩵ķ���ֵΪ%d\n", OSPrioCur, i,err);
	}

	printf("����%d:ģ�Ᵽ��������WarmMainTaskΪ��ȫ���鸳ֵ֮�󣬵ȴ�5���ӡ�\n", OSPrioCur);
	OSTimeDlyHMSM(0, 0, 5, 0);

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	OSSafeVarMemQuery(psmf);
	sprintf(log_info, "ģ�Ᵽ��������WarmMainTask׼������֮ǰ���������ش������Ϊ%d����ʱ��ȫ�������ܴ�СΪ��%dB��ʣ��ɹ��������Ч�ռ�Ϊ��%dB������%d���ڴ��ɹ�����,�ֱ���:", err, psmf->TotalSize, psmf->FreeSize, psmf->PartCount);
	recordLog("����",log_info);
	for (i = 0; i < psmf->PartCount; i++) {
		sprintf(log_info, "%d :��ǩ��СΪ%d���ڴ��ʣ��%d�飻", i + 1, psmf->Parts[i].PartBlkSize, psmf->Parts[i].PartNFree);
		recordLog("����",log_info);
	}
#endif
	printf("����%d:ģ�Ᵽ��������WarmMainTask����ִ�н���\n", OSPrioCur);
}


int main_1(void)
{
	OSInit(); /* ϵͳ��ʼ��*/
			  /* ����������*/

	//OSTaskCreate(testMemTask, (void *)0, &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);

	//OSTaskCreate(testVarTask, (void *)0, &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	//OSTaskCreate(testTasksMem1, (void *)0, &App1Task_Stk[App1Task_StkSize - 1], App1Task_Prio);
	//OSTaskCreate(testTasksMem2, (void *)0, &App2Task_Stk[App2Task_StkSize - 1], App2Task_Prio);

	//OSTaskCreateExt(testVarTask, (void *)0, &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio, MainTask_Prio, &MainTask_Stk[0], MainTask_StkSize, (void *)0, OS_TASK_OPT_STK_CHK);
	
	//OSTaskCreate(testVarTask1, (void *)0, &App1Task_Stk[App1Task_StkSize - 1], App1Task_Prio);
	//OSTaskCreate(testVarTask, (void *)0, &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);

	OSTaskCreate(WindTask, "ģ�����ڳ���", &App2Task_Stk[App2Task_StkSize - 1], App2Task_Prio);
	OSTaskCreate(FireTask, "ģ����ȳ���", &App1Task_Stk[App1Task_StkSize - 1], App1Task_Prio);
	OSTaskCreate(WarmMainTask, "ģ�Ᵽ��������", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);

	OSStart(); /* ��ʼ�������*/

	return 0;
}
