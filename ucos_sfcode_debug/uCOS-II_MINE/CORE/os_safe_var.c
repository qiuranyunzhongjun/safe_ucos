
/*
*********************************************************************************************************
*                                                uC/OS-II
*                                          The Real-Time Kernel
*                                            RULE MANAGEMENT
*
*                              (c) Copyright 2020-2025, Micrium, Weston, FL
*                                           All Rights Reserved
*
* File    : OS_SAFE_RULE.C
* By      : ������
* Version : V1.0
*
* LICENSING TERMS:
* ---------------
*  ���ڲ�����ȫ�����ĺ���
*********************************************************************************************************
*/

#ifndef  OS_MASTER_FILE
#include <ucos_ii.h>
#endif

#define NDEBUG
#include <assert.h>

#if (OS_SAFE_MEM_EN > 0u)
/*enum operations  {short=1,int, long, float,double,char}֧�ֵİ�ȫ�������������ͱ��룬�Լ���Ӧ���������ͣ������10*/
/*
*********************************************************************************************************
*                                        CREATE A SAFE VARIABLE
*
* Description : �޵ȴ��ش�����ȫ����,֧�ֻ�������
*
* Arguments   : name     Ҫ���ɵİ�ȫ���������֣�֮��Ҳֻ��ͨ��������ֽ��в�����ȫ����
				type     Ҫ���ɵİ�ȫ�����������ַ���
						 ��ȫ������ʼֵ
* Returns    : ���ش�����Ϣ
*********************************************************************************************************
*/

INT8U  OSSafeVarCreate(char * name , char * type, ...)
{
	INT32U  size = sizeof(OS_SAFE_VAR),i; 
	INT8U err,var_type;
	INT8U *pblk;
	OS_SAFE_VAR *safevar;
	va_list arg_ptr;
	va_start(arg_ptr, type);  //�Թ̶������ĵ�ַΪ���ȷ����ε��ڴ���ʼ��ַ�� 

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* ��������Ч�� */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_NAME;
	}
	if (type == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_TYPE\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_TYPE;
	}
#endif
	if (strcmp(type, "short") == 0) {
		size += sizeof(short);
		var_type  = 1;
	}
	else if (strcmp(type, "int") == 0) {
		size += sizeof(int);
		var_type = 2;
	}
	else if (strcmp(type, "long") == 0) {
		size += sizeof(long);
		var_type = 3;
	}
	else if (strcmp(type, "float") == 0) {
		size += sizeof(float);
		var_type = 4;
	}
	else if (strcmp(type, "double") == 0) {
		size += sizeof(double);
		var_type = 5;
	}
	else if (strcmp(type, "char") == 0) {
		size += sizeof(char);
		var_type = 6;
	}
	else {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_TYPE\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_TYPE;
	}
	/*�������ȼ����������Ƿ��Ѿ����������İ�ȫ����*/
	for (safevar = OSSafeVars[OSPrioCur]; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
		if (strcmp(((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name, name) == 0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_VAR_NAME_EXIST\n");
#endif
			return OS_ERR_SAFE_VAR_NAME_EXIST;
		}
	}
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	sprintf(log_info, "Ϊ��ȫ�������밲ȫ�ڴ棬��ȫ������Ϊ�� %s", name);
	recordLog("����", log_info);
#endif
	pblk = OSSafeVarMemGet(size, &err);/*Ϊ��ȫ�������밲ȫ�ڴ�*/
	if (err != OS_ERR_NONE) {
		return err;
	}
	pblk += sizeof(OS_SAFE_MEM_BLOCK);/**/
	/*�洢��ȫ����������*/
	for (i = 0; name[i] != '\0'; i++) {
		if (i > 31) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_VAR_NAME_LONG\n");
#endif
			return OS_ERR_SAFE_VAR_NAME_LONG;
		}
		((OS_SAFE_VAR*)pblk)->name[i] = name[i];
	}
	((OS_SAFE_VAR*)pblk)->name[i] = '\0';
	((OS_SAFE_VAR*)pblk)->OSSafeVarType = var_type;
	((OS_SAFE_VAR*)pblk)->OSRuleList = (OS_SAFE_RULE*)0;
	((OS_SAFE_VAR*)pblk)->next = OSSafeVars[OSPrioCur];
	((OS_SAFE_VAR*)pblk)->OSEventGrp = 0;
	for (i = 0;i< OS_EVENT_TBL_SIZE;i++) {
		((OS_SAFE_VAR*)pblk)->OSEventTbl[i] = 0;
	}
	OSSafeVars[OSPrioCur] = pblk- sizeof(OS_SAFE_MEM_BLOCK);
	/*Ϊ��ȫ��������ֵ*/
	pblk += sizeof(OS_SAFE_VAR);
	switch (var_type) {
	case 1:
		*((short*)pblk) = va_arg(arg_ptr, short);
		break;
	case 2:
		*((int*)pblk) = va_arg(arg_ptr, int);
		break;
	case 3:
		*((long*)pblk) = va_arg(arg_ptr, long);
		break;
	case 4:
		*((float*)pblk) = va_arg(arg_ptr, float);
		break;
	case 5:
		*((double*)pblk) = va_arg(arg_ptr, double);
		break;
	case 6:
		*((char*)pblk) = va_arg(arg_ptr, char);
		break;
	}
	va_end(arg_ptr);

	assert(0);

	return OS_ERR_NONE;
}

INT8U  OSSafeVarCreateWait(char * name, char * type, INT16U timeout, ...)
{
	INT32U  size = sizeof(OS_SAFE_VAR), i;
	INT8U err, var_type;
	INT8U *pblk;
	OS_SAFE_VAR *safevar;
	va_list arg_ptr;
	va_start(arg_ptr, timeout);  //�Թ̶������ĵ�ַΪ���ȷ����ε��ڴ���ʼ��ַ�� 

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* ��������Ч�� */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_NAME;
	}
	if (type == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_TYPE\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_TYPE;
	}
#endif
	if (strcmp(type, "short") == 0) {
		size += sizeof(short);
		var_type = 1;
	}
	else if (strcmp(type, "int") == 0) {
		size += sizeof(int);
		var_type = 2;
	}
	else if (strcmp(type, "long") == 0) {
		size += sizeof(long);
		var_type = 3;
	}
	else if (strcmp(type, "float") == 0) {
		size += sizeof(float);
		var_type = 4;
	}
	else if (strcmp(type, "double") == 0) {
		size += sizeof(double);
		var_type = 5;
	}
	else if (strcmp(type, "char") == 0) {
		size += sizeof(char);
		var_type = 6;
	}
	else {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_TYPE\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_TYPE;
	}
	/*�������ȼ����������Ƿ��Ѿ����������İ�ȫ����*/
	for (safevar = OSSafeVars[OSPrioCur]; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
		if (strcmp(((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name, name) == 0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_VAR_NAME_EXIST\n");
#endif
			return OS_ERR_SAFE_VAR_NAME_EXIST;
		}
	}
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	sprintf(log_info, "Ϊ��ȫ�������밲ȫ�ڴ棬��ȫ������Ϊ�� %s", name);
	recordLog("����", log_info);
#endif
	pblk = OSSafeVarMemPend(size, &timeout, &err);/*Ϊ��ȫ�������밲ȫ�ڴ�*/
	if (err != OS_ERR_NONE) {
		return err;
	}
	pblk += sizeof(OS_SAFE_MEM_BLOCK);/**/
	/*�洢��ȫ����������*/
	for (i = 0; name[i] != '\0'; i++) {
		if (i > 31) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_VAR_NAME_LONG\n");
#endif
			return OS_ERR_SAFE_VAR_NAME_LONG;
		}
		((OS_SAFE_VAR*)pblk)->name[i] = name[i];
	}
	((OS_SAFE_VAR*)pblk)->name[i] = '\0';
	((OS_SAFE_VAR*)pblk)->OSSafeVarType = var_type;
	((OS_SAFE_VAR*)pblk)->OSRuleList = (OS_SAFE_RULE*)0;
	((OS_SAFE_VAR*)pblk)->next = OSSafeVars[OSPrioCur]; 
	((OS_SAFE_VAR*)pblk)->OSEventGrp = 0;
	for (i = 0; i < OS_EVENT_TBL_SIZE; i++) {
		((OS_SAFE_VAR*)pblk)->OSEventTbl[i] = 0;
	}
	OSSafeVars[OSPrioCur] = pblk - sizeof(OS_SAFE_MEM_BLOCK);
	/*Ϊ��ȫ��������ֵ0*/
	pblk += sizeof(OS_SAFE_VAR);
	switch (var_type) {
	case 1:
		*((short*)pblk) = va_arg(arg_ptr, short);
		break;
	case 2:
		*((int*)pblk) = va_arg(arg_ptr, int);
		break;
	case 3:
		*((long*)pblk) = va_arg(arg_ptr, long);
		break;
	case 4:
		*((float*)pblk) = va_arg(arg_ptr, float);
		break;
	case 5:
		*((double*)pblk) = va_arg(arg_ptr, double);
		break;
	case 6:
		*((char*)pblk) = va_arg(arg_ptr, char);
		break;
	}
	va_end(arg_ptr);
	return OS_ERR_NONE;
}

/*
*********************************************************************************************************
*                                        CREATE A SAFE ARRAY
*
* Description : �޵ȴ��ش�����ȫ����,֧�ֻ����������������
*
* Arguments   : name     Ҫ���ɵİ�ȫ���������֣�֮��Ҳֻ��ͨ��������ֽ��в�����ȫ����
				type     Ҫ���ɵİ�ȫ�����������ַ���
				int      Ҫ���ɵ������С
* Returns    : ���ش�����Ϣ
*********************************************************************************************************
*/
INT8U  OSSafeArrayCreate(char * name, char * type, int num)
{
	INT32U  size = sizeof(OS_SAFE_VAR), i;
	INT8U err, var_type;
	INT8U *pblk;
	OS_SAFE_VAR *safevar;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* ��������Ч�� */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_NAME;
	}
	if (type == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_TYPE\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_TYPE;
	}
	if (num <= 0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_ARR_INVALID_NUM\n");
#endif
		return OS_ERR_SAFE_ARR_INVALID_NUM;
	}
#endif
	if (strcmp(type, "short") == 0) {
		size += sizeof(short) * num;
		var_type = 11;
	}
	else if (strcmp(type, "int") == 0) {
		size += sizeof(int) * num;
		var_type = 12;
	}
	else if (strcmp(type, "long") == 0) {
		size += sizeof(long) * num;
		var_type = 13;
	}
	else if (strcmp(type, "float") == 0) {
		size += sizeof(float) * num;
		var_type = 14;
	}
	else if (strcmp(type, "double") == 0) {
		size += sizeof(double) * num;
		var_type = 15;
	}
	else if (strcmp(type, "char") == 0) {
		size += sizeof(char) * num;
		var_type = 16;
	}
	else {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_TYPE\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_TYPE;
	}
	/*�������ȼ����������Ƿ��Ѿ����������İ�ȫ����*/
	for (safevar = OSSafeVars[OSPrioCur]; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
		if (strcmp(((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name, name) == 0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_VAR_NAME_EXIST\n");
#endif
			return OS_ERR_SAFE_VAR_NAME_EXIST;
		}
	}
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	sprintf(log_info, "Ϊ��ȫ����������밲ȫ�ڴ棬��ȫ���������Ϊ�� %s", name);
	recordLog("����", log_info);
#endif
	pblk = OSSafeVarMemGet(size, &err);/*Ϊ��ȫ����������밲ȫ�ڴ�*/
	if (err != OS_ERR_NONE) {
		return err;
	}
	pblk += sizeof(OS_SAFE_MEM_BLOCK);/**/
	/*�洢��ȫ����������*/
	for (i = 0; name[i] != '\0'; i++) {
		if (i > 31) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_VAR_NAME_LONG\n");
#endif
			return OS_ERR_SAFE_VAR_NAME_LONG;
		}
		((OS_SAFE_VAR*)pblk)->name[i] = name[i];
	}
	((OS_SAFE_VAR*)pblk)->name[i] = '\0';
	((OS_SAFE_VAR*)pblk)->OSSafeVarType = var_type;
	((OS_SAFE_VAR*)pblk)->OSRuleList = (OS_SAFE_RULE*)0;
	((OS_SAFE_VAR*)pblk)->next = OSSafeVars[OSPrioCur];
	((OS_SAFE_VAR*)pblk)->OSEventGrp = 0;
	for (i = 0; i < OS_EVENT_TBL_SIZE; i++) {
		((OS_SAFE_VAR*)pblk)->OSEventTbl[i] = 0;
	}
	OSSafeVars[OSPrioCur] = pblk - sizeof(OS_SAFE_MEM_BLOCK);
	/*Ϊ��ȫ��������ֵ0*/
	pblk += sizeof(OS_SAFE_VAR);
	switch (var_type) {
	case 11:
		for (i = 0; i < num; i++) {
			*((short*)pblk) = 0;
			pblk += sizeof(short);
		}
		break;
	case 12:
		for (i = 0; i < num; i++) {
			*((int*)pblk) = 0;
			pblk += sizeof(int);
		}
		break;
	case 13:
		for (i = 0; i < num; i++) {
			*((long*)pblk) = 0;
			pblk += sizeof(long);
		}
		break;
	case 14:
		for (i = 0; i < num; i++) {
			*((float*)pblk) = 0;
			pblk += sizeof(float);
		}
		break;
	case 15:
		for (i = 0; i < num; i++) {
			*((double*)pblk) = 0;
			pblk += sizeof(double);
		}
		break;
	case 16:
		for (i = 0; i < num; i++) {
			*((char*)pblk) = '\0';
			pblk += sizeof(char);
		}
		break;
	}
	return OS_ERR_NONE;
}

INT8U  OSSafeArrayCreateWait(char * name, char * type, int num, INT16U timeout)
{
	INT32U  size = sizeof(OS_SAFE_VAR), i;
	INT8U err, var_type;
	INT8U *pblk;
	OS_SAFE_VAR *safevar;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* ��������Ч�� */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_NAME;
	}
	if (type == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_TYPE\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_TYPE;
	}
	if (num <= 0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_ARR_INVALID_NUM\n");
#endif
		return OS_ERR_SAFE_ARR_INVALID_NUM;
	}
#endif
	if (strcmp(type, "short") == 0) {
		size += sizeof(short) * num;
		var_type = 11;
	}
	else if (strcmp(type, "int") == 0) {
		size += sizeof(int) * num;
		var_type = 12;
	}
	else if (strcmp(type, "long") == 0) {
		size += sizeof(long) * num;
		var_type = 13;
	}
	else if (strcmp(type, "float") == 0) {
		size += sizeof(float) * num;
		var_type = 14;
	}
	else if (strcmp(type, "double") == 0) {
		size += sizeof(double) * num;
		var_type = 15;
	}
	else if (strcmp(type, "char") == 0) {
		size += sizeof(char) * num;
		var_type = 16;
	}
	else {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_TYPE\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_TYPE;
	}
	/*�������ȼ����������Ƿ��Ѿ����������İ�ȫ����*/
	for (safevar = OSSafeVars[OSPrioCur]; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
		if (strcmp(((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name, name) == 0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_VAR_NAME_EXISTE\n");
#endif
			return OS_ERR_SAFE_VAR_NAME_EXIST;
		}
	}
	pblk = OSSafeVarMemPend(size, &timeout, &err);/*Ϊ��ȫ����������밲ȫ�ڴ�*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	sprintf(log_info, "Ϊ��ȫ����������밲ȫ�ڴ棬��ȫ���������Ϊ�� %s", name);
	recordLog("����", log_info);
#endif
	if (err != OS_ERR_NONE) {
		return err;
	}
	pblk += sizeof(OS_SAFE_MEM_BLOCK);/**/
	/*�洢��ȫ����������*/
	for (i = 0; name[i] != '\0'; i++) {
		if (i > 31) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_VAR_NAME_LONG\n");
#endif
			return OS_ERR_SAFE_VAR_NAME_LONG;
		}
		((OS_SAFE_VAR*)pblk)->name[i] = name[i];
	}
	((OS_SAFE_VAR*)pblk)->name[i] = '\0';
	((OS_SAFE_VAR*)pblk)->OSSafeVarType = var_type;
	((OS_SAFE_VAR*)pblk)->OSRuleList = (OS_SAFE_RULE*)0;
	((OS_SAFE_VAR*)pblk)->next = OSSafeVars[OSPrioCur];
	((OS_SAFE_VAR*)pblk)->OSEventGrp = 0;
	for (i = 0; i < OS_EVENT_TBL_SIZE; i++) {
		((OS_SAFE_VAR*)pblk)->OSEventTbl[i] = 0;
	}
	OSSafeVars[OSPrioCur] = pblk - sizeof(OS_SAFE_MEM_BLOCK);
	/*Ϊ��ȫ��������ֵ0*/
	pblk += sizeof(OS_SAFE_VAR);
	switch (var_type) {
	case 11:
		for (i = 0; i < num; i++) {
			*((short*)pblk) = 0;
			pblk += sizeof(short);
		}
		break;
	case 12:
		for (i = 0; i < num; i++) {
			*((int*)pblk) = 0;
			pblk += sizeof(int);
		}
		break;
	case 13:
		for (i = 0; i < num; i++) {
			*((long*)pblk) = 0;
			pblk += sizeof(long);
		}
		break;
	case 14:
		for (i = 0; i < num; i++) {
			*((float*)pblk) = 0;
			pblk += sizeof(float);
		}
		break;
	case 15:
		for (i = 0; i < num; i++) {
			*((double*)pblk) = 0;
			pblk += sizeof(double);
		}
		break;
	case 16:
		for (i = 0; i < num; i++) {
			*((char*)pblk) = 0;
			pblk += sizeof(char);
		}
		break;
	}
	return OS_ERR_NONE;
}


INT8U  OSSafeVarSet(char * name, ...)
{
	OS_SAFE_VAR *safevar;
	OS_SAFE_VAR_DATA value,last_value;
	OS_SAFE_RULE *saferule;
	INT8U err = OS_ERR_NONE;
	INT32U lockCount;
	va_list arg_ptr;
	/*�����ҵ�������������ȼ�����ı���*/
	OS_TCB   *ptcb;
	INT8U     y;
	INT8U     x;
	INT8U     prio;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* ��������Ч�� */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_NAME;
	}
#endif
	/*���Ұ�ȫ������ַ*/
	for (safevar = OSSafeVars[OSPrioCur]; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
		if (strcmp(((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name, name) == 0) {
			break;
		}
	}
	if (safevar == (OS_SAFE_VAR *)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_NOT_EXIST\n");
#endif
		return OS_ERR_SAFE_VAR_NOT_EXIST;
	}
	safevar = (OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK));
	saferule = safevar->OSRuleList;
	/*���ñ����Ƿ���Ҫ����*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//����ǰ6λ
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if ((safevar->OSSafeVarType & 33554432) == 0) {/*˵����27λ��0��δ����*/
		safevar->OSSafeVarType |= 33554432;
		OS_EXIT_CRITICAL();
	}
	else {
		/*����ǰ����Ӿ����������ɾ��*/
		if ((OSRdyTbl[OSTCBCur->OSTCBY] &= ~OSTCBCur->OSTCBBitX) == 0) {
			OSRdyGrp &= ~OSTCBCur->OSTCBBitY;
		}
		safevar->OSEventTbl[OSTCBCur->OSTCBY] |= OSTCBCur->OSTCBBitX;
		safevar->OSEventGrp |= OSTCBCur->OSTCBBitY;
		OS_EXIT_CRITICAL();
		OS_Sched();
	}
	/*--���ñ����Ƿ���Ҫ����--*/

	va_start(arg_ptr, name);  //�Թ̶������ĵ�ַΪ���ȷ����ε��ڴ���ʼ��ַ�� 
	switch (safevar->OSSafeVarType & 33554431) {
	case 1:
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR);
		last_value.short_value = *((short*)safevar);/*���氲ȫ����֮ǰ��ֵ*/
		*((short*)safevar) = va_arg(arg_ptr, short);/*����ֵ���谲ȫ����*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next){
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((short*)safevar) = last_value.short_value;/*д����ֵ���ƻ����򣬻ָ�Ϊ��ֵ*/\
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR);
		break;
	case 2:
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR);
		last_value.int_value = *((int*)safevar);/*���氲ȫ����֮ǰ��ֵ*/
		*((int*)safevar) = va_arg(arg_ptr, int);/*����ֵ���谲ȫ����*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((int*)safevar) = last_value.int_value;/*д����ֵ���ƻ����򣬻ָ�Ϊ��ֵ*/
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR);
		break;
	case 3:
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR);
		last_value.long_value = *((long*)safevar);/*���氲ȫ����֮ǰ��ֵ*/
		*((long*)safevar) = va_arg(arg_ptr, long);/*����ֵ���谲ȫ����*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((long*)safevar) = last_value.long_value;/*д����ֵ���ƻ����򣬻ָ�Ϊ��ֵ*/
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR);
		break;
	case 4:
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR);
		last_value.float_value = *((float*)safevar);/*���氲ȫ����֮ǰ��ֵ*/
		*((float*)safevar) = va_arg(arg_ptr, float);/*����ֵ���谲ȫ����*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((float*)safevar) = last_value.float_value;/*д����ֵ���ƻ����򣬻ָ�Ϊ��ֵ*/
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR);
		break;
	case 5:
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR);
		last_value.double_value = *((double*)safevar);/*���氲ȫ����֮ǰ��ֵ*/
		*((double*)safevar) = va_arg(arg_ptr, double);/*����ֵ���谲ȫ����*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((double*)safevar) = last_value.double_value;/*д����ֵ���ƻ����򣬻ָ�Ϊ��ֵ*/
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR);
		break;
	case 6:
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR);
		last_value.char_value = *((char*)safevar);/*���氲ȫ����֮ǰ��ֵ*/
		*((char*)safevar) = va_arg(arg_ptr, char);/*����ֵ���谲ȫ����*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((char*)safevar) = last_value.char_value;/*д����ֵ���ƻ����򣬻ָ�Ϊ��ֵ*/
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR);
		break;
	default:
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_TYPE\n");
#endif
		err = OS_ERR_SAFE_VAR_INVALID_TYPE;
		break;
	}
	/*���ñ����Ƿ���Ҫ�������Լ�����֮�����Ƿ��и������ȼ��������ڵȴ������ȫ����*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//����ǰ6λ
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if (safevar->OSEventGrp != 0) {/*˵���������ڵȴ������ȫ��������*/
		y = OSUnMapTbl[safevar->OSEventGrp];              /* Find HPT waiting for safeVar                */
		x = OSUnMapTbl[safevar->OSEventTbl[y]];
		prio = (INT8U)((y << 3u) + x);
		ptcb = OSTCBPrioTbl[prio];
		y = ptcb->OSTCBY;
		safevar->OSEventTbl[y] &= (OS_PRIO)~ptcb->OSTCBBitX;    /* Remove task from wait list              */
		if (safevar->OSEventTbl[y] == 0u) {
			safevar->OSEventGrp &= (OS_PRIO)~ptcb->OSTCBBitY;
		}

		if ((ptcb->OSTCBStat &   OS_STAT_SUSPEND) == OS_STAT_RDY) {
			OSRdyGrp |= ptcb->OSTCBBitY;           /* Put task in the ready to run list           */
			OSRdyTbl[y] |= ptcb->OSTCBBitX;
			OS_EXIT_CRITICAL();
			OS_Sched();
		}
		else {
			OS_EXIT_CRITICAL();
		}
	}
	else {
		safevar->OSSafeVarType &= 4261412863;
		OS_EXIT_CRITICAL();
	}
	/*--���ñ����Ƿ���Ҫ�������Լ�����֮�����Ƿ��и������ȼ��������ڵȴ������ȫ����--*/
	return err;
}

INT8U  OSSafeVarNoCheckSet(char * name, void* value)
{
	OS_SAFE_VAR *safevar;
	INT8U err = OS_ERR_NONE;
	INT32U lockCount;
	/*�����ҵ�������������ȼ�����ı���*/
	OS_TCB   *ptcb;
	INT8U     y;
	INT8U     x;
	INT8U     prio;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* ��������Ч�� */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_NAME;
	}
#endif
	/*���Ұ�ȫ������ַ*/
	for (safevar = OSSafeVars[OSPrioCur]; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
		if (strcmp(((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name, name) == 0) {
			break;
		}
	}
	if (safevar == (OS_SAFE_VAR *)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_NOT_EXIST\n");
#endif
		return OS_ERR_SAFE_VAR_NOT_EXIST;
	}
	safevar = (OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK));

	/*���ñ����Ƿ���Ҫ����*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//����ǰ6λ
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if ((safevar->OSSafeVarType & 33554432) == 0) {/*˵����27λ��0��δ����*/
		safevar->OSSafeVarType |= 33554432;
		OS_EXIT_CRITICAL();
	}
	else {
		/*����ǰ����Ӿ����������ɾ��*/
		if ((OSRdyTbl[OSTCBCur->OSTCBY] &= ~OSTCBCur->OSTCBBitX) == 0) {
			OSRdyGrp &= ~OSTCBCur->OSTCBBitY;
		}
		safevar->OSEventTbl[OSTCBCur->OSTCBY] |= OSTCBCur->OSTCBBitX;
		safevar->OSEventGrp |= OSTCBCur->OSTCBBitY;
		OS_EXIT_CRITICAL();
		OS_Sched();
	}
	/*--���ñ����Ƿ���Ҫ����--*/

	switch (safevar->OSSafeVarType & 33554431) {
	case 1:
		*((short*)((INT8U*)safevar + sizeof(OS_SAFE_VAR))) = *((short*)value);/*����ֵ���谲ȫ����*/
		break;
	case 2:
		*((int*)((INT8U*)safevar + sizeof(OS_SAFE_VAR))) = *((int*)value);/*����ֵ���谲ȫ����*/
		break;
	case 3:
		*((long*)((INT8U*)safevar + sizeof(OS_SAFE_VAR))) = *((long*)value);/*����ֵ���谲ȫ����*/
		break;
	case 4:
		*((float*)((INT8U*)safevar + sizeof(OS_SAFE_VAR))) = *((float*)value);/*����ֵ���谲ȫ����*/
		break;
	case 5:
		*((double*)((INT8U*)safevar + sizeof(OS_SAFE_VAR))) = *((double*)value);/*����ֵ���谲ȫ����*/
		break;
	case 6:
		*((char*)((INT8U*)safevar + sizeof(OS_SAFE_VAR))) = *((char*)value);/*����ֵ���谲ȫ����*/
		break;
	default:
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_TYPE\n");
#endif
		err = OS_ERR_SAFE_VAR_INVALID_TYPE;
		break;
	}
	/*���ñ����Ƿ���Ҫ�������Լ�����֮�����Ƿ��и������ȼ��������ڵȴ������ȫ����*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//����ǰ6λ
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if (safevar->OSEventGrp != 0) {/*˵���������ڵȴ������ȫ��������*/
		y = OSUnMapTbl[safevar->OSEventGrp];              /* Find HPT waiting for safeVar                */
		x = OSUnMapTbl[safevar->OSEventTbl[y]];
		prio = (INT8U)((y << 3u) + x);
		ptcb = OSTCBPrioTbl[prio];
		y = ptcb->OSTCBY;
		safevar->OSEventTbl[y] &= (OS_PRIO)~ptcb->OSTCBBitX;    /* Remove task from wait list              */
		if (safevar->OSEventTbl[y] == 0u) {
			safevar->OSEventGrp &= (OS_PRIO)~ptcb->OSTCBBitY;
		}

		if ((ptcb->OSTCBStat &   OS_STAT_SUSPEND) == OS_STAT_RDY) {
			OSRdyGrp |= ptcb->OSTCBBitY;           /* Put task in the ready to run list           */
			OSRdyTbl[y] |= ptcb->OSTCBBitX;
			OS_EXIT_CRITICAL();
			OS_Sched();
		}
		else {
			OS_EXIT_CRITICAL();
		}
	}
	else {
		safevar->OSSafeVarType &= 4261412863;
		OS_EXIT_CRITICAL();
	}
	/*--���ñ����Ƿ���Ҫ�������Լ�����֮�����Ƿ��и������ȼ��������ڵȴ������ȫ����--*/
	return err;
}

OS_SAFE_VAR_DATA*  OSSafeVarGet(char * name, INT8U   *perr)
{
	OS_SAFE_VAR *safevar;
	OS_SAFE_VAR_DATA safe_var_data = { 0 };
	INT32U lockCount;
	/*�����ҵ�������������ȼ�����ı���*/
	OS_TCB   *ptcb;
	INT8U     y;
	INT8U     x;
	INT8U     prio;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* ��������Ч�� */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		*perr = OS_ERR_SAFE_VAR_INVALID_NAME;
		return &safe_var_data;
	}
#endif
	/*���Ұ�ȫ������ַ*/
	for (safevar = OSSafeVars[OSPrioCur]; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
		if (strcmp(((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name, name) == 0) {
			break;
		}
	}
	if (safevar == (OS_SAFE_VAR *)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_NOT_EXIST\n");
#endif
		*perr = OS_ERR_SAFE_VAR_NOT_EXIST;
		return &safe_var_data;
	}
	safevar = (OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK));

	/*���ñ����Ƿ���Ҫ����*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//����ǰ6λ
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if ((safevar->OSSafeVarType & 33554432) == 0) {/*˵����27λ��0��δ����*/
		safevar->OSSafeVarType |= 33554432;
		OS_EXIT_CRITICAL();
	}
	else {
		/*����ǰ����Ӿ����������ɾ��*/
		if ((OSRdyTbl[OSTCBCur->OSTCBY] &= ~OSTCBCur->OSTCBBitX) == 0) {
			OSRdyGrp &= ~OSTCBCur->OSTCBBitY;
		}
		safevar->OSEventTbl[OSTCBCur->OSTCBY] |= OSTCBCur->OSTCBBitX;
		safevar->OSEventGrp |= OSTCBCur->OSTCBBitY;
		OS_EXIT_CRITICAL();
		OS_Sched();
	}
	/*--���ñ����Ƿ���Ҫ����--*/

	switch (safevar->OSSafeVarType & 33554431) {
	case 1:
		safe_var_data.short_value = *((short*)((INT8U*)safevar + sizeof(OS_SAFE_VAR)));
		break;
	case 2:
		safe_var_data.int_value = *((int*)((INT8U*)safevar + sizeof(OS_SAFE_VAR)));
		break;
	case 3:
		safe_var_data.long_value = *((long*)((INT8U*)safevar + sizeof(OS_SAFE_VAR)));
		break;
	case 4:
		safe_var_data.float_value = *((float*)((INT8U*)safevar + sizeof(OS_SAFE_VAR)));
		break;
	case 5:
		safe_var_data.double_value = *((double*)((INT8U*)safevar + sizeof(OS_SAFE_VAR)));
		break;
	case 6:
		safe_var_data.char_value = *((char*)((INT8U*)safevar + sizeof(OS_SAFE_VAR)));
		break;
	default:
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_TYPE\n");
#endif
		*perr = OS_ERR_SAFE_VAR_INVALID_TYPE;
		break;
	}
	/*���ñ����Ƿ���Ҫ�������Լ�����֮�����Ƿ��и������ȼ��������ڵȴ������ȫ����*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//����ǰ6λ
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if (safevar->OSEventGrp != 0) {/*˵���������ڵȴ������ȫ��������*/
		y = OSUnMapTbl[safevar->OSEventGrp];              /* Find HPT waiting for safeVar                */
		x = OSUnMapTbl[safevar->OSEventTbl[y]];
		prio = (INT8U)((y << 3u) + x);
		ptcb = OSTCBPrioTbl[prio];
		y = ptcb->OSTCBY;
		safevar->OSEventTbl[y] &= (OS_PRIO)~ptcb->OSTCBBitX;    /* Remove task from wait list              */
		if (safevar->OSEventTbl[y] == 0u) {
			safevar->OSEventGrp &= (OS_PRIO)~ptcb->OSTCBBitY;
		}

		if ((ptcb->OSTCBStat &   OS_STAT_SUSPEND) == OS_STAT_RDY) {
			OSRdyGrp |= ptcb->OSTCBBitY;           /* Put task in the ready to run list           */
			OSRdyTbl[y] |= ptcb->OSTCBBitX;
			OS_EXIT_CRITICAL();
			OS_Sched();
		}
		else {
			OS_EXIT_CRITICAL();
		}
	}
	else {
		safevar->OSSafeVarType &= 4261412863;
		OS_EXIT_CRITICAL();
	}
	/*--���ñ����Ƿ���Ҫ�������Լ�����֮�����Ƿ��и������ȼ��������ڵȴ������ȫ����--*/
	return &safe_var_data;
}

INT8U  OSSafeArraySet(char * name, int  index, ...)
{
	OS_SAFE_VAR *safevar;
	INT32U blockSize;
	OS_SAFE_VAR_DATA last_value;
	OS_SAFE_RULE *saferule;
	INT8U err = OS_ERR_NONE;
	INT32U lockCount;
	va_list arg_ptr;
	va_start(arg_ptr, index);  //�Թ̶������ĵ�ַΪ���ȷ����ε��ڴ���ʼ��ַ�� 
	/*�����ҵ�������������ȼ�����ı���*/
	OS_TCB   *ptcb;
	INT8U     y;
	INT8U     x;
	INT8U     prio;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* ��������Ч�� */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_NAME;
	}
#endif
	/*���Ұ�ȫ������ַ*/
	for (safevar = OSSafeVars[OSPrioCur]; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
		if (strcmp(((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name, name) == 0) {
			break;
		}
	}
	if (safevar == (OS_SAFE_VAR *)0) {

#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_NOT_EXIST\n");
#endif
		return OS_ERR_SAFE_VAR_NOT_EXIST;
	}
	if (((OS_SAFE_MEM_BLOCK *)safevar)->OSNextPhyMemBlk == NULL) {
		blockSize = (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE - (INT8U*)safevar - sizeof(OS_SAFE_MEM_BLOCK);
	}
	else {
		blockSize = (INT8U*)((OS_SAFE_MEM_BLOCK *)safevar)->OSNextPhyMemBlk - (INT8U*)safevar;
	}
	safevar = (OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK));
	saferule = safevar->OSRuleList;

	/*���ñ����Ƿ���Ҫ����*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//����ǰ6λ
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if ((safevar->OSSafeVarType & 33554432) == 0) {/*˵����27λ��0��δ����*/
		safevar->OSSafeVarType |= 33554432;
		OS_EXIT_CRITICAL();
	}
	else {
		/*����ǰ����Ӿ����������ɾ��*/
		if ((OSRdyTbl[OSTCBCur->OSTCBY] &= ~OSTCBCur->OSTCBBitX) == 0) {
			OSRdyGrp &= ~OSTCBCur->OSTCBBitY;
		}
		safevar->OSEventTbl[OSTCBCur->OSTCBY] |= OSTCBCur->OSTCBBitX;
		safevar->OSEventGrp |= OSTCBCur->OSTCBBitY;
		OS_EXIT_CRITICAL();
		OS_Sched();
	}
	/*--���ñ����Ƿ���Ҫ����--*/

	switch (safevar->OSSafeVarType & 33554431) {
	case 11:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(short)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			return OS_ERR_SAFE_ARRAY_INDEX;
		}
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(short)*index;
		last_value.short_value = *((short*)safevar);/*���氲ȫ����֮ǰ��ֵ*/
		*((short*)safevar) = va_arg(arg_ptr, short);/*����ֵ���谲ȫ����*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((short*)safevar) = last_value.short_value;/*д����ֵ���ƻ����򣬻ָ�Ϊ��ֵ*/
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR) - sizeof(short)*index;
		break;
	case 12:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(int)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			return OS_ERR_SAFE_ARRAY_INDEX;
		}
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(int)*index;
		last_value.int_value = *((int*)safevar);/*���氲ȫ����֮ǰ��ֵ*/
		*((int*)safevar) = va_arg(arg_ptr, int);/*����ֵ���谲ȫ����*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((int*)safevar) = last_value.int_value;/*д����ֵ���ƻ����򣬻ָ�Ϊ��ֵ*/
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR) - sizeof(int)*index;
		break;
	case 13:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(long)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			return OS_ERR_SAFE_ARRAY_INDEX;
		}
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(long)*index;
		last_value.long_value = *((long*)safevar);/*���氲ȫ����֮ǰ��ֵ*/
		*((long*)safevar) = va_arg(arg_ptr, long);/*����ֵ���谲ȫ����*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((long*)safevar) = last_value.long_value;/*д����ֵ���ƻ����򣬻ָ�Ϊ��ֵ*/
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR) - sizeof(long)*index;
		break;
	case 14:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(float)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			return OS_ERR_SAFE_ARRAY_INDEX;
		}
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(float)*index;
		last_value.float_value = *((float*)safevar);/*���氲ȫ����֮ǰ��ֵ*/
		*((float*)safevar) = va_arg(arg_ptr, float);/*����ֵ���谲ȫ����*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((float*)safevar) = last_value.float_value;/*д����ֵ���ƻ����򣬻ָ�Ϊ��ֵ*/
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR) - sizeof(float)*index;
		break;
	case 15:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(double)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			return OS_ERR_SAFE_ARRAY_INDEX;
		}
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(double)*index;
		last_value.double_value = *((double*)safevar);/*���氲ȫ����֮ǰ��ֵ*/
		*((double*)safevar) = va_arg(arg_ptr, double);/*����ֵ���谲ȫ����*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((double*)safevar) = last_value.double_value;/*д����ֵ���ƻ����򣬻ָ�Ϊ��ֵ*/
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR) - sizeof(double)*index;
		break;
	case 16:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(char)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			return OS_ERR_SAFE_ARRAY_INDEX;
		}
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(char)*index;
		last_value.char_value = *((char*)safevar);/*���氲ȫ����֮ǰ��ֵ*/
		*((char*)safevar) = va_arg(arg_ptr, char);/*����ֵ���谲ȫ����*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((char*)safevar) = last_value.char_value;/*д����ֵ���ƻ����򣬻ָ�Ϊ��ֵ*/
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR) - sizeof(char)*index;
		break;
	default:
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_TYPE\n");
#endif
		err = OS_ERR_SAFE_VAR_INVALID_TYPE;
		break;
	}
	/*���ñ����Ƿ���Ҫ�������Լ�����֮�����Ƿ��и������ȼ��������ڵȴ������ȫ����*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//����ǰ6λ
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if (safevar->OSEventGrp != 0) {/*˵���������ڵȴ������ȫ��������*/
		y = OSUnMapTbl[safevar->OSEventGrp];              /* Find HPT waiting for safeVar                */
		x = OSUnMapTbl[safevar->OSEventTbl[y]];
		prio = (INT8U)((y << 3u) + x);
		ptcb = OSTCBPrioTbl[prio];
		y = ptcb->OSTCBY;
		safevar->OSEventTbl[y] &= (OS_PRIO)~ptcb->OSTCBBitX;    /* Remove task from wait list              */
		if (safevar->OSEventTbl[y] == 0u) {
			safevar->OSEventGrp &= (OS_PRIO)~ptcb->OSTCBBitY;
		}

		if ((ptcb->OSTCBStat &   OS_STAT_SUSPEND) == OS_STAT_RDY) {
			OSRdyGrp |= ptcb->OSTCBBitY;           /* Put task in the ready to run list           */
			OSRdyTbl[y] |= ptcb->OSTCBBitX;
			OS_EXIT_CRITICAL();
			OS_Sched();
		}
		else {
			OS_EXIT_CRITICAL();
		}
	}
	else {
		safevar->OSSafeVarType &= 4261412863;
		OS_EXIT_CRITICAL();
	}
	/*--���ñ����Ƿ���Ҫ�������Լ�����֮�����Ƿ��и������ȼ��������ڵȴ������ȫ����--*/
	return err;
}


INT8U  OSSafeArrayNoCheckSet(char * name, int  index, ...)
{
	OS_SAFE_VAR *safevar;
	INT32U blockSize;
	INT32U lockCount;
	va_list arg_ptr;
	va_start(arg_ptr, index);  //�Թ̶������ĵ�ַΪ���ȷ����ε��ڴ���ʼ��ַ�� 
	/*�����ҵ�������������ȼ�����ı���*/
	OS_TCB   *ptcb;
	INT8U     y;
	INT8U     x;
	INT8U     prio;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* ��������Ч�� */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_NAME;
	}
#endif
	/*���Ұ�ȫ������ַ*/
	for (safevar = OSSafeVars[OSPrioCur]; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
		if (strcmp(((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name, name) == 0) {
			break;
		}
	}
	if (safevar == (OS_SAFE_VAR *)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_NOT_EXIST\n");
#endif
		return OS_ERR_SAFE_VAR_NOT_EXIST;
	}
	if (((OS_SAFE_MEM_BLOCK *)safevar)->OSNextPhyMemBlk == NULL) {
		blockSize = (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE - (INT8U*)safevar - sizeof(OS_SAFE_MEM_BLOCK);
	}
	else {
		blockSize = (INT8U*)((OS_SAFE_MEM_BLOCK *)safevar)->OSNextPhyMemBlk - (INT8U*)safevar;
	}
	safevar = (OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK));

	/*���ñ����Ƿ���Ҫ����*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//����ǰ6λ
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if ((safevar->OSSafeVarType & 33554432) == 0) {/*˵����27λ��0��δ����*/
		safevar->OSSafeVarType |= 33554432;
		OS_EXIT_CRITICAL();
	}
	else {
		/*����ǰ����Ӿ����������ɾ��*/
		if ((OSRdyTbl[OSTCBCur->OSTCBY] &= ~OSTCBCur->OSTCBBitX) == 0) {
			OSRdyGrp &= ~OSTCBCur->OSTCBBitY;
		}
		safevar->OSEventTbl[OSTCBCur->OSTCBY] |= OSTCBCur->OSTCBBitX;
		safevar->OSEventGrp |= OSTCBCur->OSTCBBitY;
		OS_EXIT_CRITICAL();
		OS_Sched();
	}
	/*--���ñ����Ƿ���Ҫ����--*/

	switch (safevar->OSSafeVarType & 33554431) {
	case 11:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(short)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			return OS_ERR_SAFE_ARRAY_INDEX;
		}
		*((short*)((INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(short)*index)) = va_arg(arg_ptr, short);/*����ֵ���谲ȫ����*/
		break;
	case 12:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(int)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			return OS_ERR_SAFE_ARRAY_INDEX;
		}
		*((int*)((INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(int)*index)) = va_arg(arg_ptr, int);/*����ֵ���谲ȫ����*/
		break;
	case 13:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(long)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			return OS_ERR_SAFE_ARRAY_INDEX;
		}
		*((long*)((INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(long)*index)) = va_arg(arg_ptr, long);/*����ֵ���谲ȫ����*/
		break;
	case 14:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(float)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			return OS_ERR_SAFE_ARRAY_INDEX;
		}
		*((float*)((INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(float)*index)) = va_arg(arg_ptr, float);/*����ֵ���谲ȫ����*/
		break;
	case 15:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(double)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			return OS_ERR_SAFE_ARRAY_INDEX;
		}
		*((double*)((INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(double)*index)) = va_arg(arg_ptr, double);/*����ֵ���谲ȫ����*/
		break;
	case 16:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(char)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			return OS_ERR_SAFE_ARRAY_INDEX;
		}
		*((char*)((INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(char)*index)) = va_arg(arg_ptr, char);/*����ֵ���谲ȫ����*/
		break;
	default:
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_TYPE\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_TYPE;
		break;
	}
	/*���ñ����Ƿ���Ҫ�������Լ�����֮�����Ƿ��и������ȼ��������ڵȴ������ȫ����*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//����ǰ6λ
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if (safevar->OSEventGrp != 0) {/*˵���������ڵȴ������ȫ��������*/
		y = OSUnMapTbl[safevar->OSEventGrp];              /* Find HPT waiting for safeVar                */
		x = OSUnMapTbl[safevar->OSEventTbl[y]];
		prio = (INT8U)((y << 3u) + x);
		ptcb = OSTCBPrioTbl[prio];
		y = ptcb->OSTCBY;
		safevar->OSEventTbl[y] &= (OS_PRIO)~ptcb->OSTCBBitX;    /* Remove task from wait list              */
		if (safevar->OSEventTbl[y] == 0u) {
			safevar->OSEventGrp &= (OS_PRIO)~ptcb->OSTCBBitY;
		}

		if ((ptcb->OSTCBStat &   OS_STAT_SUSPEND) == OS_STAT_RDY) {
			OSRdyGrp |= ptcb->OSTCBBitY;           /* Put task in the ready to run list           */
			OSRdyTbl[y] |= ptcb->OSTCBBitX;
			OS_EXIT_CRITICAL();
			OS_Sched();
		}
		else {
			OS_EXIT_CRITICAL();
		}
	}
	else {
		safevar->OSSafeVarType &= 4261412863;
		OS_EXIT_CRITICAL();
	}
	/*--���ñ����Ƿ���Ҫ�������Լ�����֮�����Ƿ��и������ȼ��������ڵȴ������ȫ����--*/
	return OS_ERR_NONE;
}

INT8U  OSSafeArrayNoCheckNCopy(char * name, void* value, int  n)
{
	OS_SAFE_VAR *safevar;
	INT32U blockSize,i;
	INT32U lockCount;
	/*�����ҵ�������������ȼ�����ı���*/
	OS_TCB   *ptcb;
	INT8U     y;
	INT8U     x;
	INT8U     prio;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* ��������Ч�� */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_NAME;
	}
#endif
	/*���Ұ�ȫ������ַ*/
	for (safevar = OSSafeVars[OSPrioCur]; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
		if (strcmp(((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name, name) == 0) {
			break;
		}
	}
	if (safevar == (OS_SAFE_VAR *)0) {

#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_NOT_EXIST\n");
#endif
		return OS_ERR_SAFE_VAR_NOT_EXIST;
	}
	if (((OS_SAFE_MEM_BLOCK *)safevar)->OSNextPhyMemBlk == NULL) {
		blockSize = (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE - (INT8U*)safevar - sizeof(OS_SAFE_MEM_BLOCK);
	}
	else {
		blockSize = (INT8U*)((OS_SAFE_MEM_BLOCK *)safevar)->OSNextPhyMemBlk - (INT8U*)safevar;
	}
	safevar = (OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK));

	/*���ñ����Ƿ���Ҫ����*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//����ǰ6λ
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if ((safevar->OSSafeVarType & 33554432) == 0) {/*˵����27λ��0��δ����*/
		safevar->OSSafeVarType |= 33554432;
		OS_EXIT_CRITICAL();
	}
	else {
		/*����ǰ����Ӿ����������ɾ��*/
		if ((OSRdyTbl[OSTCBCur->OSTCBY] &= ~OSTCBCur->OSTCBBitX) == 0) {
			OSRdyGrp &= ~OSTCBCur->OSTCBBitY;
		}
		safevar->OSEventTbl[OSTCBCur->OSTCBY] |= OSTCBCur->OSTCBBitX;
		safevar->OSEventGrp |= OSTCBCur->OSTCBBitY;
		OS_EXIT_CRITICAL();
		OS_Sched();
	}
	/*--���ñ����Ƿ���Ҫ����--*/

	switch (safevar->OSSafeVarType & 33554431) {
	case 11:
		if (n > (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(short)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_BOUND\n");
#endif
			return OS_ERR_SAFE_ARRAY_BOUND;
		}
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR);
		for (i = 0; i < n; i++) {
			*((short*)safevar) = *((short*)value);/*����ֵ���谲ȫ����*/
			safevar = (INT8U*)safevar + sizeof(short);
			value = (INT8U*)value + sizeof(short);
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR) - sizeof(short)*n;
		break;
	case 12:
		if (n > (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(int)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_BOUND\n");
#endif
			return OS_ERR_SAFE_ARRAY_BOUND;
		}
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR);
		for (i = 0; i < n; i++) {
			*((int*)safevar) = *((int*)value);/*����ֵ���谲ȫ����*/
			safevar = (INT8U*)safevar + sizeof(int);
			value = (INT8U*)value + sizeof(int);
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR) - sizeof(int)*n;
		break;
	case 13:
		if (n > (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(long)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_BOUND\n");
#endif
			return OS_ERR_SAFE_ARRAY_BOUND;
		}
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR);
		for (i = 0; i < n; i++) {
			*((long*)safevar) = *((long*)value);/*����ֵ���谲ȫ����*/
			safevar = (INT8U*)safevar + sizeof(long);
			value = (INT8U*)value + sizeof(long);
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR) - sizeof(long)*n;
		break;
	case 14:
		if (n > (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(float)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_BOUND\n");
#endif
			return OS_ERR_SAFE_ARRAY_BOUND;
		}
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR);
		for (i = 0; i < n; i++) {
			*((float*)safevar) = *((float*)value);/*����ֵ���谲ȫ����*/
			safevar = (INT8U*)safevar + sizeof(float);
			value = (INT8U*)value + sizeof(float);
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR) - sizeof(float)*n;
		break;
	case 15:
		if (n > (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(double)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_BOUND\n");
#endif
			return OS_ERR_SAFE_ARRAY_BOUND;
		}
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR);
		for (i = 0; i < n; i++) {
			*((double*)safevar) = *((double*)value);/*����ֵ���谲ȫ����*/
			safevar = (INT8U*)safevar + sizeof(double);
			value = (INT8U*)value + sizeof(double);
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR) - sizeof(double)*n;
		break;
	case 16:
		if (n > (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(char)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_BOUND\n");
#endif
			return OS_ERR_SAFE_ARRAY_BOUND;
		}
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR);
		for (i = 0; i < n; i++) {
			*((char*)safevar) = *((char*)value);/*����ֵ���谲ȫ����*/
			safevar = (INT8U*)safevar + sizeof(char);
			value = (INT8U*)value + sizeof(char);
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR) - sizeof(char)*n;
		break;
	default:
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_TYPE\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_TYPE;
	}
	/*���ñ����Ƿ���Ҫ�������Լ�����֮�����Ƿ��и������ȼ��������ڵȴ������ȫ����*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//����ǰ6λ
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if (safevar->OSEventGrp != 0) {/*˵���������ڵȴ������ȫ��������*/
		y = OSUnMapTbl[safevar->OSEventGrp];              /* Find HPT waiting for safeVar                */
		x = OSUnMapTbl[safevar->OSEventTbl[y]];
		prio = (INT8U)((y << 3u) + x);
		ptcb = OSTCBPrioTbl[prio];
		y = ptcb->OSTCBY;
		safevar->OSEventTbl[y] &= (OS_PRIO)~ptcb->OSTCBBitX;    /* Remove task from wait list              */
		if (safevar->OSEventTbl[y] == 0u) {
			safevar->OSEventGrp &= (OS_PRIO)~ptcb->OSTCBBitY;
		}

		if ((ptcb->OSTCBStat &   OS_STAT_SUSPEND) == OS_STAT_RDY) {
			OSRdyGrp |= ptcb->OSTCBBitY;           /* Put task in the ready to run list           */
			OSRdyTbl[y] |= ptcb->OSTCBBitX;
			OS_EXIT_CRITICAL();
			OS_Sched();
		}
		else {
			OS_EXIT_CRITICAL();
		}
	}
	else {
		safevar->OSSafeVarType &= 4261412863;
		OS_EXIT_CRITICAL();
	}
	/*--���ñ����Ƿ���Ҫ�������Լ�����֮�����Ƿ��и������ȼ��������ڵȴ������ȫ����--*/
	return OS_ERR_NONE;;
}


OS_SAFE_VAR_DATA*  OSSafeArrayGet(char * name, int index , INT8U   *perr)
{
	OS_SAFE_VAR *safevar;
	OS_SAFE_VAR_DATA safe_var_data = { 0 };
	INT32U blockSize;
	INT32U lockCount;
	/*�����ҵ�������������ȼ�����ı���*/
	OS_TCB   *ptcb;
	INT8U     y;
	INT8U     x;
	INT8U     prio;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* ��������Ч�� */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		*perr = OS_ERR_SAFE_VAR_INVALID_NAME;
		return &safe_var_data;
	}
#endif
	/*���Ұ�ȫ������ַ*/
	for (safevar = OSSafeVars[OSPrioCur]; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
		if (strcmp(((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name, name) == 0) {
			break;
		}
	}
	if (safevar == (OS_SAFE_VAR *)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_NOT_EXIST\n");
#endif
		*perr = OS_ERR_SAFE_VAR_NOT_EXIST;
		return &safe_var_data;
	}
	if (((OS_SAFE_MEM_BLOCK *)safevar)->OSNextPhyMemBlk == NULL) {
		blockSize = (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE - (INT8U*)safevar - sizeof(OS_SAFE_MEM_BLOCK);
	}
	else {
		blockSize = (INT8U*)((OS_SAFE_MEM_BLOCK *)safevar)->OSNextPhyMemBlk - (INT8U*)safevar;
	}
	safevar = (OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK));

	/*���ñ����Ƿ���Ҫ����*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//����ǰ6λ
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if ((safevar->OSSafeVarType & 33554432) == 0) {/*˵����27λ��0��δ����*/
		safevar->OSSafeVarType |= 33554432;
		OS_EXIT_CRITICAL();
	}
	else {
		/*����ǰ����Ӿ����������ɾ��*/
		if ((OSRdyTbl[OSTCBCur->OSTCBY] &= ~OSTCBCur->OSTCBBitX) == 0) {
			OSRdyGrp &= ~OSTCBCur->OSTCBBitY;
		}
		safevar->OSEventTbl[OSTCBCur->OSTCBY] |= OSTCBCur->OSTCBBitX;
		safevar->OSEventGrp |= OSTCBCur->OSTCBBitY;
		OS_EXIT_CRITICAL();
		OS_Sched();
	}
	/*--���ñ����Ƿ���Ҫ����--*/

	switch (safevar->OSSafeVarType & 33554431) {
	case 11:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(short)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			*perr = OS_ERR_SAFE_ARRAY_INDEX;
			return &safe_var_data;
		}
		safe_var_data.short_value = *((short*)((INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(short)*index));
		break;
	case 12:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(int)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			*perr = OS_ERR_SAFE_ARRAY_INDEX;
			return &safe_var_data;
		}
		safe_var_data.int_value = *((int*)((INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(int)*index));
		break;
	case 13:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(long)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			*perr = OS_ERR_SAFE_ARRAY_INDEX;
			return &safe_var_data;
		}
		safe_var_data.long_value = *((long*)((INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(long)*index));
		break;
	case 14:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(float)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			*perr = OS_ERR_SAFE_ARRAY_INDEX;
			return &safe_var_data;
		}
		safe_var_data.float_value = *((float*)((INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(float)*index));
		break;
	case 15:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(double)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			*perr = OS_ERR_SAFE_ARRAY_INDEX;
			return &safe_var_data;
		}
		safe_var_data.double_value = *((double*)((INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(double)*index));
		break;
	case 16:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(char)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			*perr = OS_ERR_SAFE_ARRAY_INDEX;
			return &safe_var_data;
		}
		safe_var_data.char_value  = *((char*)((INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(char)*index));
		break;
	default:
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_TYPE\n");
#endif
		*perr = OS_ERR_SAFE_VAR_INVALID_TYPE;
		return &safe_var_data;
		break;
	}
	/*���ñ����Ƿ���Ҫ�������Լ�����֮�����Ƿ��и������ȼ��������ڵȴ������ȫ����*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//����ǰ6λ
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if (safevar->OSEventGrp != 0) {/*˵���������ڵȴ������ȫ��������*/
		y = OSUnMapTbl[safevar->OSEventGrp];              /* Find HPT waiting for safeVar                */
		x = OSUnMapTbl[safevar->OSEventTbl[y]];
		prio = (INT8U)((y << 3u) + x);
		ptcb = OSTCBPrioTbl[prio];
		y = ptcb->OSTCBY;
		safevar->OSEventTbl[y] &= (OS_PRIO)~ptcb->OSTCBBitX;    /* Remove task from wait list              */
		if (safevar->OSEventTbl[y] == 0u) {
			safevar->OSEventGrp &= (OS_PRIO)~ptcb->OSTCBBitY;
		}

		if ((ptcb->OSTCBStat &   OS_STAT_SUSPEND) == OS_STAT_RDY) {
			OSRdyGrp |= ptcb->OSTCBBitY;           /* Put task in the ready to run list           */
			OSRdyTbl[y] |= ptcb->OSTCBBitX;
			OS_EXIT_CRITICAL();
			OS_Sched();
		}
		else {
			OS_EXIT_CRITICAL();
		}
	}
	else {
		safevar->OSSafeVarType &= 4261412863;
		OS_EXIT_CRITICAL();
	}
	/*--���ñ����Ƿ���Ҫ�������Լ�����֮�����Ƿ��и������ȼ��������ڵȴ������ȫ����--*/
	*perr = OS_ERR_NONE;
	return &safe_var_data;
}

INT8U  OSSafeVarCheck(char * name)
{
	OS_SAFE_VAR *safevar;
	OS_SAFE_RULE *saferule;
	INT8U err = OS_ERR_NONE;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* ��������Ч�� */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_NAME;
	}
#endif
	/*���Ұ�ȫ������ַ*/
	for (safevar = OSSafeVars[OSPrioCur]; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
		if (strcmp(((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name, name) == 0) {
			break;
		}
	}
	if (safevar == (OS_SAFE_VAR *)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_NOT_EXIST\n");
#endif
		return OS_ERR_SAFE_VAR_NOT_EXIST;
	}
	safevar = (OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK));
	saferule = safevar->OSRuleList;
	switch (safevar->OSSafeVarType & 33554431) {
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	case 11:
	case 12:
	case 13:
	case 14:
	case 15:
	case 16:
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				return err;
		}
		break;
	default:
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_TYPE\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_TYPE;
		break;
	}
	return OS_ERR_NONE;
}


/*���ݱ�����ɾ����ȫ������������*/
INT8U  OSSafeVarDelete(char * name)
{
	INT8U err;
	OS_SAFE_VAR *safevar,*lastvar;
	OS_SAFE_RULE *saferule;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* ��������Ч�� */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_NAME;
	}
#endif
	/*���Ұ�ȫ������ַ*/
	lastvar = (OS_SAFE_VAR *)0;
	for (safevar = OSSafeVars[OSPrioCur]; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
		if (strcmp(((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name, name) == 0) {
			if (lastvar == (OS_SAFE_VAR *)0) {
				OSSafeVars[OSPrioCur] = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next;
			}
			else {
				((OS_SAFE_VAR *)((INT8U*)lastvar + sizeof(OS_SAFE_MEM_BLOCK)))->next = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next;
			}
			break;
		}
		else {
			lastvar = safevar;
		}
	}
	if (safevar == (OS_SAFE_VAR *)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_NOT_EXIST\n");
#endif
		return OS_ERR_SAFE_VAR_NOT_EXIST;
	}
	saferule = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->OSRuleList;
	/*���ոð�ȫ�����йص����й������Ӧ�������ݽṹ���ڴ�*/
	for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
		err = OSSafeRuleDelete(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
		if (err != OS_ERR_NONE) {
			return err;
		}
	}
	err = OSSafeVarMemPut(safevar);
	if (err != OS_ERR_NONE) {
		return err;
	}
	return OS_ERR_NONE;
}

/*�������ȼ������ȫ����*/
INT8U  OSSafeVarClear(INT8U Prio)
{
	INT8U err;
	OS_SAFE_VAR *safevar;
	OS_SAFE_RULE *saferule, *temprule;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* ��������Ч�� */
	if (Prio < 0u || Prio > OS_LOWEST_PRIO) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_PRIO_INVALID\n");
#endif
		return OS_ERR_PRIO_INVALID;
	}
#endif
	/*��������ȼ������еİ�ȫ����*/
	while (OSSafeVars[Prio] != (OS_SAFE_VAR *)0) {
		safevar = OSSafeVars[Prio];
		OSSafeVars[Prio] = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next;
		sprintf(log_info, "��ע�����ȼ�Ϊ %d �������������İ�ȫ���� %s û����Ӧ��ɾ����������������Զ�ɾ����",Prio, ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name);
		recordLog("����",log_info);
		saferule = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->OSRuleList;
		/*���ոð�ȫ�����йص����й������Ӧ�������ݽṹ���ڴ�*/
		while(saferule != (OS_SAFE_RULE *)0) {
			temprule = saferule;/*���չ����ڼ��Ӱ��saferule*/
			saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next;
			err = OSSafeRuleDelete(((OS_SAFE_RULE *)((INT8U*)temprule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE) {
				return err;
			}
		}
		err = OSSafeVarMemPut(safevar);
		if (err != OS_ERR_NONE) {
			return err;
		}
	}
	return OS_ERR_NONE;
}

#endif                                                    /* OS_SAFE_MEM_EN                                 */
