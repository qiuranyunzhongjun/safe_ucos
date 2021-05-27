
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
* By      : 宋立军
* Version : V1.0
*
* LICENSING TERMS:
* ---------------
*  用于操作安全变量的函数
*********************************************************************************************************
*/

#ifndef  OS_MASTER_FILE
#include <ucos_ii.h>
#endif

#define NDEBUG
#include <assert.h>

#if (OS_SAFE_MEM_EN > 0u)
/*enum operations  {short=1,int, long, float,double,char}支持的安全变量的数据类型编码，以及相应的数组类型，编码加10*/
/*
*********************************************************************************************************
*                                        CREATE A SAFE VARIABLE
*
* Description : 无等待地创建安全变量,支持基本变量
*
* Arguments   : name     要生成的安全变量的名字，之后也只能通过这个名字进行操作安全变量
				type     要生成的安全变量的类型字符串
						 安全变量初始值
* Returns    : 返回错误信息
*********************************************************************************************************
*/

INT8U  OSSafeVarCreate(char * name , char * type, ...)
{
	INT32U  size = sizeof(OS_SAFE_VAR),i; 
	INT8U err,var_type;
	INT8U *pblk;
	OS_SAFE_VAR *safevar;
	va_list arg_ptr;
	va_start(arg_ptr, type);  //以固定参数的地址为起点确定变参的内存起始地址。 

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */
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
	/*检查该优先级的任务中是否已经有了重名的安全变量*/
	for (safevar = OSSafeVars[OSPrioCur]; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
		if (strcmp(((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name, name) == 0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_VAR_NAME_EXIST\n");
#endif
			return OS_ERR_SAFE_VAR_NAME_EXIST;
		}
	}
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	sprintf(log_info, "为安全变量申请安全内存，安全变量名为： %s", name);
	recordLog("变量", log_info);
#endif
	pblk = OSSafeVarMemGet(size, &err);/*为安全变量申请安全内存*/
	if (err != OS_ERR_NONE) {
		return err;
	}
	pblk += sizeof(OS_SAFE_MEM_BLOCK);/**/
	/*存储安全变量的名字*/
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
	/*为安全变量赋初值*/
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
	va_start(arg_ptr, timeout);  //以固定参数的地址为起点确定变参的内存起始地址。 

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */
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
	/*检查该优先级的任务中是否已经有了重名的安全变量*/
	for (safevar = OSSafeVars[OSPrioCur]; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
		if (strcmp(((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name, name) == 0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_VAR_NAME_EXIST\n");
#endif
			return OS_ERR_SAFE_VAR_NAME_EXIST;
		}
	}
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	sprintf(log_info, "为安全变量申请安全内存，安全变量名为： %s", name);
	recordLog("变量", log_info);
#endif
	pblk = OSSafeVarMemPend(size, &timeout, &err);/*为安全变量申请安全内存*/
	if (err != OS_ERR_NONE) {
		return err;
	}
	pblk += sizeof(OS_SAFE_MEM_BLOCK);/**/
	/*存储安全变量的名字*/
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
	/*为安全变量赋初值0*/
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
* Description : 无等待地创建安全变量,支持基本变量的数组变量
*
* Arguments   : name     要生成的安全变量的名字，之后也只能通过这个名字进行操作安全变量
				type     要生成的安全变量的类型字符串
				int      要生成的数组大小
* Returns    : 返回错误信息
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

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */
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
	/*检查该优先级的任务中是否已经有了重名的安全变量*/
	for (safevar = OSSafeVars[OSPrioCur]; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
		if (strcmp(((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name, name) == 0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_VAR_NAME_EXIST\n");
#endif
			return OS_ERR_SAFE_VAR_NAME_EXIST;
		}
	}
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	sprintf(log_info, "为安全数组变量申请安全内存，安全数组变量名为： %s", name);
	recordLog("变量", log_info);
#endif
	pblk = OSSafeVarMemGet(size, &err);/*为安全数组变量申请安全内存*/
	if (err != OS_ERR_NONE) {
		return err;
	}
	pblk += sizeof(OS_SAFE_MEM_BLOCK);/**/
	/*存储安全变量的名字*/
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
	/*为安全变量赋初值0*/
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

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */
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
	/*检查该优先级的任务中是否已经有了重名的安全变量*/
	for (safevar = OSSafeVars[OSPrioCur]; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
		if (strcmp(((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name, name) == 0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_VAR_NAME_EXISTE\n");
#endif
			return OS_ERR_SAFE_VAR_NAME_EXIST;
		}
	}
	pblk = OSSafeVarMemPend(size, &timeout, &err);/*为安全数组变量申请安全内存*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	sprintf(log_info, "为安全数组变量申请安全内存，安全数组变量名为： %s", name);
	recordLog("变量", log_info);
#endif
	if (err != OS_ERR_NONE) {
		return err;
	}
	pblk += sizeof(OS_SAFE_MEM_BLOCK);/**/
	/*存储安全变量的名字*/
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
	/*为安全变量赋初值0*/
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
	/*用于找到就绪的最高优先级任务的变量*/
	OS_TCB   *ptcb;
	INT8U     y;
	INT8U     x;
	INT8U     prio;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_NAME;
	}
#endif
	/*查找安全变量地址*/
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
	/*检查该变量是否需要加锁*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//解析前6位
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if ((safevar->OSSafeVarType & 33554432) == 0) {/*说明第27位是0，未加锁*/
		safevar->OSSafeVarType |= 33554432;
		OS_EXIT_CRITICAL();
	}
	else {
		/*将当前任务从就绪任务表中删除*/
		if ((OSRdyTbl[OSTCBCur->OSTCBY] &= ~OSTCBCur->OSTCBBitX) == 0) {
			OSRdyGrp &= ~OSTCBCur->OSTCBBitY;
		}
		safevar->OSEventTbl[OSTCBCur->OSTCBY] |= OSTCBCur->OSTCBBitX;
		safevar->OSEventGrp |= OSTCBCur->OSTCBBitY;
		OS_EXIT_CRITICAL();
		OS_Sched();
	}
	/*--检查该变量是否需要加锁--*/

	va_start(arg_ptr, name);  //以固定参数的地址为起点确定变参的内存起始地址。 
	switch (safevar->OSSafeVarType & 33554431) {
	case 1:
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR);
		last_value.short_value = *((short*)safevar);/*保存安全变量之前的值*/
		*((short*)safevar) = va_arg(arg_ptr, short);/*将新值赋予安全变量*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next){
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((short*)safevar) = last_value.short_value;/*写入新值会破坏规则，恢复为旧值*/\
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR);
		break;
	case 2:
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR);
		last_value.int_value = *((int*)safevar);/*保存安全变量之前的值*/
		*((int*)safevar) = va_arg(arg_ptr, int);/*将新值赋予安全变量*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((int*)safevar) = last_value.int_value;/*写入新值会破坏规则，恢复为旧值*/
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR);
		break;
	case 3:
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR);
		last_value.long_value = *((long*)safevar);/*保存安全变量之前的值*/
		*((long*)safevar) = va_arg(arg_ptr, long);/*将新值赋予安全变量*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((long*)safevar) = last_value.long_value;/*写入新值会破坏规则，恢复为旧值*/
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR);
		break;
	case 4:
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR);
		last_value.float_value = *((float*)safevar);/*保存安全变量之前的值*/
		*((float*)safevar) = va_arg(arg_ptr, float);/*将新值赋予安全变量*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((float*)safevar) = last_value.float_value;/*写入新值会破坏规则，恢复为旧值*/
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR);
		break;
	case 5:
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR);
		last_value.double_value = *((double*)safevar);/*保存安全变量之前的值*/
		*((double*)safevar) = va_arg(arg_ptr, double);/*将新值赋予安全变量*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((double*)safevar) = last_value.double_value;/*写入新值会破坏规则，恢复为旧值*/
		}
		safevar = (INT8U*)safevar - sizeof(OS_SAFE_VAR);
		break;
	case 6:
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR);
		last_value.char_value = *((char*)safevar);/*保存安全变量之前的值*/
		*((char*)safevar) = va_arg(arg_ptr, char);/*将新值赋予安全变量*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((char*)safevar) = last_value.char_value;/*写入新值会破坏规则，恢复为旧值*/
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
	/*检查该变量是否需要解锁，以及解锁之后检查是否有更高优先级的任务在等待这个安全变量*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//解析前6位
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if (safevar->OSEventGrp != 0) {/*说明有任务在等待这个安全变量解锁*/
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
	/*--检查该变量是否需要解锁，以及解锁之后检查是否有更高优先级的任务在等待这个安全变量--*/
	return err;
}

INT8U  OSSafeVarNoCheckSet(char * name, void* value)
{
	OS_SAFE_VAR *safevar;
	INT8U err = OS_ERR_NONE;
	INT32U lockCount;
	/*用于找到就绪的最高优先级任务的变量*/
	OS_TCB   *ptcb;
	INT8U     y;
	INT8U     x;
	INT8U     prio;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_NAME;
	}
#endif
	/*查找安全变量地址*/
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

	/*检查该变量是否需要加锁*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//解析前6位
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if ((safevar->OSSafeVarType & 33554432) == 0) {/*说明第27位是0，未加锁*/
		safevar->OSSafeVarType |= 33554432;
		OS_EXIT_CRITICAL();
	}
	else {
		/*将当前任务从就绪任务表中删除*/
		if ((OSRdyTbl[OSTCBCur->OSTCBY] &= ~OSTCBCur->OSTCBBitX) == 0) {
			OSRdyGrp &= ~OSTCBCur->OSTCBBitY;
		}
		safevar->OSEventTbl[OSTCBCur->OSTCBY] |= OSTCBCur->OSTCBBitX;
		safevar->OSEventGrp |= OSTCBCur->OSTCBBitY;
		OS_EXIT_CRITICAL();
		OS_Sched();
	}
	/*--检查该变量是否需要加锁--*/

	switch (safevar->OSSafeVarType & 33554431) {
	case 1:
		*((short*)((INT8U*)safevar + sizeof(OS_SAFE_VAR))) = *((short*)value);/*将新值赋予安全变量*/
		break;
	case 2:
		*((int*)((INT8U*)safevar + sizeof(OS_SAFE_VAR))) = *((int*)value);/*将新值赋予安全变量*/
		break;
	case 3:
		*((long*)((INT8U*)safevar + sizeof(OS_SAFE_VAR))) = *((long*)value);/*将新值赋予安全变量*/
		break;
	case 4:
		*((float*)((INT8U*)safevar + sizeof(OS_SAFE_VAR))) = *((float*)value);/*将新值赋予安全变量*/
		break;
	case 5:
		*((double*)((INT8U*)safevar + sizeof(OS_SAFE_VAR))) = *((double*)value);/*将新值赋予安全变量*/
		break;
	case 6:
		*((char*)((INT8U*)safevar + sizeof(OS_SAFE_VAR))) = *((char*)value);/*将新值赋予安全变量*/
		break;
	default:
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_TYPE\n");
#endif
		err = OS_ERR_SAFE_VAR_INVALID_TYPE;
		break;
	}
	/*检查该变量是否需要解锁，以及解锁之后检查是否有更高优先级的任务在等待这个安全变量*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//解析前6位
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if (safevar->OSEventGrp != 0) {/*说明有任务在等待这个安全变量解锁*/
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
	/*--检查该变量是否需要解锁，以及解锁之后检查是否有更高优先级的任务在等待这个安全变量--*/
	return err;
}

OS_SAFE_VAR_DATA*  OSSafeVarGet(char * name, INT8U   *perr)
{
	OS_SAFE_VAR *safevar;
	OS_SAFE_VAR_DATA safe_var_data = { 0 };
	INT32U lockCount;
	/*用于找到就绪的最高优先级任务的变量*/
	OS_TCB   *ptcb;
	INT8U     y;
	INT8U     x;
	INT8U     prio;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		*perr = OS_ERR_SAFE_VAR_INVALID_NAME;
		return &safe_var_data;
	}
#endif
	/*查找安全变量地址*/
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

	/*检查该变量是否需要加锁*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//解析前6位
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if ((safevar->OSSafeVarType & 33554432) == 0) {/*说明第27位是0，未加锁*/
		safevar->OSSafeVarType |= 33554432;
		OS_EXIT_CRITICAL();
	}
	else {
		/*将当前任务从就绪任务表中删除*/
		if ((OSRdyTbl[OSTCBCur->OSTCBY] &= ~OSTCBCur->OSTCBBitX) == 0) {
			OSRdyGrp &= ~OSTCBCur->OSTCBBitY;
		}
		safevar->OSEventTbl[OSTCBCur->OSTCBY] |= OSTCBCur->OSTCBBitX;
		safevar->OSEventGrp |= OSTCBCur->OSTCBBitY;
		OS_EXIT_CRITICAL();
		OS_Sched();
	}
	/*--检查该变量是否需要加锁--*/

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
	/*检查该变量是否需要解锁，以及解锁之后检查是否有更高优先级的任务在等待这个安全变量*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//解析前6位
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if (safevar->OSEventGrp != 0) {/*说明有任务在等待这个安全变量解锁*/
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
	/*--检查该变量是否需要解锁，以及解锁之后检查是否有更高优先级的任务在等待这个安全变量--*/
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
	va_start(arg_ptr, index);  //以固定参数的地址为起点确定变参的内存起始地址。 
	/*用于找到就绪的最高优先级任务的变量*/
	OS_TCB   *ptcb;
	INT8U     y;
	INT8U     x;
	INT8U     prio;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_NAME;
	}
#endif
	/*查找安全变量地址*/
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

	/*检查该变量是否需要加锁*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//解析前6位
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if ((safevar->OSSafeVarType & 33554432) == 0) {/*说明第27位是0，未加锁*/
		safevar->OSSafeVarType |= 33554432;
		OS_EXIT_CRITICAL();
	}
	else {
		/*将当前任务从就绪任务表中删除*/
		if ((OSRdyTbl[OSTCBCur->OSTCBY] &= ~OSTCBCur->OSTCBBitX) == 0) {
			OSRdyGrp &= ~OSTCBCur->OSTCBBitY;
		}
		safevar->OSEventTbl[OSTCBCur->OSTCBY] |= OSTCBCur->OSTCBBitX;
		safevar->OSEventGrp |= OSTCBCur->OSTCBBitY;
		OS_EXIT_CRITICAL();
		OS_Sched();
	}
	/*--检查该变量是否需要加锁--*/

	switch (safevar->OSSafeVarType & 33554431) {
	case 11:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(short)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			return OS_ERR_SAFE_ARRAY_INDEX;
		}
		safevar = (INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(short)*index;
		last_value.short_value = *((short*)safevar);/*保存安全变量之前的值*/
		*((short*)safevar) = va_arg(arg_ptr, short);/*将新值赋予安全变量*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((short*)safevar) = last_value.short_value;/*写入新值会破坏规则，恢复为旧值*/
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
		last_value.int_value = *((int*)safevar);/*保存安全变量之前的值*/
		*((int*)safevar) = va_arg(arg_ptr, int);/*将新值赋予安全变量*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((int*)safevar) = last_value.int_value;/*写入新值会破坏规则，恢复为旧值*/
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
		last_value.long_value = *((long*)safevar);/*保存安全变量之前的值*/
		*((long*)safevar) = va_arg(arg_ptr, long);/*将新值赋予安全变量*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((long*)safevar) = last_value.long_value;/*写入新值会破坏规则，恢复为旧值*/
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
		last_value.float_value = *((float*)safevar);/*保存安全变量之前的值*/
		*((float*)safevar) = va_arg(arg_ptr, float);/*将新值赋予安全变量*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((float*)safevar) = last_value.float_value;/*写入新值会破坏规则，恢复为旧值*/
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
		last_value.double_value = *((double*)safevar);/*保存安全变量之前的值*/
		*((double*)safevar) = va_arg(arg_ptr, double);/*将新值赋予安全变量*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((double*)safevar) = last_value.double_value;/*写入新值会破坏规则，恢复为旧值*/
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
		last_value.char_value = *((char*)safevar);/*保存安全变量之前的值*/
		*((char*)safevar) = va_arg(arg_ptr, char);/*将新值赋予安全变量*/
		for (; saferule != (OS_SAFE_RULE *)0; saferule = ((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			err = OSSafeRuleCalculate(((OS_SAFE_RULE *)((INT8U*)saferule + sizeof(OS_SAFE_MEM_BLOCK)))->rule);
			if (err != OS_ERR_NONE)
				break;
		}
		if (err != OS_ERR_NONE) {
			*((char*)safevar) = last_value.char_value;/*写入新值会破坏规则，恢复为旧值*/
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
	/*检查该变量是否需要解锁，以及解锁之后检查是否有更高优先级的任务在等待这个安全变量*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//解析前6位
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if (safevar->OSEventGrp != 0) {/*说明有任务在等待这个安全变量解锁*/
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
	/*--检查该变量是否需要解锁，以及解锁之后检查是否有更高优先级的任务在等待这个安全变量--*/
	return err;
}


INT8U  OSSafeArrayNoCheckSet(char * name, int  index, ...)
{
	OS_SAFE_VAR *safevar;
	INT32U blockSize;
	INT32U lockCount;
	va_list arg_ptr;
	va_start(arg_ptr, index);  //以固定参数的地址为起点确定变参的内存起始地址。 
	/*用于找到就绪的最高优先级任务的变量*/
	OS_TCB   *ptcb;
	INT8U     y;
	INT8U     x;
	INT8U     prio;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_NAME;
	}
#endif
	/*查找安全变量地址*/
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

	/*检查该变量是否需要加锁*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//解析前6位
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if ((safevar->OSSafeVarType & 33554432) == 0) {/*说明第27位是0，未加锁*/
		safevar->OSSafeVarType |= 33554432;
		OS_EXIT_CRITICAL();
	}
	else {
		/*将当前任务从就绪任务表中删除*/
		if ((OSRdyTbl[OSTCBCur->OSTCBY] &= ~OSTCBCur->OSTCBBitX) == 0) {
			OSRdyGrp &= ~OSTCBCur->OSTCBBitY;
		}
		safevar->OSEventTbl[OSTCBCur->OSTCBY] |= OSTCBCur->OSTCBBitX;
		safevar->OSEventGrp |= OSTCBCur->OSTCBBitY;
		OS_EXIT_CRITICAL();
		OS_Sched();
	}
	/*--检查该变量是否需要加锁--*/

	switch (safevar->OSSafeVarType & 33554431) {
	case 11:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(short)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			return OS_ERR_SAFE_ARRAY_INDEX;
		}
		*((short*)((INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(short)*index)) = va_arg(arg_ptr, short);/*将新值赋予安全变量*/
		break;
	case 12:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(int)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			return OS_ERR_SAFE_ARRAY_INDEX;
		}
		*((int*)((INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(int)*index)) = va_arg(arg_ptr, int);/*将新值赋予安全变量*/
		break;
	case 13:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(long)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			return OS_ERR_SAFE_ARRAY_INDEX;
		}
		*((long*)((INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(long)*index)) = va_arg(arg_ptr, long);/*将新值赋予安全变量*/
		break;
	case 14:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(float)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			return OS_ERR_SAFE_ARRAY_INDEX;
		}
		*((float*)((INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(float)*index)) = va_arg(arg_ptr, float);/*将新值赋予安全变量*/
		break;
	case 15:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(double)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			return OS_ERR_SAFE_ARRAY_INDEX;
		}
		*((double*)((INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(double)*index)) = va_arg(arg_ptr, double);/*将新值赋予安全变量*/
		break;
	case 16:
		if (index >= (blockSize - sizeof(OS_SAFE_MEM_BLOCK) - sizeof(OS_SAFE_VAR)) / sizeof(char)) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_ARRAY_INDEX\n");
#endif
			return OS_ERR_SAFE_ARRAY_INDEX;
		}
		*((char*)((INT8U*)safevar + sizeof(OS_SAFE_VAR) + sizeof(char)*index)) = va_arg(arg_ptr, char);/*将新值赋予安全变量*/
		break;
	default:
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_TYPE\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_TYPE;
		break;
	}
	/*检查该变量是否需要解锁，以及解锁之后检查是否有更高优先级的任务在等待这个安全变量*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//解析前6位
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if (safevar->OSEventGrp != 0) {/*说明有任务在等待这个安全变量解锁*/
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
	/*--检查该变量是否需要解锁，以及解锁之后检查是否有更高优先级的任务在等待这个安全变量--*/
	return OS_ERR_NONE;
}

INT8U  OSSafeArrayNoCheckNCopy(char * name, void* value, int  n)
{
	OS_SAFE_VAR *safevar;
	INT32U blockSize,i;
	INT32U lockCount;
	/*用于找到就绪的最高优先级任务的变量*/
	OS_TCB   *ptcb;
	INT8U     y;
	INT8U     x;
	INT8U     prio;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_NAME;
	}
#endif
	/*查找安全变量地址*/
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

	/*检查该变量是否需要加锁*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//解析前6位
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if ((safevar->OSSafeVarType & 33554432) == 0) {/*说明第27位是0，未加锁*/
		safevar->OSSafeVarType |= 33554432;
		OS_EXIT_CRITICAL();
	}
	else {
		/*将当前任务从就绪任务表中删除*/
		if ((OSRdyTbl[OSTCBCur->OSTCBY] &= ~OSTCBCur->OSTCBBitX) == 0) {
			OSRdyGrp &= ~OSTCBCur->OSTCBBitY;
		}
		safevar->OSEventTbl[OSTCBCur->OSTCBY] |= OSTCBCur->OSTCBBitX;
		safevar->OSEventGrp |= OSTCBCur->OSTCBBitY;
		OS_EXIT_CRITICAL();
		OS_Sched();
	}
	/*--检查该变量是否需要加锁--*/

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
			*((short*)safevar) = *((short*)value);/*将新值赋予安全变量*/
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
			*((int*)safevar) = *((int*)value);/*将新值赋予安全变量*/
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
			*((long*)safevar) = *((long*)value);/*将新值赋予安全变量*/
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
			*((float*)safevar) = *((float*)value);/*将新值赋予安全变量*/
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
			*((double*)safevar) = *((double*)value);/*将新值赋予安全变量*/
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
			*((char*)safevar) = *((char*)value);/*将新值赋予安全变量*/
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
	/*检查该变量是否需要解锁，以及解锁之后检查是否有更高优先级的任务在等待这个安全变量*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//解析前6位
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if (safevar->OSEventGrp != 0) {/*说明有任务在等待这个安全变量解锁*/
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
	/*--检查该变量是否需要解锁，以及解锁之后检查是否有更高优先级的任务在等待这个安全变量--*/
	return OS_ERR_NONE;;
}


OS_SAFE_VAR_DATA*  OSSafeArrayGet(char * name, int index , INT8U   *perr)
{
	OS_SAFE_VAR *safevar;
	OS_SAFE_VAR_DATA safe_var_data = { 0 };
	INT32U blockSize;
	INT32U lockCount;
	/*用于找到就绪的最高优先级任务的变量*/
	OS_TCB   *ptcb;
	INT8U     y;
	INT8U     x;
	INT8U     prio;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		*perr = OS_ERR_SAFE_VAR_INVALID_NAME;
		return &safe_var_data;
	}
#endif
	/*查找安全变量地址*/
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

	/*检查该变量是否需要加锁*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//解析前6位
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if ((safevar->OSSafeVarType & 33554432) == 0) {/*说明第27位是0，未加锁*/
		safevar->OSSafeVarType |= 33554432;
		OS_EXIT_CRITICAL();
	}
	else {
		/*将当前任务从就绪任务表中删除*/
		if ((OSRdyTbl[OSTCBCur->OSTCBY] &= ~OSTCBCur->OSTCBBitX) == 0) {
			OSRdyGrp &= ~OSTCBCur->OSTCBBitY;
		}
		safevar->OSEventTbl[OSTCBCur->OSTCBY] |= OSTCBCur->OSTCBBitX;
		safevar->OSEventGrp |= OSTCBCur->OSTCBBitY;
		OS_EXIT_CRITICAL();
		OS_Sched();
	}
	/*--检查该变量是否需要加锁--*/

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
	/*检查该变量是否需要解锁，以及解锁之后检查是否有更高优先级的任务在等待这个安全变量*/
	OS_ENTER_CRITICAL();
	lockCount = safevar->OSSafeVarType >> 26;//解析前6位
	if (lockCount == 0) {
		OS_EXIT_CRITICAL();
	}
	else if (safevar->OSEventGrp != 0) {/*说明有任务在等待这个安全变量解锁*/
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
	/*--检查该变量是否需要解锁，以及解锁之后检查是否有更高优先级的任务在等待这个安全变量--*/
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

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_NAME;
	}
#endif
	/*查找安全变量地址*/
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


/*根据变量名删除安全变量或者数组*/
INT8U  OSSafeVarDelete(char * name)
{
	INT8U err;
	OS_SAFE_VAR *safevar,*lastvar;
	OS_SAFE_RULE *saferule;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */
	if (name == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_VAR_INVALID_NAME\n");
#endif
		return OS_ERR_SAFE_VAR_INVALID_NAME;
	}
#endif
	/*查找安全变量地址*/
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
	/*回收该安全变量有关的所有规则和相应规则数据结构的内存*/
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

/*根据优先级清除安全变量*/
INT8U  OSSafeVarClear(INT8U Prio)
{
	INT8U err;
	OS_SAFE_VAR *safevar;
	OS_SAFE_RULE *saferule, *temprule;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */
	if (Prio < 0u || Prio > OS_LOWEST_PRIO) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_PRIO_INVALID\n");
#endif
		return OS_ERR_PRIO_INVALID;
	}
#endif
	/*清除该优先级下所有的安全变量*/
	while (OSSafeVars[Prio] != (OS_SAFE_VAR *)0) {
		safevar = OSSafeVars[Prio];
		OSSafeVars[Prio] = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next;
		sprintf(log_info, "请注意优先级为 %d 的任务中声明的安全变量 %s 没有相应的删除操作，任务结束自动删除。",Prio, ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name);
		recordLog("变量",log_info);
		saferule = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->OSRuleList;
		/*回收该安全变量有关的所有规则和相应规则数据结构的内存*/
		while(saferule != (OS_SAFE_RULE *)0) {
			temprule = saferule;/*回收规则期间会影响saferule*/
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
