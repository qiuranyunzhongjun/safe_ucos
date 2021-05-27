#include "includes.h"
#include <time.h>
#include <assert.h>
#include <stdio.h>
#include <math.h>

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

void my_use_after_free(void *name) {
	char* input = "ucos";
	OSSafeArrayCreate("buf1R1", "char", 5);
	OSSafeArrayCreate("buf2R1", "char", 5);
	OSSafeVarDelete("buf2R1");
	OSSafeArrayCreate("buf2R2", "char", 5);
	OSSafeArrayNoCheckNCopy("buf2R1", input, 5);
	OSSafeVarDelete("buf1R1");
	OSSafeVarDelete("buf2R2");
	OSSafeVarDelete("buf2R1");
}

void my_buffer_overflow(void *name) {
	char *s = "hello world";
	OSSafeArrayCreate("buf1", "char", 5);
	OSSafeArrayNoCheckNCopy("buf1", s, 12);
}

void my_never_free_1(char* s) {
	INT8U err;
	int i;
	OSSafeArrayCreate("p", "char", strlen(s)+1);
	for (i = 0; s[i] != '\0'; i++) {
		OSSafeArraySet("p", i, s[i]);
	}
	OSSafeArraySet("p", i, s[i]);
	for (i = 0; i <= sizeof(s); i++) {
		printf("%c\n", OSSafeArrayGet("p",i,&err)->char_value);
	}
	/* there's no free and p is a local variable */
	return;
}
void my_never_free(void *name) {
	char *s = "hello";

	OS_SAFE_MEM_DATA *psmf = malloc(sizeof(OS_SAFE_MEM_DATA)); 
	OSSafeVarMemQuery(psmf);
	printf("此时安全数据区总大小为：%dB，剩余可供分配的有效空间为：%dB\n", psmf->TotalSize, psmf->FreeSize);

	OSTaskCreate(my_never_free_1, s, &App1Task_Stk[App1Task_StkSize - 1], App1Task_Prio);
	printf("等待2秒钟开始。\n");
	OSTimeDlyHMSM(0, 0, 2, 0);
	printf("等待2秒钟结束。\n");

	OSSafeVarMemQuery(psmf);
	printf("此时安全数据区总大小为：%dB，剩余可供分配的有效空间为：%dB\n",psmf->TotalSize, psmf->FreeSize);
}

void my_basicmath_small(void *name) {

	INT8U err;
	int i;
	OSSafeVarCreate("temp", "int", 0);
	double run_time;
	LARGE_INTEGER time_start;	//开始时间
	LARGE_INTEGER time_over;	//结束时间
	double dqFreq;		//计时器频率
	LARGE_INTEGER f;	//计时器频率
	QueryPerformanceFrequency(&f);
	dqFreq = (double)f.QuadPart;
	QueryPerformanceCounter(&time_start);	//计时开始

	//for (OSSafeVarSet("i",1); OSSafeVarGet("i",&err)->int_value <= 10000; i++);	//要计时的程序
	for (i = 1; i <= 10000; i++ ) {
		OSSafeVarSet("temp", OSSafeVarGet("temp", &err)->int_value + 1);
	}

	QueryPerformanceCounter(&time_over);	//计时结束
	run_time = 1000000 * (time_over.QuadPart - time_start.QuadPart) / dqFreq;
	//乘以1000000把单位由秒化为微秒，精度为1000 000/（cpu主频）微秒
	printf("\nrun_time：%fus\n", run_time);
	printf("最后变量的值为: %d\n", OSSafeVarGet("temp", &err)->int_value);
}

void my_missing_null(void * name) {
	char *str = "hello world";
	OSSafeArrayCreate("buf3", "char", 5);
	OSSafeArrayCreate("buf2", "char", 5);
	OSSafeArrayCreate("buf1", "char", 5);

	OSSafeArrayNoCheckNCopy("buf1", str, 5); 
	OSSafeArrayNoCheckNCopy("buf2", "This", 5); 
	
	int i;
	INT8U err;
	printf("result: ");
	for (i = 0; OSSafeArrayGet("buf1", i, &err)->char_value != '\0'; i++) {
		OSSafeArraySet("buf3", i, OSSafeArrayGet("buf1", i, &err)->char_value);
		printf("%c", OSSafeArrayGet("buf3", i, &err)->char_value);
	}
}

/*
void my_stack_based_buffer_overflow1(void *name) {
	OSSafeArrayCreate("buf", "char", 10);
	OSSafeArraySet("buf", 12, 'A');
}
 */

void my_improper_bound_read(void* name) {
	INT8U err;
	char read_value;
	OSSafeArrayCreate("buf", "char", 10);


	/*  BAD  */
	read_value = OSSafeArrayGet("buf", 12, &err)->char_value;
	printf("%c\n", read_value);
}

void my_proper_bound_read(void* name) {
	INT8U err;
	char read_value;
	OSSafeArrayCreate("buf", "char", 10);
	read_value = OSSafeArrayGet("buf", 9, &err)->char_value;
	printf("%d\n", read_value);
}

void my_heap_based_buffer_overflow2(void *name) {
	OSSafeArrayCreate("buf", "char", 10);
	/*  BAD  */
	OSSafeArraySet("buf", -4096, 'A');
}

void my_heap_based_buffer_overflow1(void *name) {
	OSSafeArrayCreate("buf", "int", 10);
	/*  BAD  */
	OSSafeArraySet("buf", 12, 12138);
}

int main(void)
{
	OSInit(); /* 系统初始化*/
			  /* 创建主任务*/


	//OSTaskCreate(my_use_after_free, "test case 6", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	//OSTaskCreate(my_buffer_overflow, "test case 7", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	//OSTaskCreate(my_never_free, "test case 98", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	//OSTaskCreate(my_basicmath_small, "my_basicmath_small", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	//OSTaskCreate(my_missing_null, "test case 100", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	//OSTaskCreate(my_stack_based_buffer_overflow1, "test case 115", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	//OSTaskCreate(my_improper_bound_read, "test case 119", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	//OSTaskCreate(my_proper_bound_read, "test case 122", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	//OSTaskCreate(my_heap_based_buffer_overflow2, "test case 123", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	OSTaskCreate(my_heap_based_buffer_overflow1, "test case 152", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	/*179开始有多维数组*/
	OSStart(); /* 开始任务调度*/

	return 0;
}