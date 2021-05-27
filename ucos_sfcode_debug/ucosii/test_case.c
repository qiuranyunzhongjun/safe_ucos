#include "includes.h"
#include <time.h>
#include <assert.h>
#include <stdio.h>
#include <math.h>

#include <windows.h>

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

void use_after_free(void *name){
	char* input = "ucos";
	char *buf1R1 = (char *)malloc(5 * sizeof(char));
	char *buf2R1 = (char *)malloc(5 * sizeof(char));
	free(buf2R1);
	char *buf2R2 = (char *)malloc(2 * sizeof(char));
	strncpy(buf2R1, input, 5 * sizeof(char));
	free(buf1R1);
	free(buf2R2);
	puts(buf2R1);
}

void buffer_overflow(void *name) {
	char *s = "hello world";
	char *buf1 = (char *)malloc(5 * sizeof(char));
	strncpy(buf1, s, 12 * sizeof(char));
	puts(buf1);
}

void never_free_1(char* s) {
	int i;
	char *p = malloc(strlen(s)+1);
	for (i = 0; s[i] != '\0'; i++) {
		p[i] = s[i];
	}
	p[i] = s[i];
	for (i = 0; i<=sizeof(s); i++) {
		printf("%c\n", p[i]);
	}
	/* there's no free and p is a local variable */
	return;
}
void never_free(void *name){
	char *s = "hello";

	OSTaskCreate(never_free_1, s, &App1Task_Stk[App1Task_StkSize-1], App1Task_Prio);
	printf("等待2秒钟开始。\n");
	OSTimeDlyHMSM(0, 0, 2, 0);
	printf("等待2秒钟结束。\n");
}

void basicmath_small(void *name) {

	/*记录程序开始时间
	int start, end;
	start = clock();

	int i = 0;
	int res = 0;
	for ( ; i < 10000; i++) {
		res = res + 2 * i;
	}
	printf("最后res的值为:%d\n", res);
	end = clock();
	printf("程序开始%d,结束%d程序耗时：%dms\n", start,end,end-start);
	*/

	INT8U err;
	int temp = 0;
	int i;
	double run_time;
	LARGE_INTEGER time_start;	//开始时间
	LARGE_INTEGER time_over;	//结束时间
	double dqFreq;		//计时器频率
	LARGE_INTEGER f;	//计时器频率
	QueryPerformanceFrequency(&f);
	dqFreq = (double)f.QuadPart;
	QueryPerformanceCounter(&time_start);	//计时开始

	for (i=1; i <= 10000; i++ ) {
		temp = temp + 1;
	}
	
	QueryPerformanceCounter(&time_over);	//计时结束
	run_time = 1000000 * (time_over.QuadPart - time_start.QuadPart) / dqFreq;
	//乘以1000000把单位由秒化为微秒，精度为1000 000/（cpu主频）微秒
	printf("\nrun_time：%fus\n", run_time);
	printf("最后变量的值为: %d\n",temp);
}

void missing_null(void * name) {
	char *str = "hello world";
	char *buf3 = malloc(sizeof(char)*5);
	char *buf2 = malloc(sizeof(char) * 5);
	char *buf1 = malloc(sizeof(char) * 5);

	/* strncpy does not NUL terminate if buffer isnt large enough */
	strncpy(buf1, str, sizeof buf1);
	strncpy(buf2, "This", sizeof buf2);
	strcpy(buf3, buf1);         /* BAD */
	printf("result: %s", buf3);
}


void improper_bound_read(void* name) {
	char read_value;
	char *buf = malloc(sizeof(char) * 10);


	/*  BAD  */
	read_value = buf[12];
	printf("%c\n", read_value);
}

void proper_bound_read(void* name) {
	char read_value;
	char *buf = malloc(sizeof(char) * 10);


	/*  BAD  */
	read_value = buf[9];
	printf("%d\n", read_value);
}

void heap_based_buffer_overflow2(void *name) {
	char *buf = malloc(sizeof(char) * 10);
	/*  BAD  */
	buf[-4096] = 'A';
	/*-2会引发异常，-4096就不会耶*/
}

void heap_based_buffer_overflow1(void *name) {
	int *buf = malloc(sizeof(int)*10);
	/*  BAD  */
	buf[12] =12138;
	/*不会引发异常*/
}

int main_2(void)
{
	OSInit(); /* 系统初始化*/
			  /* 创建主任务*/


	//OSTaskCreate(use_after_free, "test case 6", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	//OSTaskCreate(buffer_overflow, "test case 7", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	//OSTaskCreate(never_free, "test case 98", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	//OSTaskCreate(basicmath_small, "basicmath_small", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	//OSTaskCreate(missing_null, "test case 100", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	OSTaskCreate(improper_bound_read, "test case 119", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	//OSTaskCreate(proper_bound_read, "test case 122", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	//OSTaskCreate(heap_based_buffer_overflow2, "test case 123", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	//OSTaskCreate(heap_based_buffer_overflow1, "test case 152", &MainTask_Stk[MainTask_StkSize - 1], MainTask_Prio);
	OSStart(); /* 开始任务调度*/

	return 0;
}
