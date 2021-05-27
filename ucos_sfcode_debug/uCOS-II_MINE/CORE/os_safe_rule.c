
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
*  用于操作安全变量规则的函数
*********************************************************************************************************
*/

#ifndef  OS_MASTER_FILE
#include <ucos_ii.h>
#endif
#include <math.h>

#if (OS_SAFE_MEM_EN > 0u)

INT32U ruleStack[OS_SAFE_RULE_SIZE];
INT32U opStack[OS_SAFE_RULE_SIZE];
double calStack[OS_SAFE_RULE_SIZE];/*按照设计的安全变量最大的空间决定类型*/
INT32U rule_top, op_top,cal_top;
OS_RULE_OP_PRI OP[] = { { "=",0 },{ ">",0 },{ "<",0 },{ ">=",0 },{ "<=",0 },
						{ "+",3 },{ "-",3 },{ "*",5 },{ "/",5 },
						{ "^",7 },{ "ln",7 },/*ln后面只能跟数字或者( ，[]之间只能是数字*/
						{ "(",10 },{ ")",10 },{ "[",10 },{ "]",10 } };
/*enum operations  {equal=0,gt, lt,get,let, add=11,sub,mult,div,power,ln};*/
/*支持的数学运算，之后存储规则时只存储相应的枚举值,上一个字符为0说明下一个是数字 为1说明下一个是运算符 为2说明下一个是变量地址*/

void recordLog(char* type,char* loginfo) {
	FILE *fp; 
	char str[100];
	time_t t;
	struct tm *lt;
	t = time(NULL);
	lt = localtime(&t);
	strftime(str, 100, "\n %Y-%m-%d %H:%M:%S ;", lt);

	if ((fp = fopen("..\\..\\..\\log.csv", "a+")) == NULL)
		printf("log file cannot open \n");
	//fwrite(log,sizeof(char), strlen(log), fp); //输入到文件中
	fputs(str, fp);
	fputs(type, fp);
	fputs(";", fp);
	fputs(loginfo, fp);
	log_info[0] = '\0';
	if (fclose(fp) != 0)
		printf("log file cannot be closed \n");
}

int PRIofOP(char* name) {
	INT32U  i;
	for (i = 0; i < sizeof(OP) / sizeof(OS_RULE_OP_PRI); i++) {
		if (strcmp(OP[i].op, name) == 0)
			return OP[i].pri;
	}
	return -1;
}
int IndexofOP(char* name) {
	INT32U  i;
	for (i = 0; i < sizeof(OP) / sizeof(OS_RULE_OP_PRI); i++) {
		if (strcmp(OP[i].op, name) == 0)
			return i;
	}
	return -1;
}
int compareOP(char* op1, char* op2) {
	INT32U  i,pri1;
	for (i = 0; i < sizeof(OP) / sizeof(OS_RULE_OP_PRI); i++) {
		if (strcmp(OP[i].op, op1) == 0) {
			pri1 = OP[i].pri;
			break;
		}
	}
	for (i = 0; i < sizeof(OP) / sizeof(OS_RULE_OP_PRI); i++) {
		if (strcmp(OP[i].op, op2) == 0) {
			return  pri1 - OP[i].pri;
		}
	}
}
/*将该字符与运算符栈顶的运算符的优先关系相比较。如果，该字符优先关系高于此运算符栈顶的运算符，则将该运算符入栈。倘若不是的话，则将此运算符栈顶的运算倘若不是的话，则将此运算符栈顶的运算*/
void insertOP(char* op) {
	INT32U  OPindex = IndexofOP(op);
	if (op_top == 0 || OP[OPindex].pri > OP[opStack[op_top]].pri) {
		/*如果，该字符优先关系高于此运算符栈顶的运算符，则将该运算符入栈。*/
		opStack[op_top] = OPindex;
		op_top++;
	}
	else if (strcmp(op, ")") == 0 && strcmp(OP[opStack[op_top]].op, ")") == 0) {
		op_top--;
	}
	else {
		while (op_top != 0 && OP[OPindex].pri <= OP[opStack[op_top]].pri) {
			ruleStack[rule_top] = -2;/*先加-2代表后面是运算符*/
			rule_top++;
			ruleStack[rule_top] = opStack[op_top-1];
			rule_top++;
			op_top--;
		}
		opStack[op_top] = OPindex;
		op_top++;
	}
}
/*
*********************************************************************************************************
*                                        INSERT A RULE
*
* Description : 为已有的安全变量创建一条规则
*
* Arguments   : rule     是一个包含规则的字符串，其中包含的未知数必须是已经声明的安全变量
*                        this function to either:
* Returns    : != (OS_SAFE_MEM *)0  创建的用于保存生成的的逆波兰表达式规则的内存首地址
*              == (OS_SAFE_MEM *)0  规则未创建成功.
*********************************************************************************************************
*/

INT8U  OSSafeRuleInsert(char * rule)
{
	OS_SAFE_MEM      *pSafeMem;
	INT32U  i = 0, j = 0, compare = -1,targetPrio=-1;
	INT8U  err;
	char value[32];/*用于临时保存正在分析的字符串*/
	OS_SAFE_VAR *safevar;
	OS_SAFE_VAR *needLockVars[OS_SAFE_RULE_LOCK];//需要加锁的
	INT32U lockVarCount = 0;
	INT8U *pblk,*tempblk;
	INT32U *safevars[OS_SAFE_RULE_SIZE];
	INT32U safe_var_count=0;
	OS_SAFE_RULE *safeRule;
	op_top = 0;
	rule_top = 0;

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */
	if (rule == (char*)0) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
		recordLog("规则","插入的规则为空字符串");
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
		return OS_ERR_SAFE_INVALID_RULE;
	}
#endif
	for (i = 0; i < OS_SAFE_RULE_SIZE; i++) {
		safevars[i] = 0;
	}
	for (i = 0; i < 32; i++) {
		value[i] = '\0';
	}
	i = 0;
	while (rule[i] != '\0') {
		while (rule[i] == ' ') {
			i++;
		}
		if (rule[i] == '\0') {
			break;
		}
		if (rule_top >= OS_SAFE_RULE_SIZE) {/*定义的规则栈大小不够*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，插入的规则要素过多，接下来的规则%s无法解析，请修改预定义的OS_SAFE_RULE_SIZE字段。", log_info, i, rule, rule + i);
			recordLog("规则", log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_RULE_SMALL_SIZE\n");
#endif
			return OS_ERR_SAFE_RULE_SMALL_SIZE;
		}
		/*分析规则中的数字*/
		if (rule[i] >= '0' && rule[i] <= '9')
		{
			for (j = i + 1; rule[j] != '\0'; j++) {
				if (!(rule[j] >= '0' && rule[j] <= '9'))/*暂不考虑小数*/
					break;
			}
			strncpy(value, rule + i, j - i);/*将输入的rule字符串的[i,j)位截取赋值给value*/
			value[j - i] = '\0';
			i = j;
			ruleStack[rule_top] = -1;/*先加-1代表后面是数字*/
			rule_top++;
			ruleStack[rule_top] = atoi(value);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s %d", log_info, ruleStack[rule_top]);
#endif
			rule_top++;
			continue;
		}
		else if (rule[i] == '>' || rule[i] == '<' || rule[i] == 'l') {
			/*分析规则中的双字符运算符*/
			if (rule[i] == 'l'&&rule[i+1] == 'n'&&(rule[i+2] == '('|| rule[i+2] >= '0'&&rule[i + 2] <= '9')) {
				/*ln后面只有跟数字或者左括号才是对的*/ 
				insertOP("ln");
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s ln", log_info);
#endif
				i += 2;
				continue;
			}
			else if ((rule[i] == '>' || rule[i] == '<') && rule[i + 1] == '=') {
				if(compare != -1) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
					sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，已经有了不等号判断，接下来多余的不等号%s无法解析，请修改规则。", log_info, i, rule, rule + i);
					recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
					OS_Printf("OS_ERR_SAFE_RULE_MORE_CON\n");
#endif
					return OS_ERR_SAFE_RULE_MORE_CON;
				}
				if(rule[i] == '>'){
					compare = 3;
					insertOP(">=");
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
					sprintf(log_info, "%s >=", log_info);
#endif
				}
				else {
					compare = 4;
					insertOP("<=");
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
					sprintf(log_info, "%s <=", log_info);
#endif
				}
				i += 2;
				continue;
			}
		}
		/*分析规则中的单字符运算符*/
		if (rule[i] == '>' || rule[i] == '<' || rule[i] == '=' ) {
			if (compare != -1) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，已经有了不等号判断，接下来多余的不等号%s无法解析，请修改规则。", log_info, i, rule, rule + i);
				recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
				OS_Printf("OS_ERR_SAFE_RULE_MORE_CON\n");
#endif
				return OS_ERR_SAFE_RULE_MORE_CON;
			}
			if (rule[i] == '>') {
				compare = 1;
				insertOP(">");
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s >", log_info);
#endif
			}
			else if (rule[i] == '<') {
				compare = 2;
				insertOP(">");
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s <", log_info);
#endif
			}
			else{
				compare = 0;
				insertOP("=");
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s =", log_info);
#endif
			}
			i ++;
			continue;
		}
		else if (rule[i] == '+' || rule[i] == '-' || rule[i] == '*' || rule[i] == '/' || rule[i] == '^' || rule[i] == '(' || rule[i] == ')') {
			value[0] = rule[i];
			value[1] = '\0';
			insertOP(value);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s %s", log_info, value);
#endif
			i++;
			continue;
		}
		else {
			targetPrio = -1;
			if (rule[i] == '@') {/*可能是引用其他任务中的安全变量*/
				i++;
				/*提取目标任务的优先级*/
				if (rule[i] >= '0' && rule[i] <= '9')
				{
					for (j = i + 1; rule[j] != '\0'; j++) {
						if (!(rule[j] >= '0' && rule[j] <= '9'))/*暂不考虑小数*/
							break;
					}
					strncpy(value, rule + i, j - i);/*将输入的rule字符串的[i,j)位截取赋值给value*/
					value[j - i] = '\0';
					targetPrio = atoi(value);
					if (targetPrio <0||targetPrio>OS_LOWEST_PRIO) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
						sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，%s标识任务优先级的整型数字%d超过了操作系统支持的优先级范围，请修改规则。", log_info, i, rule, rule + i,targetPrio);
						recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
						OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
						return OS_ERR_SAFE_INVALID_RULE;
					}
					i = j;
				}
				else {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
					sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，接下来的规则%s应该首先输入整型数字指定任务优先级。", log_info, i, rule,rule+i);
					recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
					OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
					return OS_ERR_SAFE_INVALID_RULE;
				}
				/*过滤掉中间的空格*/
				while (rule[i] == ' ') {
					i++;
				}
			}
			/*分析完所有支持的运算符，接下来分析的一定是安全变量名，否则就有问题*/
			for (j = i ; rule[j] != '\0'; j++) {
				if (!(rule[j] >= 'a'&&rule[j] <= 'z' || rule[j] >= 'A'&&rule[j] <= 'Z' || rule[j] == '_'))
					break;
			}
			if (j - i == 0) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，接下来%s应该解析安全变量名，但不符合变量命名标准，请修改规则。", log_info, i, rule, rule + i);
				recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
				OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
				return OS_ERR_SAFE_INVALID_RULE;
			}
			else if (j - i > 31) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，接下来%s要解析的安全变量名超过了设定的最大安全变量长度31，请修改规则。", log_info, i, rule, rule + i);
				recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
				OS_Printf("OS_ERR_SAFE_VAR_NAME_LONG\n");
#endif
				return OS_ERR_SAFE_VAR_NAME_LONG;
			}
			strncpy(value, rule + i, j - i);/*将输入的rule字符串的[i,j)位截取赋值给value*/
			value[j - i] = '\0';
			i = j;
			if (targetPrio == -1) {
				safevar = OSSafeVars[OSPrioCur];
			}
			else {
				safevar = OSSafeVars[targetPrio];
			}
			for ( ; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
				if (strcmp(((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name, value) == 0) {
					if (targetPrio != -1) {
						//记录需要加锁的变量，等规则解析完毕之后统一进行锁的数量加一
						for (j = 0; j < lockVarCount; j++) {
							if (needLockVars[j] == safevar)
								break;
						}
						if (j == lockVarCount) {
							if (lockVarCount < OS_SAFE_RULE_LOCK) {
								needLockVars[lockVarCount++] = safevar;
							}
							else {
#if OS_SAFE_MEM_DETAIL_OUT_EN
								OS_Printf("OS_ERR_SAFE_RULE_LOCK_SMALL：解析规则时发现OS_SAFE_RULE_LOCK设置过小，请检查规则是否正确或者更改OS_SAFE_RULE_LOCK！\n");
#endif
								return OS_ERR_SAFE_RULE_LOCK_SMALL;
							}
						}
					}
					/*判断变量是不是数组变量*/
					if (rule[i] == '[') {
						i++;
						/*分析规则中的数字*/
						if (rule[i] >= '0' && rule[i] <= '9')
						{
							for (j = i + 1; rule[j] != '\0'; j++) {
								if (!(rule[j] >= '0' && rule[j] <= '9'))/*暂不考虑小数*/
									break;
							}
							strncpy(value, rule + i, j - i);/*将输入的rule字符串的[i,j)位截取赋值给value*/
							value[j - i] = '\0';
							i = j;
							ruleStack[rule_top] = atoi(value);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
							sprintf(log_info, "%s @%d", log_info, ruleStack[rule_top]);
#endif
							rule_top++;
							if (rule[i] == ']') {
								i++;
							}
							else {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
								sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，接下来%s需要符号]来完善安全数组引用，请修改规则。", log_info, i, rule, rule + i);
								recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
								OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
								return OS_ERR_SAFE_INVALID_RULE;
							}
						}
						else {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
							sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，接下来%s需要整型数字指定数组下标，请修改规则。", log_info, i, rule, rule + i);
							recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
							OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
							return OS_ERR_SAFE_INVALID_RULE;
						}
					}
					else {
						ruleStack[rule_top] = 0;/*代表变量偏移的位数*/
						rule_top++;
					}
					ruleStack[rule_top] = safevar;/*这里要根据安全变量名获取首地址*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
					sprintf(log_info, "%s 0X%X", log_info, ruleStack[rule_top]);
#endif
					rule_top++;
					for (j = 0; j < safe_var_count; j++) {
						if (safevars[j] == safevar)
							break;
					}
					if (j == safe_var_count) {/*添加安全变量到列表中，之后为列表中所有安全变量增加指向规则的引用*/
						safevars[safe_var_count] = safevar;
						safe_var_count++;
					}
					break;
				}
			}
			if (safevar == (OS_SAFE_VAR *)0) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，接下来%s需要解析安全变量名，但是安全变量%s在相应优先级的任务重尚未声明，请修改规则。", log_info, i, rule, rule + i,value);
				recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
				OS_Printf("OS_ERR_SAFE_VAR_NOT_EXIST\n");
#endif
				return OS_ERR_SAFE_VAR_NOT_EXIST;
			}
			continue;
		}
	}
	for (i = op_top; i >0 ; i--) {
		ruleStack[rule_top] = -2;/*先加-2代表后面是运算符*/
		rule_top++;
		ruleStack[rule_top] = opStack[i-1];
		rule_top++;
	}
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	recordLog("规则","规则解析完毕，结果如下：");
#endif
	for (i = 0; i < rule_top; i++) {
		if (ruleStack[i] == -1) {
			i++;
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s%d ", log_info,ruleStack[i]);
#endif
		}
		else if(ruleStack[i] == -2) {
			i++;
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s%s ", log_info, OP[ruleStack[i]].op);
#endif
		}
		else{
			i++;
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s 0X%X @%d  ", log_info, ruleStack[i], ruleStack[i - 1]);
#endif
		}
	}

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	//sprintf(log_info, "为规则申请空间：%s", log_info);
	recordLog("规则",log_info);
#endif
	pblk = OSSafeVarMemGet(sizeof(INT32U)*rule_top, &err);/*为安全变量规则申请安全内存*/

	tempblk = pblk + sizeof(OS_SAFE_MEM_BLOCK);
	if (err == OS_ERR_NONE) {
		for (i = 0; i < rule_top; i++) {
			*((INT32U*)tempblk) = ruleStack[i];
			tempblk += sizeof(INT32U);
		}
		/*检查当前安全变量的值是否违反了规则*/
		err = OSSafeRuleCalculate(pblk);
		if (err == OS_ERR_NONE) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "添加规则 %s 时未发生冲突。", rule);
			recordLog("规则",log_info);
#endif
			/*为涉及到的每一个安全变量增加一个指向规则的指针*/
			for (i = 0; i < safe_var_count; i++) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "为安全变量%s增加规则引用", ((OS_SAFE_VAR *)((INT8U*)safevars[i] + sizeof(OS_SAFE_MEM_BLOCK)))->name);
				recordLog("规则",log_info);
#endif
				safeRule = OSSafeVarMemGet(sizeof(OS_SAFE_RULE), &err);

				if (err == OS_ERR_NONE) {
					((OS_SAFE_RULE *)((INT8U*)safeRule + sizeof(OS_SAFE_MEM_BLOCK)))->next = ((OS_SAFE_VAR *)((INT8U*)safevars[i] + sizeof(OS_SAFE_MEM_BLOCK)))->OSRuleList;
					((OS_SAFE_RULE *)((INT8U*)safeRule + sizeof(OS_SAFE_MEM_BLOCK)))->rule = pblk;
					((OS_SAFE_VAR *)((INT8U*)safevars[i] + sizeof(OS_SAFE_MEM_BLOCK)))->OSRuleList = safeRule;
				}
				else {
					return err;
				}
			}
			//此时规则的空间 已经申请完毕，规则准备生效之前先将锁数加一
			for (j = 0; j < lockVarCount; j++) {
				OS_ENTER_CRITICAL();
				//((OS_SAFE_VAR *)((INT8U*)needLockVars[j] + sizeof(OS_SAFE_MEM_BLOCK)))->OSSafeVarType = 67108879;
				i = ((OS_SAFE_VAR *)((INT8U*)needLockVars[j] + sizeof(OS_SAFE_MEM_BLOCK)))->OSSafeVarType >> 26;//解析前6位
				i++;
				//printf("%d %d", ((OS_SAFE_VAR *)((INT8U*)needLockVars[j] + sizeof(OS_SAFE_MEM_BLOCK)))->OSSafeVarType, i);
				((OS_SAFE_VAR *)((INT8U*)needLockVars[j] + sizeof(OS_SAFE_MEM_BLOCK)))->OSSafeVarType = ((OS_SAFE_VAR *)((INT8U*)needLockVars[j] + sizeof(OS_SAFE_MEM_BLOCK)))->OSSafeVarType & 67108863 | (i << 26);
				OS_EXIT_CRITICAL();
			}
			return OS_ERR_NONE;
		}
		else {
			return err;
		}
	}
	else {
		return err;
	}
}

INT8U  OSSafeRuleInsertWait(char * rule, INT32U timeout)
{
	OS_SAFE_MEM      *pSafeMem;
	INT32U  i = 0, j = 0, compare = -1, targetPrio=-1;
	INT8U  err;
	INT32U new_timeout = timeout;
	char value[32];/*用于临时保存正在分析的字符串*/
	OS_SAFE_VAR *safevar;
	OS_SAFE_VAR *needLockVars[OS_SAFE_RULE_LOCK];//需要加锁的
	INT32U lockVarCount = 0;
	INT8U *pblk, *tempblk;
	INT32U *safevars[OS_SAFE_RULE_SIZE];
	INT32U safe_var_count = 0;
	OS_SAFE_RULE *safeRule = (OS_SAFE_RULE *)0;
	op_top = 0;
	rule_top = 0;
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
#endif

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */
	if (rule == (char*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
		return OS_ERR_SAFE_INVALID_RULE;
	}
#endif
	for (i = 0; i < OS_SAFE_RULE_SIZE; i++) {
		safevars[i] = 0;
	}
	for (i = 0; i < 32; i++) {
		value[i] = '\0';
	}
	i = 0;
	while (rule[i] != '\0') {
		while (rule[i] == ' ') {
			i++;
		}
		if (rule[i] == '\0') {
			break;
		}
		if (rule_top >= OS_SAFE_RULE_SIZE) {/*定义的规则栈大小不够*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，插入的规则要素过多，接下来的规则%s无法解析，请修改预定义的OS_SAFE_RULE_SIZE字段。", log_info, i, rule, rule + i);
			recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_RULE_SMALL_SIZE\n");
#endif
			return OS_ERR_SAFE_RULE_SMALL_SIZE;
		}
		/*分析规则中的数字*/
		if (rule[i] >= '0' && rule[i] <= '9')
		{
			for (j = i + 1; rule[j] != '\0'; j++) {
				if (!(rule[j] >= '0' && rule[j] <= '9'))/*暂不考虑小数*/
					break;
			}
			strncpy(value, rule + i, j - i);/*将输入的rule字符串的[i,j)位截取赋值给value*/
			value[j - i] = '\0';
			i = j;
			ruleStack[rule_top] = -1;/*先加-1代表后面是数字*/
			rule_top++;
			ruleStack[rule_top] = atoi(value);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s %d", log_info, ruleStack[rule_top]);
#endif
			rule_top++;
			continue;
		}
		else if (rule[i] == '>' || rule[i] == '<' || rule[i] == 'l') {
			/*分析规则中的双字符运算符*/
			if (rule[i] == 'l'&&rule[i + 1] == 'n' && (rule[i + 2] == '(' || rule[i + 2] >= '0'&&rule[i + 2] <= '9')) {
				/*ln后面只有跟数字或者左括号才是对的*/
				insertOP("ln");
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s ln", log_info);
#endif
				i += 2;
				continue;
			}
			else if ((rule[i] == '>' || rule[i] == '<') && rule[i + 1] == '=') {
				if (compare != -1) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
					sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，已经有了不等号判断，接下来多余的不等号%s无法解析，请修改规则。", log_info, i, rule, rule + i);
					recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
					OS_Printf("OS_ERR_SAFE_RULE_MORE_CON\n");
#endif
					return OS_ERR_SAFE_RULE_MORE_CON;
				}
				if (rule[i] == '>') {
					compare = 3;
					insertOP(">=");
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
					sprintf(log_info, "%s >=", log_info);
#endif
				}
				else {
					compare = 4;
					insertOP("<=");
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
					sprintf(log_info, "%s <=", log_info);
#endif
				}
				i += 2;
				continue;
			}
		}
		/*分析规则中的单字符运算符*/
		if (rule[i] == '>' || rule[i] == '<' || rule[i] == '=') {
			if (compare != -1) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，已经有了不等号判断，接下来多余的不等号%s无法解析，请修改规则。", log_info, i, rule, rule + i);
				recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
				OS_Printf("OS_ERR_SAFE_RULE_MORE_CON\n");
#endif
				return OS_ERR_SAFE_RULE_MORE_CON;
			}
			if (rule[i] == '>') {
				compare = 1;
				insertOP(">");
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s >", log_info);
#endif
			}
			else if (rule[i] == '<') {
				compare = 2;
				insertOP(">");
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s <", log_info);
#endif
			}
			else {
				compare = 0;
				insertOP("=");
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s =", log_info);
#endif
			}
			i++;
			continue;
		}
		else if (rule[i] == '+' || rule[i] == '-' || rule[i] == '*' || rule[i] == '/' || rule[i] == '^' || rule[i] == '(' || rule[i] == ')') {
			value[0] = rule[i];
			value[1] = '\0';
			insertOP(value);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s %s", log_info, value);
#endif
			i++;
			continue;
		}
		else {
			targetPrio = -1;
			if (rule[i] == '@') {/*可能是引用其他任务中的安全变量*/
				i++;
				/*提取目标任务的优先级*/
				if (rule[i] >= '0' && rule[i] <= '9')
				{
					for (j = i + 1; rule[j] != '\0'; j++) {
						if (!(rule[j] >= '0' && rule[j] <= '9'))/*暂不考虑小数*/
							break;
					}
					strncpy(value, rule + i, j - i);/*将输入的rule字符串的[i,j)位截取赋值给value*/
					value[j - i] = '\0';
					targetPrio = atoi(value);
					if (targetPrio <0 || targetPrio>OS_LOWEST_PRIO) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
						sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，%s标识任务优先级的整型数字%d超过了操作系统支持的优先级范围，请修改规则。", log_info, i, rule, rule + i, targetPrio);
						recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
						OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
						return OS_ERR_SAFE_INVALID_RULE;
					}
					i = j;
				}
				else {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
					sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，接下来的规则%s应该首先输入整型数字指定任务优先级。", log_info, i, rule, rule + i);
					recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
					OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
					return OS_ERR_SAFE_INVALID_RULE;
				}
				/*过滤掉中间的空格*/
				while (rule[i] == ' ') {
					i++;
				}
			}
			/*分析完所有支持的运算符，接下来分析的一定是安全变量名，否则就有问题*/
			for (j = i; rule[j] != '\0'; j++) {
				if (!(rule[j] >= 'a'&&rule[j] <= 'z' || rule[j] >= 'A'&&rule[j] <= 'Z' || rule[j] == '_'))
					break;
			}
			if (j - i == 0) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，接下来%s应该解析安全变量名，但不符合变量命名标准，请修改规则。", log_info, i, rule, rule + i);
				recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
				OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
				return OS_ERR_SAFE_INVALID_RULE;
			}
			else if (j - i > 31) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，接下来%s要解析的安全变量名超过了设定的最大安全变量长度31，请修改规则。", log_info, i, rule, rule + i);
				recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
				OS_Printf("OS_ERR_SAFE_VAR_NAME_LONG\n");
#endif
				return OS_ERR_SAFE_VAR_NAME_LONG;
			}
			strncpy(value, rule + i, j - i);/*将输入的rule字符串的[i,j)位截取赋值给value*/
			value[j - i] = '\0';
			i = j;
			if (targetPrio == -1) {
				safevar = OSSafeVars[OSPrioCur];
			}
			else {
				safevar = OSSafeVars[targetPrio];
			}
			for (; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
				if (strcmp(((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->name, value) == 0) {
					if (targetPrio != -1) {
						//记录需要加锁的变量，等规则解析完毕之后统一进行锁的数量加一
						for (j = 0; j < lockVarCount; j++) {
							if (needLockVars[j] == safevar)
								break;
						}
						if (j == lockVarCount) {
							if (lockVarCount < OS_SAFE_RULE_LOCK) {
								needLockVars[lockVarCount++] = safevar;
							}
							else {
#if OS_SAFE_MEM_DETAIL_OUT_EN
								OS_Printf("OS_ERR_SAFE_VAR_NAME_LONG:解析规则时发现OS_SAFE_RULE_LOCK设置过小，请检查规则是否正确或者更改OS_SAFE_RULE_LOCK！\n");
#endif
								return OS_ERR_SAFE_RULE_LOCK_SMALL;
							}
						}
					}
					/*判断变量是不是数组变量*/
					if (rule[i] == '[') {
						i++;
						/*分析规则中的数字*/
						if (rule[i] >= '0' && rule[i] <= '9')
						{
							for (j = i + 1; rule[j] != '\0'; j++) {
								if (!(rule[j] >= '0' && rule[j] <= '9'))/*暂不考虑小数*/
									break;
							}
							strncpy(value, rule + i, j - i);/*将输入的rule字符串的[i,j)位截取赋值给value*/
							value[j - i] = '\0';
							i = j;
							ruleStack[rule_top] = atoi(value);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
							sprintf(log_info, "%s @%d", log_info, ruleStack[rule_top]);
#endif
							rule_top++;
							if (rule[i] == ']') {
								i++;
							}
							else {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
								sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，接下来%s需要符号]来完善安全数组引用，请修改规则。", log_info, i, rule, rule + i);
								recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
								OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
								return OS_ERR_SAFE_INVALID_RULE;
							}
						}
						else {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
							sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，接下来%s需要整型数字指定数组下标，请修改规则。", log_info, i, rule, rule + i);
							recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
							OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
							return OS_ERR_SAFE_INVALID_RULE;
						}
					}
					else {
						ruleStack[rule_top] = 0;/*代表变量偏移的位数*/
						rule_top++;
					}
					ruleStack[rule_top] = safevar;/*这里要根据安全变量名获取首地址*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
					sprintf(log_info, "%s 0X%X", log_info, ruleStack[rule_top]);
#endif
					rule_top++;
					for (j = 0; j < safe_var_count; j++) {
						if (safevars[j] == safevar)
							break;
					}
					if (j == safe_var_count) {/*添加安全变量到列表中，之后为列表中所有安全变量增加指向规则的引用*/
						safevars[safe_var_count] = safevar;
						safe_var_count++;
					}
					break;
				}
			}
			if (safevar == (OS_SAFE_VAR *)0) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s是解析规则前半部分%.*s获得的，按照规则语法，接下来%s需要解析安全变量名，但是安全变量%s在相应优先级的任务重尚未声明，请修改规则。", log_info, i, rule, rule + i, value);
				recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
				OS_Printf("OS_ERR_SAFE_VAR_NOT_EXIST\n");
#endif
				return OS_ERR_SAFE_VAR_NOT_EXIST;
			}
			continue;
		}
	}
	for (i = op_top; i > 0; i--) {
		ruleStack[rule_top] = -2;/*先加-2代表后面是运算符*/
		rule_top++;
		ruleStack[rule_top] = opStack[i - 1];
		rule_top++;
	}
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	recordLog("规则", "规则解析完毕，结果如下：");
	log_info[0] = '\0';
#endif
	for (i = 0; i < rule_top; i++) {
		if (ruleStack[i] == -1) {
			i++;
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s%d ", log_info, ruleStack[i]);
#endif
		}
		else if (ruleStack[i] == -2) {
			i++;
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s%s ", log_info, OP[ruleStack[i]].op);
#endif
		}
		else {
			i++;
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s 0X%X @%d  ", log_info, ruleStack[i], ruleStack[i - 1]);
#endif
		}
	}

#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	//sprintf(log_info, "为规则申请空间：%s", log_info);
	recordLog("规则",log_info);
#endif
	pblk = OSSafeVarMemPend(sizeof(INT32U)*rule_top,&new_timeout, &err);/*为安全变量规则申请安全内存*/

	tempblk = pblk + sizeof(OS_SAFE_MEM_BLOCK);
	if (err == OS_ERR_NONE) {
		for (i = 0; i < rule_top; i++) {
			*((INT32U*)tempblk) = ruleStack[i];
			tempblk += sizeof(INT32U);
		}
		/*检查当前安全变量的值是否违反了规则*/
		err = OSSafeRuleCalculate(pblk);
		if (err == OS_ERR_NONE) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s：添加规则时未发生冲突。", rule);
			recordLog("规则",log_info);
#endif
			/*为涉及到的每一个安全变量增加一个指向规则的指针*/
			for (i = 0; i < safe_var_count; i++) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "为安全变量%s增加规则引用", ((OS_SAFE_VAR *)((INT8U*)safevars[i] + sizeof(OS_SAFE_MEM_BLOCK)))->name);
				recordLog("规则",log_info);
#endif
				if (timeout == 0) {/*原本就需要无限等待*/
					safeRule = OSSafeVarMemPend(sizeof(OS_SAFE_RULE), timeout, &err);
				}
				else if (new_timeout == 0u) {
					err == OS_ERR_TIMEOUT;
				}
				else {
					safeRule = OSSafeVarMemPend(sizeof(OS_SAFE_RULE), &new_timeout, &err);
				}
				if (err == OS_ERR_NONE) {
					((OS_SAFE_RULE *)((INT8U*)safeRule + sizeof(OS_SAFE_MEM_BLOCK)))->next = ((OS_SAFE_VAR *)((INT8U*)safevars[i] + sizeof(OS_SAFE_MEM_BLOCK)))->OSRuleList;
					((OS_SAFE_RULE *)((INT8U*)safeRule + sizeof(OS_SAFE_MEM_BLOCK)))->rule = pblk;
					((OS_SAFE_VAR *)((INT8U*)safevars[i] + sizeof(OS_SAFE_MEM_BLOCK)))->OSRuleList = safeRule;
				}
				else {
					return err;
				}
			}
			//此时规则的空间 已经申请完毕，规则准备生效之前先将锁数加一
			for (j = 0; j < lockVarCount; j++) {
				OS_ENTER_CRITICAL();
				i = ((OS_SAFE_VAR *)((INT8U*)needLockVars[j] + sizeof(OS_SAFE_MEM_BLOCK)))->OSSafeVarType >> 26;//解析前6位
				i++;
				((OS_SAFE_VAR *)((INT8U*)needLockVars[j] + sizeof(OS_SAFE_MEM_BLOCK)))->OSSafeVarType |= i << 26;
				OS_EXIT_CRITICAL();
			}
			return OS_ERR_NONE;
		}
		else {
			return err;
		}
	}
	else {
		return err;
	}
}

INT8U  OSSafeRuleCalculate(void *rule) {

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

	void  *tempblk;
	INT8U *pblk;
	INT32U arr_no;
	cal_top = 0;

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */
	if (rule == (void*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
		return OS_ERR_SAFE_INVALID_RULE;
	}
#endif
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	recordLog("规则", "计算规则表达式");
#endif
#if OS_SAFE_MEM_MERGE_EN == 0u
	for (tempblk = (INT8U*)rule + sizeof(OS_SAFE_MEM_BLOCK); tempblk < (((OS_SAFE_MEM_BLOCK*)rule)->OSNextPhyMemBlk == (void*)0 ? (INT8U*)OSSafeMem->OSSafeMemAddr + 5*OS_SAFE_MEM_TOTAL_SIZE : ((OS_SAFE_MEM_BLOCK*)rule)->OSNextPhyMemBlk); tempblk = (INT8U*)tempblk + sizeof(INT32U)) {
#else
	for (tempblk = (INT8U*)rule + sizeof(OS_SAFE_MEM_BLOCK); tempblk < (((OS_SAFE_MEM_BLOCK*)rule)->OSNextPhyMemBlk== (void*)0? (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE : ((OS_SAFE_MEM_BLOCK*)rule)->OSNextPhyMemBlk); tempblk = (INT8U*)tempblk + sizeof(INT32U)) {
#endif
		if (*((INT32U*)tempblk) == -1) {/* 数字 */
			tempblk = (INT8U*)tempblk + sizeof(INT32U);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s%d ", log_info, *((INT32U*)tempblk));
#endif
			calStack[cal_top] = *((INT32U*)tempblk);
			cal_top++;
		}
		else if (*((INT32U*)tempblk) == -2) {/* 运算符 */
			tempblk = (INT8U*)tempblk + sizeof(INT32U);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s%s ", log_info, OP[*((INT32U*)tempblk)].op);
#endif
			switch (*((INT32U*)tempblk)) {
			case 0:/*=*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				recordLog("规则",log_info);
#endif
				if (cal_top == 2 && calStack[0] == calStack[1]) {
					return OS_ERR_NONE;
				}
				else {
#if OS_SAFE_MEM_DETAIL_OUT_EN
					OS_Printf("OS_ERR_SAFE_RULE_NOT_FIT\n");
#endif
					return OS_ERR_SAFE_RULE_NOT_FIT;
				}
			case 1:/*>*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				recordLog("规则",log_info);
#endif
				if (cal_top == 2 && calStack[0] > calStack[1]) {
					return OS_ERR_NONE;
				}
				else {
#if OS_SAFE_MEM_DETAIL_OUT_EN
					OS_Printf("OS_ERR_SAFE_RULE_NOT_FIT\n");
#endif
					return OS_ERR_SAFE_RULE_NOT_FIT;
				}
			case 2:/*<*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				recordLog("规则",log_info);
#endif
				if (cal_top == 2 && calStack[0] < calStack[1]) {
					return OS_ERR_NONE;
				}
				else {
#if OS_SAFE_MEM_DETAIL_OUT_EN
					OS_Printf("OS_ERR_SAFE_RULE_NOT_FIT\n");
#endif
					return OS_ERR_SAFE_RULE_NOT_FIT;
				}
			case 3:/*>=*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				recordLog("规则",log_info);
#endif
				if (cal_top == 2 && calStack[0] >= calStack[1]) {
					return OS_ERR_NONE;
				}
				else {
#if OS_SAFE_MEM_DETAIL_OUT_EN
					OS_Printf("OS_ERR_SAFE_RULE_NOT_FIT\n");
#endif
					return OS_ERR_SAFE_RULE_NOT_FIT;
				}
			case 4:/*<=*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				recordLog("规则",log_info);
#endif
				if (cal_top == 2 && calStack[0] <= calStack[1]) {
					return OS_ERR_NONE;
				}
				else {
#if OS_SAFE_MEM_DETAIL_OUT_EN
					OS_Printf("OS_ERR_SAFE_RULE_NOT_FIT\n");
#endif
					return OS_ERR_SAFE_RULE_NOT_FIT;
				}
			case 5:/* + */
				if (cal_top >= 2) {
					cal_top--;
					calStack[cal_top - 1] = calStack[cal_top - 1] + calStack[cal_top];
					break;
				}
				else {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0
					recordLog("规则", "计算规则出现问题,运算符缺少足够的操作数");
					recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
					OS_Printf("OS_ERR_SAFE_RULE_NOT_FIT\n");
#endif
					return OS_ERR_SAFE_RULE_NOT_FIT;
				}
			case 6:/* - */
				if (cal_top >= 2) {
					cal_top--;
					calStack[cal_top - 1] = calStack[cal_top - 1] - calStack[cal_top];
				}
				else {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0
					recordLog("规则", "计算规则出现问题,运算符缺少足够的操作数");
					recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
					OS_Printf("OS_ERR_SAFE_RULE_NOT_FIT\n");
#endif
					return OS_ERR_SAFE_RULE_NOT_FIT;
				}
				break;
			case 7:/* * */
				if (cal_top >= 2) {
					cal_top--;
					calStack[cal_top - 1] = calStack[cal_top - 1] * calStack[cal_top];
				}
				else {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0
					recordLog("规则", "计算规则出现问题,运算符缺少足够的操作数");
					recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
					OS_Printf("OS_ERR_SAFE_RULE_NOT_FIT\n");
#endif
					return OS_ERR_SAFE_RULE_NOT_FIT;
				}
				break;
			case 8:/* / */
				if (cal_top >= 2) {
					cal_top--;
					calStack[cal_top - 1] = calStack[cal_top - 1] / calStack[cal_top];
				}
				else {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0
					recordLog("规则", "计算规则出现问题,运算符缺少足够的操作数");
					recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
					OS_Printf("OS_ERR_SAFE_RULE_NOT_FIT\n");
#endif
					return OS_ERR_SAFE_RULE_NOT_FIT;
				}
				break;
			case 9:/* ^ */
				if (cal_top >= 2) {
					cal_top--;
					calStack[cal_top - 1] = pow(calStack[cal_top - 1] , calStack[cal_top]);/*是不是要考虑一下pow函数结果太大了*/
				}
				else {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0
					recordLog("规则", "计算规则出现问题,运算符缺少足够的操作数");
					recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
					OS_Printf("OS_ERR_SAFE_RULE_NOT_FIT\n");
#endif
					return OS_ERR_SAFE_RULE_NOT_FIT;
				}
				break;
			case 10:/*ln*/
				if (cal_top >= 1) {
					calStack[cal_top - 1] = log(calStack[cal_top - 1]);
				}
				else {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0
					recordLog("规则", "计算规则出现问题,运算符缺少足够的操作数");
					recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
					OS_Printf("OS_ERR_SAFE_RULE_NOT_FIT\n");
#endif
					return OS_ERR_SAFE_RULE_NOT_FIT;
				}
				break;
			default:
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0
				recordLog("规则", "计算规则出现问题,不支持的运算符");
				recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
				OS_Printf("OS_ERR_SAFE_RULE_NOT_FIT\n");
#endif
				return OS_ERR_SAFE_RULE_NOT_FIT;
				break;
			}
		}
		else{
			arr_no = *((INT32U*)tempblk);
			tempblk = (INT8U*)tempblk + sizeof(INT32U);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s %s[%d] ", log_info, ((OS_SAFE_VAR *)((INT8U*)(*((INT32U*)tempblk)) + sizeof(OS_SAFE_MEM_BLOCK)))->name, arr_no);
#endif
			pblk = *((INT32U*)tempblk);
			pblk += sizeof(OS_SAFE_MEM_BLOCK);
			switch (((OS_SAFE_VAR*)pblk)->OSSafeVarType & 33554431)/*2的25次方减一  33554431=b00000001 11111111 11111111 11111111*/
			{
			case 1:/*short*/
				pblk += sizeof(OS_SAFE_VAR);
				calStack[cal_top] = *((short*)pblk);
				break;
			case 2:
				pblk += sizeof(OS_SAFE_VAR);
				calStack[cal_top] = *((int*)pblk);
				break;
			case 3:
				pblk += sizeof(OS_SAFE_VAR);
				calStack[cal_top] = *((long*)pblk);
				break;
			case 4:
				pblk += sizeof(OS_SAFE_VAR);
				calStack[cal_top] = *((float*)pblk);
				break;
			case 5:
				pblk += sizeof(OS_SAFE_VAR);
				calStack[cal_top] = *((double*)pblk);
				break;
			case 6:
				pblk += sizeof(OS_SAFE_VAR);
				calStack[cal_top] = *((char*)pblk);
				break;
			case 11:/*short数组*/
				pblk += sizeof(OS_SAFE_VAR);
				pblk += sizeof(short)*arr_no;
				calStack[cal_top] = *((short*)pblk);
				break;
			case 12:
				pblk += sizeof(OS_SAFE_VAR);
				pblk += sizeof(int)*arr_no;
				calStack[cal_top] = *((int*)pblk);
				break;
			case 13:
				pblk += sizeof(OS_SAFE_VAR);
				pblk += sizeof(long)*arr_no;
				calStack[cal_top] = *((long*)pblk);
				break;
			case 14:
				pblk += sizeof(OS_SAFE_VAR);
				pblk += sizeof(float)*arr_no;
				calStack[cal_top] = *((float*)pblk);
				break;
			case 15:
				pblk += sizeof(OS_SAFE_VAR);
				pblk += sizeof(double)*arr_no;
				calStack[cal_top] = *((double*)pblk);
				break;
			case 16:
				pblk += sizeof(OS_SAFE_VAR);
				pblk += sizeof(char)*arr_no;
				calStack[cal_top] = *((char*)pblk);
				break;
			default:
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0
				recordLog("规则", "计算规则出现问题,不支持的操作数类型");
				recordLog("规则",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
				OS_Printf("OS_ERR_SAFE_RULE_NOT_FIT\n");
#endif
				return OS_ERR_SAFE_RULE_NOT_FIT;
				break;
			}
			cal_top++;
		}
	}
/*应该也不会运行到这一步*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	recordLog("规则", "计算规则出现问题,错误的结尾");
	recordLog("规则",log_info);
#endif
	return OS_ERR_NONE;
}

INT8U  OSSafeRuleDelete(void * rule) {

#if OS_CRITICAL_METHOD == 3u                          /* Allocate storage for CPU status register      */
	OS_CPU_SR  cpu_sr = 0u;
#endif

	void  *tempblk;
	INT8U *pblk,err;
	INT32U *safevars[OS_SAFE_RULE_SIZE],j, safe_var_count=0,lockCount;
	OS_SAFE_VAR *safevar;
	OS_SAFE_RULE *safeRule,*lastRule,*tempRule;

#if OS_ARG_CHK_EN > 0u                                /* 检查参数有效性 */
	if (rule == (void*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
		return OS_ERR_SAFE_INVALID_RULE;
	}
#endif
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	recordLog("规则", "删除规则表达式,先解析出该规则约束的安全变量地址");
#endif
	for (tempblk = (INT8U*)rule + sizeof(OS_SAFE_MEM_BLOCK); tempblk < ((OS_SAFE_MEM_BLOCK*)rule)->OSNextPhyMemBlk; tempblk = (INT8U*)tempblk + sizeof(INT32U)) {
		if (*((INT32U*)tempblk) == -1 || *((INT32U*)tempblk) == -2) {
			tempblk = (INT8U*)tempblk + sizeof(INT32U);
		}
		else if (*((INT32U*)tempblk) >=0 ) {/* 安全变量地址 */
			tempblk = (INT8U*)tempblk + sizeof(INT32U);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s0X%X ", log_info, *((INT32U*)tempblk));
#endif
			pblk = *((INT32U*)tempblk);
			for (j = 0; j < safe_var_count; j++) {
				if (safevars[j] == pblk)
					break;
			}
			if (j == safe_var_count) {/*添加安全变量到列表中，之后为列表中所有安全变量删除指向规则的引用*/
				safevars[safe_var_count] = pblk;
				safe_var_count++;
			}
		}
		else {
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
			return OS_ERR_SAFE_INVALID_RULE;
		}
	}
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	recordLog("规则",log_info);
#endif
	/*为涉及到的每一个安全变量删除指向规则的指针*/
	for (j = 0; j < safe_var_count; j++) {
		//首先对所有其他任务优先级中的变量锁数减一
		for (safevar = OSSafeVars[OSPrioCur]; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			if (safevar == safevars[j])
				break;
		}
		if (safevar == (OS_SAFE_VAR *)0) {
			//对所有其他任务优先级中的变量锁数减一
			OS_ENTER_CRITICAL();
			lockCount  = ((OS_SAFE_VAR *)((INT8U*)safevars[j] + sizeof(OS_SAFE_MEM_BLOCK)))->OSSafeVarType >> 26;//解析前6位
			lockCount--;
			((OS_SAFE_VAR *)((INT8U*)safevars[j] + sizeof(OS_SAFE_MEM_BLOCK)))->OSSafeVarType |= lockCount << 26;
			OS_EXIT_CRITICAL();
		}
		lastRule = (OS_SAFE_RULE *)0;
		for (safeRule = ((OS_SAFE_VAR *)((INT8U*)safevars[j] + sizeof(OS_SAFE_MEM_BLOCK)))->OSRuleList; safeRule != (OS_SAFE_RULE *)0; ) {
			tempRule = safeRule;
			safeRule = ((OS_SAFE_RULE *)((INT8U*)safeRule + sizeof(OS_SAFE_MEM_BLOCK)))->next;
			if (((OS_SAFE_RULE *)((INT8U*)tempRule + sizeof(OS_SAFE_MEM_BLOCK)))->rule == rule) {
				if (lastRule == (OS_SAFE_RULE *)0) {
					((OS_SAFE_VAR *)((INT8U*)safevars[j] + sizeof(OS_SAFE_MEM_BLOCK)))->OSRuleList = ((OS_SAFE_RULE *)((INT8U*)tempRule + sizeof(OS_SAFE_MEM_BLOCK)))->next;
				}
				else {
					((OS_SAFE_RULE *)((INT8U*)lastRule + sizeof(OS_SAFE_MEM_BLOCK)))->next = ((OS_SAFE_RULE *)((INT8U*)tempRule + sizeof(OS_SAFE_MEM_BLOCK)))->next;
				}
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "为安全变量%s解除规则引用", ((OS_SAFE_VAR *)((INT8U*)safevars[j] + sizeof(OS_SAFE_MEM_BLOCK)))->name);
				recordLog("规则",log_info);
#endif
				err = OSSafeVarMemPut(tempRule);
				if (err != OS_ERR_NONE) {
					return err;
				}
				break;
			}
			else {
				lastRule = tempRule;
			}
		}
	}
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	recordLog("规则", "回收规则空间");
#endif
	err = OSSafeVarMemPut(rule);
	if (err != OS_ERR_NONE) {
		return err;
	}
	return OS_ERR_NONE;
}

#endif                                                    /* OS_SAFE_MEM_EN                                 */
