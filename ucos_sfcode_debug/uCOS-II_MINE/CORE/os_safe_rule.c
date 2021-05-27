
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
*  ���ڲ�����ȫ��������ĺ���
*********************************************************************************************************
*/

#ifndef  OS_MASTER_FILE
#include <ucos_ii.h>
#endif
#include <math.h>

#if (OS_SAFE_MEM_EN > 0u)

INT32U ruleStack[OS_SAFE_RULE_SIZE];
INT32U opStack[OS_SAFE_RULE_SIZE];
double calStack[OS_SAFE_RULE_SIZE];/*������Ƶİ�ȫ�������Ŀռ��������*/
INT32U rule_top, op_top,cal_top;
OS_RULE_OP_PRI OP[] = { { "=",0 },{ ">",0 },{ "<",0 },{ ">=",0 },{ "<=",0 },
						{ "+",3 },{ "-",3 },{ "*",5 },{ "/",5 },
						{ "^",7 },{ "ln",7 },/*ln����ֻ�ܸ����ֻ���( ��[]֮��ֻ��������*/
						{ "(",10 },{ ")",10 },{ "[",10 },{ "]",10 } };
/*enum operations  {equal=0,gt, lt,get,let, add=11,sub,mult,div,power,ln};*/
/*֧�ֵ���ѧ���㣬֮��洢����ʱֻ�洢��Ӧ��ö��ֵ,��һ���ַ�Ϊ0˵����һ�������� Ϊ1˵����һ��������� Ϊ2˵����һ���Ǳ�����ַ*/

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
	//fwrite(log,sizeof(char), strlen(log), fp); //���뵽�ļ���
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
/*�����ַ��������ջ��������������ȹ�ϵ��Ƚϡ���������ַ����ȹ�ϵ���ڴ������ջ������������򽫸��������ջ���������ǵĻ����򽫴������ջ���������������ǵĻ����򽫴������ջ��������*/
void insertOP(char* op) {
	INT32U  OPindex = IndexofOP(op);
	if (op_top == 0 || OP[OPindex].pri > OP[opStack[op_top]].pri) {
		/*��������ַ����ȹ�ϵ���ڴ������ջ������������򽫸��������ջ��*/
		opStack[op_top] = OPindex;
		op_top++;
	}
	else if (strcmp(op, ")") == 0 && strcmp(OP[opStack[op_top]].op, ")") == 0) {
		op_top--;
	}
	else {
		while (op_top != 0 && OP[OPindex].pri <= OP[opStack[op_top]].pri) {
			ruleStack[rule_top] = -2;/*�ȼ�-2��������������*/
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
* Description : Ϊ���еİ�ȫ��������һ������
*
* Arguments   : rule     ��һ������������ַ��������а�����δ֪���������Ѿ������İ�ȫ����
*                        this function to either:
* Returns    : != (OS_SAFE_MEM *)0  ���������ڱ������ɵĵ��沨�����ʽ������ڴ��׵�ַ
*              == (OS_SAFE_MEM *)0  ����δ�����ɹ�.
*********************************************************************************************************
*/

INT8U  OSSafeRuleInsert(char * rule)
{
	OS_SAFE_MEM      *pSafeMem;
	INT32U  i = 0, j = 0, compare = -1,targetPrio=-1;
	INT8U  err;
	char value[32];/*������ʱ�������ڷ������ַ���*/
	OS_SAFE_VAR *safevar;
	OS_SAFE_VAR *needLockVars[OS_SAFE_RULE_LOCK];//��Ҫ������
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

#if OS_ARG_CHK_EN > 0u                                /* ��������Ч�� */
	if (rule == (char*)0) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
		recordLog("����","����Ĺ���Ϊ���ַ���");
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
		if (rule_top >= OS_SAFE_RULE_SIZE) {/*����Ĺ���ջ��С����*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨������Ĺ���Ҫ�ع��࣬�������Ĺ���%s�޷����������޸�Ԥ�����OS_SAFE_RULE_SIZE�ֶΡ�", log_info, i, rule, rule + i);
			recordLog("����", log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_RULE_SMALL_SIZE\n");
#endif
			return OS_ERR_SAFE_RULE_SMALL_SIZE;
		}
		/*���������е�����*/
		if (rule[i] >= '0' && rule[i] <= '9')
		{
			for (j = i + 1; rule[j] != '\0'; j++) {
				if (!(rule[j] >= '0' && rule[j] <= '9'))/*�ݲ�����С��*/
					break;
			}
			strncpy(value, rule + i, j - i);/*�������rule�ַ�����[i,j)λ��ȡ��ֵ��value*/
			value[j - i] = '\0';
			i = j;
			ruleStack[rule_top] = -1;/*�ȼ�-1�������������*/
			rule_top++;
			ruleStack[rule_top] = atoi(value);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s %d", log_info, ruleStack[rule_top]);
#endif
			rule_top++;
			continue;
		}
		else if (rule[i] == '>' || rule[i] == '<' || rule[i] == 'l') {
			/*���������е�˫�ַ������*/
			if (rule[i] == 'l'&&rule[i+1] == 'n'&&(rule[i+2] == '('|| rule[i+2] >= '0'&&rule[i + 2] <= '9')) {
				/*ln����ֻ�и����ֻ��������Ų��ǶԵ�*/ 
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
					sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨���Ѿ����˲��Ⱥ��жϣ�����������Ĳ��Ⱥ�%s�޷����������޸Ĺ���", log_info, i, rule, rule + i);
					recordLog("����",log_info);
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
		/*���������еĵ��ַ������*/
		if (rule[i] == '>' || rule[i] == '<' || rule[i] == '=' ) {
			if (compare != -1) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨���Ѿ����˲��Ⱥ��жϣ�����������Ĳ��Ⱥ�%s�޷����������޸Ĺ���", log_info, i, rule, rule + i);
				recordLog("����",log_info);
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
			if (rule[i] == '@') {/*�������������������еİ�ȫ����*/
				i++;
				/*��ȡĿ����������ȼ�*/
				if (rule[i] >= '0' && rule[i] <= '9')
				{
					for (j = i + 1; rule[j] != '\0'; j++) {
						if (!(rule[j] >= '0' && rule[j] <= '9'))/*�ݲ�����С��*/
							break;
					}
					strncpy(value, rule + i, j - i);/*�������rule�ַ�����[i,j)λ��ȡ��ֵ��value*/
					value[j - i] = '\0';
					targetPrio = atoi(value);
					if (targetPrio <0||targetPrio>OS_LOWEST_PRIO) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
						sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨��%s��ʶ�������ȼ�����������%d�����˲���ϵͳ֧�ֵ����ȼ���Χ�����޸Ĺ���", log_info, i, rule, rule + i,targetPrio);
						recordLog("����",log_info);
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
					sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨���������Ĺ���%sӦ������������������ָ���������ȼ���", log_info, i, rule,rule+i);
					recordLog("����",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
					OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
					return OS_ERR_SAFE_INVALID_RULE;
				}
				/*���˵��м�Ŀո�*/
				while (rule[i] == ' ') {
					i++;
				}
			}
			/*����������֧�ֵ��������������������һ���ǰ�ȫ�������������������*/
			for (j = i ; rule[j] != '\0'; j++) {
				if (!(rule[j] >= 'a'&&rule[j] <= 'z' || rule[j] >= 'A'&&rule[j] <= 'Z' || rule[j] == '_'))
					break;
			}
			if (j - i == 0) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨��������%sӦ�ý�����ȫ���������������ϱ���������׼�����޸Ĺ���", log_info, i, rule, rule + i);
				recordLog("����",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
				OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
				return OS_ERR_SAFE_INVALID_RULE;
			}
			else if (j - i > 31) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨��������%sҪ�����İ�ȫ�������������趨�����ȫ��������31�����޸Ĺ���", log_info, i, rule, rule + i);
				recordLog("����",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
				OS_Printf("OS_ERR_SAFE_VAR_NAME_LONG\n");
#endif
				return OS_ERR_SAFE_VAR_NAME_LONG;
			}
			strncpy(value, rule + i, j - i);/*�������rule�ַ�����[i,j)λ��ȡ��ֵ��value*/
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
						//��¼��Ҫ�����ı������ȹ���������֮��ͳһ��������������һ
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
								OS_Printf("OS_ERR_SAFE_RULE_LOCK_SMALL����������ʱ����OS_SAFE_RULE_LOCK���ù�С����������Ƿ���ȷ���߸���OS_SAFE_RULE_LOCK��\n");
#endif
								return OS_ERR_SAFE_RULE_LOCK_SMALL;
							}
						}
					}
					/*�жϱ����ǲ����������*/
					if (rule[i] == '[') {
						i++;
						/*���������е�����*/
						if (rule[i] >= '0' && rule[i] <= '9')
						{
							for (j = i + 1; rule[j] != '\0'; j++) {
								if (!(rule[j] >= '0' && rule[j] <= '9'))/*�ݲ�����С��*/
									break;
							}
							strncpy(value, rule + i, j - i);/*�������rule�ַ�����[i,j)λ��ȡ��ֵ��value*/
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
								sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨��������%s��Ҫ����]�����ư�ȫ�������ã����޸Ĺ���", log_info, i, rule, rule + i);
								recordLog("����",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
								OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
								return OS_ERR_SAFE_INVALID_RULE;
							}
						}
						else {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
							sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨��������%s��Ҫ��������ָ�������±꣬���޸Ĺ���", log_info, i, rule, rule + i);
							recordLog("����",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
							OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
							return OS_ERR_SAFE_INVALID_RULE;
						}
					}
					else {
						ruleStack[rule_top] = 0;/*�������ƫ�Ƶ�λ��*/
						rule_top++;
					}
					ruleStack[rule_top] = safevar;/*����Ҫ���ݰ�ȫ��������ȡ�׵�ַ*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
					sprintf(log_info, "%s 0X%X", log_info, ruleStack[rule_top]);
#endif
					rule_top++;
					for (j = 0; j < safe_var_count; j++) {
						if (safevars[j] == safevar)
							break;
					}
					if (j == safe_var_count) {/*��Ӱ�ȫ�������б��У�֮��Ϊ�б������а�ȫ��������ָ����������*/
						safevars[safe_var_count] = safevar;
						safe_var_count++;
					}
					break;
				}
			}
			if (safevar == (OS_SAFE_VAR *)0) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨��������%s��Ҫ������ȫ�����������ǰ�ȫ����%s����Ӧ���ȼ�����������δ���������޸Ĺ���", log_info, i, rule, rule + i,value);
				recordLog("����",log_info);
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
		ruleStack[rule_top] = -2;/*�ȼ�-2��������������*/
		rule_top++;
		ruleStack[rule_top] = opStack[i-1];
		rule_top++;
	}
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	recordLog("����","���������ϣ�������£�");
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
	//sprintf(log_info, "Ϊ��������ռ䣺%s", log_info);
	recordLog("����",log_info);
#endif
	pblk = OSSafeVarMemGet(sizeof(INT32U)*rule_top, &err);/*Ϊ��ȫ�����������밲ȫ�ڴ�*/

	tempblk = pblk + sizeof(OS_SAFE_MEM_BLOCK);
	if (err == OS_ERR_NONE) {
		for (i = 0; i < rule_top; i++) {
			*((INT32U*)tempblk) = ruleStack[i];
			tempblk += sizeof(INT32U);
		}
		/*��鵱ǰ��ȫ������ֵ�Ƿ�Υ���˹���*/
		err = OSSafeRuleCalculate(pblk);
		if (err == OS_ERR_NONE) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "��ӹ��� %s ʱδ������ͻ��", rule);
			recordLog("����",log_info);
#endif
			/*Ϊ�漰����ÿһ����ȫ��������һ��ָ������ָ��*/
			for (i = 0; i < safe_var_count; i++) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "Ϊ��ȫ����%s���ӹ�������", ((OS_SAFE_VAR *)((INT8U*)safevars[i] + sizeof(OS_SAFE_MEM_BLOCK)))->name);
				recordLog("����",log_info);
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
			//��ʱ����Ŀռ� �Ѿ�������ϣ�����׼����Ч֮ǰ�Ƚ�������һ
			for (j = 0; j < lockVarCount; j++) {
				OS_ENTER_CRITICAL();
				//((OS_SAFE_VAR *)((INT8U*)needLockVars[j] + sizeof(OS_SAFE_MEM_BLOCK)))->OSSafeVarType = 67108879;
				i = ((OS_SAFE_VAR *)((INT8U*)needLockVars[j] + sizeof(OS_SAFE_MEM_BLOCK)))->OSSafeVarType >> 26;//����ǰ6λ
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
	char value[32];/*������ʱ�������ڷ������ַ���*/
	OS_SAFE_VAR *safevar;
	OS_SAFE_VAR *needLockVars[OS_SAFE_RULE_LOCK];//��Ҫ������
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

#if OS_ARG_CHK_EN > 0u                                /* ��������Ч�� */
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
		if (rule_top >= OS_SAFE_RULE_SIZE) {/*����Ĺ���ջ��С����*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨������Ĺ���Ҫ�ع��࣬�������Ĺ���%s�޷����������޸�Ԥ�����OS_SAFE_RULE_SIZE�ֶΡ�", log_info, i, rule, rule + i);
			recordLog("����",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
			OS_Printf("OS_ERR_SAFE_RULE_SMALL_SIZE\n");
#endif
			return OS_ERR_SAFE_RULE_SMALL_SIZE;
		}
		/*���������е�����*/
		if (rule[i] >= '0' && rule[i] <= '9')
		{
			for (j = i + 1; rule[j] != '\0'; j++) {
				if (!(rule[j] >= '0' && rule[j] <= '9'))/*�ݲ�����С��*/
					break;
			}
			strncpy(value, rule + i, j - i);/*�������rule�ַ�����[i,j)λ��ȡ��ֵ��value*/
			value[j - i] = '\0';
			i = j;
			ruleStack[rule_top] = -1;/*�ȼ�-1�������������*/
			rule_top++;
			ruleStack[rule_top] = atoi(value);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s %d", log_info, ruleStack[rule_top]);
#endif
			rule_top++;
			continue;
		}
		else if (rule[i] == '>' || rule[i] == '<' || rule[i] == 'l') {
			/*���������е�˫�ַ������*/
			if (rule[i] == 'l'&&rule[i + 1] == 'n' && (rule[i + 2] == '(' || rule[i + 2] >= '0'&&rule[i + 2] <= '9')) {
				/*ln����ֻ�и����ֻ��������Ų��ǶԵ�*/
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
					sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨���Ѿ����˲��Ⱥ��жϣ�����������Ĳ��Ⱥ�%s�޷����������޸Ĺ���", log_info, i, rule, rule + i);
					recordLog("����",log_info);
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
		/*���������еĵ��ַ������*/
		if (rule[i] == '>' || rule[i] == '<' || rule[i] == '=') {
			if (compare != -1) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨���Ѿ����˲��Ⱥ��жϣ�����������Ĳ��Ⱥ�%s�޷����������޸Ĺ���", log_info, i, rule, rule + i);
				recordLog("����",log_info);
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
			if (rule[i] == '@') {/*�������������������еİ�ȫ����*/
				i++;
				/*��ȡĿ����������ȼ�*/
				if (rule[i] >= '0' && rule[i] <= '9')
				{
					for (j = i + 1; rule[j] != '\0'; j++) {
						if (!(rule[j] >= '0' && rule[j] <= '9'))/*�ݲ�����С��*/
							break;
					}
					strncpy(value, rule + i, j - i);/*�������rule�ַ�����[i,j)λ��ȡ��ֵ��value*/
					value[j - i] = '\0';
					targetPrio = atoi(value);
					if (targetPrio <0 || targetPrio>OS_LOWEST_PRIO) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
						sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨��%s��ʶ�������ȼ�����������%d�����˲���ϵͳ֧�ֵ����ȼ���Χ�����޸Ĺ���", log_info, i, rule, rule + i, targetPrio);
						recordLog("����",log_info);
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
					sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨���������Ĺ���%sӦ������������������ָ���������ȼ���", log_info, i, rule, rule + i);
					recordLog("����",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
					OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
					return OS_ERR_SAFE_INVALID_RULE;
				}
				/*���˵��м�Ŀո�*/
				while (rule[i] == ' ') {
					i++;
				}
			}
			/*����������֧�ֵ��������������������һ���ǰ�ȫ�������������������*/
			for (j = i; rule[j] != '\0'; j++) {
				if (!(rule[j] >= 'a'&&rule[j] <= 'z' || rule[j] >= 'A'&&rule[j] <= 'Z' || rule[j] == '_'))
					break;
			}
			if (j - i == 0) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨��������%sӦ�ý�����ȫ���������������ϱ���������׼�����޸Ĺ���", log_info, i, rule, rule + i);
				recordLog("����",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
				OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
				return OS_ERR_SAFE_INVALID_RULE;
			}
			else if (j - i > 31) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨��������%sҪ�����İ�ȫ�������������趨�����ȫ��������31�����޸Ĺ���", log_info, i, rule, rule + i);
				recordLog("����",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
				OS_Printf("OS_ERR_SAFE_VAR_NAME_LONG\n");
#endif
				return OS_ERR_SAFE_VAR_NAME_LONG;
			}
			strncpy(value, rule + i, j - i);/*�������rule�ַ�����[i,j)λ��ȡ��ֵ��value*/
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
						//��¼��Ҫ�����ı������ȹ���������֮��ͳһ��������������һ
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
								OS_Printf("OS_ERR_SAFE_VAR_NAME_LONG:��������ʱ����OS_SAFE_RULE_LOCK���ù�С����������Ƿ���ȷ���߸���OS_SAFE_RULE_LOCK��\n");
#endif
								return OS_ERR_SAFE_RULE_LOCK_SMALL;
							}
						}
					}
					/*�жϱ����ǲ����������*/
					if (rule[i] == '[') {
						i++;
						/*���������е�����*/
						if (rule[i] >= '0' && rule[i] <= '9')
						{
							for (j = i + 1; rule[j] != '\0'; j++) {
								if (!(rule[j] >= '0' && rule[j] <= '9'))/*�ݲ�����С��*/
									break;
							}
							strncpy(value, rule + i, j - i);/*�������rule�ַ�����[i,j)λ��ȡ��ֵ��value*/
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
								sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨��������%s��Ҫ����]�����ư�ȫ�������ã����޸Ĺ���", log_info, i, rule, rule + i);
								recordLog("����",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
								OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
								return OS_ERR_SAFE_INVALID_RULE;
							}
						}
						else {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
							sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨��������%s��Ҫ��������ָ�������±꣬���޸Ĺ���", log_info, i, rule, rule + i);
							recordLog("����",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
							OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
							return OS_ERR_SAFE_INVALID_RULE;
						}
					}
					else {
						ruleStack[rule_top] = 0;/*�������ƫ�Ƶ�λ��*/
						rule_top++;
					}
					ruleStack[rule_top] = safevar;/*����Ҫ���ݰ�ȫ��������ȡ�׵�ַ*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
					sprintf(log_info, "%s 0X%X", log_info, ruleStack[rule_top]);
#endif
					rule_top++;
					for (j = 0; j < safe_var_count; j++) {
						if (safevars[j] == safevar)
							break;
					}
					if (j == safe_var_count) {/*��Ӱ�ȫ�������б��У�֮��Ϊ�б������а�ȫ��������ָ����������*/
						safevars[safe_var_count] = safevar;
						safe_var_count++;
					}
					break;
				}
			}
			if (safevar == (OS_SAFE_VAR *)0) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "%s�ǽ�������ǰ�벿��%.*s��õģ����չ����﷨��������%s��Ҫ������ȫ�����������ǰ�ȫ����%s����Ӧ���ȼ�����������δ���������޸Ĺ���", log_info, i, rule, rule + i, value);
				recordLog("����",log_info);
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
		ruleStack[rule_top] = -2;/*�ȼ�-2��������������*/
		rule_top++;
		ruleStack[rule_top] = opStack[i - 1];
		rule_top++;
	}
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	recordLog("����", "���������ϣ�������£�");
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
	//sprintf(log_info, "Ϊ��������ռ䣺%s", log_info);
	recordLog("����",log_info);
#endif
	pblk = OSSafeVarMemPend(sizeof(INT32U)*rule_top,&new_timeout, &err);/*Ϊ��ȫ�����������밲ȫ�ڴ�*/

	tempblk = pblk + sizeof(OS_SAFE_MEM_BLOCK);
	if (err == OS_ERR_NONE) {
		for (i = 0; i < rule_top; i++) {
			*((INT32U*)tempblk) = ruleStack[i];
			tempblk += sizeof(INT32U);
		}
		/*��鵱ǰ��ȫ������ֵ�Ƿ�Υ���˹���*/
		err = OSSafeRuleCalculate(pblk);
		if (err == OS_ERR_NONE) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s����ӹ���ʱδ������ͻ��", rule);
			recordLog("����",log_info);
#endif
			/*Ϊ�漰����ÿһ����ȫ��������һ��ָ������ָ��*/
			for (i = 0; i < safe_var_count; i++) {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				sprintf(log_info, "Ϊ��ȫ����%s���ӹ�������", ((OS_SAFE_VAR *)((INT8U*)safevars[i] + sizeof(OS_SAFE_MEM_BLOCK)))->name);
				recordLog("����",log_info);
#endif
				if (timeout == 0) {/*ԭ������Ҫ���޵ȴ�*/
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
			//��ʱ����Ŀռ� �Ѿ�������ϣ�����׼����Ч֮ǰ�Ƚ�������һ
			for (j = 0; j < lockVarCount; j++) {
				OS_ENTER_CRITICAL();
				i = ((OS_SAFE_VAR *)((INT8U*)needLockVars[j] + sizeof(OS_SAFE_MEM_BLOCK)))->OSSafeVarType >> 26;//����ǰ6λ
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

#if OS_ARG_CHK_EN > 0u                                /* ��������Ч�� */
	if (rule == (void*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
		return OS_ERR_SAFE_INVALID_RULE;
	}
#endif
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	recordLog("����", "���������ʽ");
#endif
#if OS_SAFE_MEM_MERGE_EN == 0u
	for (tempblk = (INT8U*)rule + sizeof(OS_SAFE_MEM_BLOCK); tempblk < (((OS_SAFE_MEM_BLOCK*)rule)->OSNextPhyMemBlk == (void*)0 ? (INT8U*)OSSafeMem->OSSafeMemAddr + 5*OS_SAFE_MEM_TOTAL_SIZE : ((OS_SAFE_MEM_BLOCK*)rule)->OSNextPhyMemBlk); tempblk = (INT8U*)tempblk + sizeof(INT32U)) {
#else
	for (tempblk = (INT8U*)rule + sizeof(OS_SAFE_MEM_BLOCK); tempblk < (((OS_SAFE_MEM_BLOCK*)rule)->OSNextPhyMemBlk== (void*)0? (INT8U*)OSSafeMem->OSSafeMemAddr + OS_SAFE_MEM_TOTAL_SIZE : ((OS_SAFE_MEM_BLOCK*)rule)->OSNextPhyMemBlk); tempblk = (INT8U*)tempblk + sizeof(INT32U)) {
#endif
		if (*((INT32U*)tempblk) == -1) {/* ���� */
			tempblk = (INT8U*)tempblk + sizeof(INT32U);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s%d ", log_info, *((INT32U*)tempblk));
#endif
			calStack[cal_top] = *((INT32U*)tempblk);
			cal_top++;
		}
		else if (*((INT32U*)tempblk) == -2) {/* ����� */
			tempblk = (INT8U*)tempblk + sizeof(INT32U);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s%s ", log_info, OP[*((INT32U*)tempblk)].op);
#endif
			switch (*((INT32U*)tempblk)) {
			case 0:/*=*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
				recordLog("����",log_info);
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
				recordLog("����",log_info);
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
				recordLog("����",log_info);
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
				recordLog("����",log_info);
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
				recordLog("����",log_info);
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
					recordLog("����", "��������������,�����ȱ���㹻�Ĳ�����");
					recordLog("����",log_info);
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
					recordLog("����", "��������������,�����ȱ���㹻�Ĳ�����");
					recordLog("����",log_info);
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
					recordLog("����", "��������������,�����ȱ���㹻�Ĳ�����");
					recordLog("����",log_info);
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
					recordLog("����", "��������������,�����ȱ���㹻�Ĳ�����");
					recordLog("����",log_info);
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
					calStack[cal_top - 1] = pow(calStack[cal_top - 1] , calStack[cal_top]);/*�ǲ���Ҫ����һ��pow�������̫����*/
				}
				else {
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0
					recordLog("����", "��������������,�����ȱ���㹻�Ĳ�����");
					recordLog("����",log_info);
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
					recordLog("����", "��������������,�����ȱ���㹻�Ĳ�����");
					recordLog("����",log_info);
#endif
#if OS_SAFE_MEM_DETAIL_OUT_EN
					OS_Printf("OS_ERR_SAFE_RULE_NOT_FIT\n");
#endif
					return OS_ERR_SAFE_RULE_NOT_FIT;
				}
				break;
			default:
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0
				recordLog("����", "��������������,��֧�ֵ������");
				recordLog("����",log_info);
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
			switch (((OS_SAFE_VAR*)pblk)->OSSafeVarType & 33554431)/*2��25�η���һ  33554431=b00000001 11111111 11111111 11111111*/
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
			case 11:/*short����*/
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
				recordLog("����", "��������������,��֧�ֵĲ���������");
				recordLog("����",log_info);
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
/*Ӧ��Ҳ�������е���һ��*/
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	recordLog("����", "��������������,����Ľ�β");
	recordLog("����",log_info);
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

#if OS_ARG_CHK_EN > 0u                                /* ��������Ч�� */
	if (rule == (void*)0) {
#if OS_SAFE_MEM_DETAIL_OUT_EN
		OS_Printf("OS_ERR_SAFE_INVALID_RULE\n");
#endif
		return OS_ERR_SAFE_INVALID_RULE;
	}
#endif
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
	recordLog("����", "ɾ��������ʽ,�Ƚ������ù���Լ���İ�ȫ������ַ");
#endif
	for (tempblk = (INT8U*)rule + sizeof(OS_SAFE_MEM_BLOCK); tempblk < ((OS_SAFE_MEM_BLOCK*)rule)->OSNextPhyMemBlk; tempblk = (INT8U*)tempblk + sizeof(INT32U)) {
		if (*((INT32U*)tempblk) == -1 || *((INT32U*)tempblk) == -2) {
			tempblk = (INT8U*)tempblk + sizeof(INT32U);
		}
		else if (*((INT32U*)tempblk) >=0 ) {/* ��ȫ������ַ */
			tempblk = (INT8U*)tempblk + sizeof(INT32U);
#if OS_SAFE_MEM_DETAIL_LOG_EN > 0u
			sprintf(log_info, "%s0X%X ", log_info, *((INT32U*)tempblk));
#endif
			pblk = *((INT32U*)tempblk);
			for (j = 0; j < safe_var_count; j++) {
				if (safevars[j] == pblk)
					break;
			}
			if (j == safe_var_count) {/*��Ӱ�ȫ�������б��У�֮��Ϊ�б������а�ȫ����ɾ��ָ����������*/
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
	recordLog("����",log_info);
#endif
	/*Ϊ�漰����ÿһ����ȫ����ɾ��ָ������ָ��*/
	for (j = 0; j < safe_var_count; j++) {
		//���ȶ����������������ȼ��еı���������һ
		for (safevar = OSSafeVars[OSPrioCur]; safevar != (OS_SAFE_VAR *)0; safevar = ((OS_SAFE_VAR *)((INT8U*)safevar + sizeof(OS_SAFE_MEM_BLOCK)))->next) {
			if (safevar == safevars[j])
				break;
		}
		if (safevar == (OS_SAFE_VAR *)0) {
			//�����������������ȼ��еı���������һ
			OS_ENTER_CRITICAL();
			lockCount  = ((OS_SAFE_VAR *)((INT8U*)safevars[j] + sizeof(OS_SAFE_MEM_BLOCK)))->OSSafeVarType >> 26;//����ǰ6λ
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
				sprintf(log_info, "Ϊ��ȫ����%s�����������", ((OS_SAFE_VAR *)((INT8U*)safevars[j] + sizeof(OS_SAFE_MEM_BLOCK)))->name);
				recordLog("����",log_info);
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
	recordLog("����", "���չ���ռ�");
#endif
	err = OSSafeVarMemPut(rule);
	if (err != OS_ERR_NONE) {
		return err;
	}
	return OS_ERR_NONE;
}

#endif                                                    /* OS_SAFE_MEM_EN                                 */
