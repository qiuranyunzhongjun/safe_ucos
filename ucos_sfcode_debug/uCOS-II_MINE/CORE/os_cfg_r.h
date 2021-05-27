/*
*********************************************************************************************************
*                                                uC/OS-II
*                                          The Real-Time Kernel
*                                  uC/OS-II Configuration File for V2.8x
*
*                               (c) Copyright 2005-2009, Micrium, Weston, FL
*                                          All Rights Reserved
*
*
* File    : OS_CFG.H
* By      : Jean J. Labrosse
* Version : V2.91
*
* LICENSING TERMS:
* ---------------
*   uC/OS-II is provided in source form for FREE evaluation, for educational use or for peaceful research.
* If you plan on using  uC/OS-II  in a commercial product you need to contact Micri祄 to properly license
* its use in your product. We provide ALL the source code for your convenience and to help you experience
* uC/OS-II.   The fact that the  source is provided does  NOT  mean that you can use it without  paying a
* licensing fee.
*********************************************************************************************************
*/

#ifndef OS_CFG_H
#define OS_CFG_H


                                       /* ---------------------- MISCELLANEOUS ----------------------- */
#define OS_APP_HOOKS_EN           1u   /* Application-defined hooks are called from the uC/OS-II hooks */
#define OS_ARG_CHK_EN             1u   /* Enable (1) or Disable (0) argument checking                  */
#define OS_CPU_HOOKS_EN           1u   /* uC/OS-II hooks are found in the processor port files         */

#define OS_DEBUG_EN               1u   /* Enable(1) debug variables                                    */

#define OS_EVENT_MULTI_EN         1u   /* Include code for OSEventPendMulti()                          */
#define OS_EVENT_NAME_EN          1u   /* Enable names for Sem, Mutex, Mbox and Q                      */

#define OS_LOWEST_PRIO           63u   /* Defines the lowest priority that can be assigned ...         */
                                       /* ... MUST NEVER be higher than 254!                           */

#define OS_MAX_EVENTS            10u   /* Max. number of event control blocks in your application      */
#define OS_MAX_FLAGS              5u   /* Max. number of Event Flag Groups    in your application      */
#define OS_MAX_MEM_PART           5u   /* Max. number of memory partitions                             */
#define OS_MAX_QS                 4u   /* Max. number of queue control blocks in your application      */
#define OS_MAX_TASKS             20u   /* Max. number of tasks in your application, MUST be >= 2       */

#define OS_SCHED_LOCK_EN          1u   /* Include code for OSSchedLock() and OSSchedUnlock()           */

#define OS_TICK_STEP_EN           1u   /* Enable tick stepping feature for uC/OS-View                  */
#define OS_TICKS_PER_SEC        100u   /* Set the number of ticks in one second                        */


                                       /* --------------------- TASK STACK SIZE ---------------------- */
#define OS_TASK_TMR_STK_SIZE    128u   /* Timer      task stack size (# of OS_STK wide entries)        */
#define OS_TASK_STAT_STK_SIZE   128u   /* Statistics task stack size (# of OS_STK wide entries)        */
#define OS_TASK_IDLE_STK_SIZE   128u   /* Idle       task stack size (# of OS_STK wide entries)        */


                                       /* --------------------- TASK MANAGEMENT ---------------------- */
#define OS_TASK_CHANGE_PRIO_EN    1u   /*     Include code for OSTaskChangePrio()                      */
#define OS_TASK_CREATE_EN         1u   /*     Include code for OSTaskCreate()                          */
#define OS_TASK_CREATE_EXT_EN     1u   /*     Include code for OSTaskCreateExt()                       */
#define OS_TASK_DEL_EN            1u   /*     Include code for OSTaskDel()                             */
#define OS_TASK_NAME_EN           1u   /*     Enable task names                                        */
#define OS_TASK_PROFILE_EN        1u   /*     Include variables in OS_TCB for profiling                */
#define OS_TASK_QUERY_EN          1u   /*     Include code for OSTaskQuery()                           */
#define OS_TASK_REG_TBL_SIZE      1u   /*     Size of task variables array (#of INT32U entries)        */
#define OS_TASK_STAT_EN           1u   /*     Enable (1) or Disable(0) the statistics task             */
#define OS_TASK_STAT_STK_CHK_EN   1u   /*     Check task stacks from statistic task                    */
#define OS_TASK_SUSPEND_EN        1u   /*     Include code for OSTaskSuspend() and OSTaskResume()      */
#define OS_TASK_SW_HOOK_EN        1u   /*     Include code for OSTaskSwHook()                          */


                                       /* ----------------------- EVENT FLAGS ------------------------ */
#define OS_FLAG_EN                1u   /* Enable (1) or Disable (0) code generation for EVENT FLAGS    */
#define OS_FLAG_ACCEPT_EN         1u   /*     Include code for OSFlagAccept()                          */
#define OS_FLAG_DEL_EN            1u   /*     Include code for OSFlagDel()                             */
#define OS_FLAG_NAME_EN           1u   /*     Enable names for event flag group                        */
#define OS_FLAG_QUERY_EN          1u   /*     Include code for OSFlagQuery()                           */
#define OS_FLAG_WAIT_CLR_EN       1u   /* Include code for Wait on Clear EVENT FLAGS                   */
#define OS_FLAGS_NBITS           16u   /* Size in #bits of OS_FLAGS data type (8, 16 or 32)            */


                                       /* -------------------- MESSAGE MAILBOXES --------------------- */
#define OS_MBOX_EN                1u   /* Enable (1) or Disable (0) code generation for MAILBOXES      */
#define OS_MBOX_ACCEPT_EN         1u   /*     Include code for OSMboxAccept()                          */
#define OS_MBOX_DEL_EN            1u   /*     Include code for OSMboxDel()                             */
#define OS_MBOX_PEND_ABORT_EN     1u   /*     Include code for OSMboxPendAbort()                       */
#define OS_MBOX_POST_EN           1u   /*     Include code for OSMboxPost()                            */
#define OS_MBOX_POST_OPT_EN       1u   /*     Include code for OSMboxPostOpt()                         */
#define OS_MBOX_QUERY_EN          1u   /*     Include code for OSMboxQuery()                           */


                                       /* --------------------- MEMORY MANAGEMENT -------------------- */
#define OS_MEM_EN                 1u   /* Enable (1) or Disable (0) code generation for MEMORY MANAGER */
#define OS_MEM_NAME_EN            1u   /*     Enable memory partition names                            */
#define OS_MEM_QUERY_EN           1u   /*     Include code for OSMemQuery()                            */

#define OS_SAFEMEM_EN                 1u   /* Enable (1) or Disable (0) code generation for SAFEMEMORY MANAGER */
#define OS_SAFEMEMNAME_EN             1u   /*     Enable memory partition names                            */
#define OS_SAFEMEM_QUERY_EN           1u   /*     Include code for OSSafeMemQuery()                            */

                                       /* -------------------MY SAFE MEMORY MANAGEMENT -------------------- */
#define OS_SAFE_MEM_EN        1u   /* Enable (1) or Disable (0) code generation for MY SAFE MEMORY MANAGER 使能安全数据区*/
#define OS_SAFE_MEM_DETAIL_LOG_EN    1u   /* Enable (1) or Disable (0) code generation for MY SAFE MEMORY MANAGER 使能安全数据区详细的调试输出*/
#define OS_SAFE_MEM_DETAIL_OUT_EN    1u   /* Enable (1) or Disable (0) code generation for MY SAFE MEMORY MANAGER 使能安全数据区详细的调试输出*/
#define OS_SAFE_MEM_TOTAL_SIZE       1024u   /* 安全数据区初始大小，单位为B*/
#define OS_SAFE_MEM_BLOCK_MIN        8u   /* 安全数据区最小内存块大小，单位为B*/
#define OS_SAFE_MEM_BLOCK_INERVAl    4u   /* 安全数据区等差递增内存块间隔，单位为B*/
//#define OS_SAFE_MEM_BLOCK_NUM        2u   /* 安全数据区等差递增内存块,每种大小的初始数*/
#define OS_SAFE_MEM_BLOCK_MAX        20u   /* 安全数据区等差递增最大内存块大小，单位为B，同时也是翻倍的内存块仓的大小的翻倍基准值*/
#define OS_SAFE_MEM_BLOCK_COUNT      10u   /* 安全数据区内存块种类的最大个数*/

#define OS_SAFE_RULE_SIZE            256u   /* 解析后的规则的最大存储空间字节数*/
#define OS_SAFE_RULE_LOCK            10u   /* 解析规则的的时候需要加锁的安全变量最大数量*/

#define OS_SAFE_MEM_MERGE_EN      1u   /* Enable (1) or Disable  回收安全内存数据时是否合并安全内存*/
#define OS_SAFE_MEM_SIZE_PRIOR      1u   /* 回收安全内存后是否将回收的内存优先分配给满足条件的任务，而不是仅考虑优先级*/


                                       /* ---------------- MUTUAL EXCLUSION SEMAPHORES --------------- */
#define OS_MUTEX_EN               1u   /* Enable (1) or Disable (0) code generation for MUTEX          */
#define OS_MUTEX_ACCEPT_EN        1u   /*     Include code for OSMutexAccept()                         */
#define OS_MUTEX_DEL_EN           1u   /*     Include code for OSMutexDel()                            */
#define OS_MUTEX_QUERY_EN         1u   /*     Include code for OSMutexQuery()                          */


                                       /* ---------------------- MESSAGE QUEUES ---------------------- */
#define OS_Q_EN                   1u   /* Enable (1) or Disable (0) code generation for QUEUES         */
#define OS_Q_ACCEPT_EN            1u   /*     Include code for OSQAccept()                             */
#define OS_Q_DEL_EN               1u   /*     Include code for OSQDel()                                */
#define OS_Q_FLUSH_EN             1u   /*     Include code for OSQFlush()                              */
#define OS_Q_PEND_ABORT_EN        1u   /*     Include code for OSQPendAbort()                          */
#define OS_Q_POST_EN              1u   /*     Include code for OSQPost()                               */
#define OS_Q_POST_FRONT_EN        1u   /*     Include code for OSQPostFront()                          */
#define OS_Q_POST_OPT_EN          1u   /*     Include code for OSQPostOpt()                            */
#define OS_Q_QUERY_EN             1u   /*     Include code for OSQQuery()                              */


                                       /* ------------------------ SEMAPHORES ------------------------ */
#define OS_SEM_EN                 1u   /* Enable (1) or Disable (0) code generation for SEMAPHORES     */
#define OS_SEM_ACCEPT_EN          1u   /*    Include code for OSSemAccept()                            */
#define OS_SEM_DEL_EN             1u   /*    Include code for OSSemDel()                               */
#define OS_SEM_PEND_ABORT_EN      1u   /*    Include code for OSSemPendAbort()                         */
#define OS_SEM_QUERY_EN           1u   /*    Include code for OSSemQuery()                             */
#define OS_SEM_SET_EN             1u   /*    Include code for OSSemSet()                               */


                                       /* --------------------- TIME MANAGEMENT ---------------------- */
#define OS_TIME_DLY_HMSM_EN       1u   /*     Include code for OSTimeDlyHMSM()                         */
#define OS_TIME_DLY_RESUME_EN     1u   /*     Include code for OSTimeDlyResume()                       */
#define OS_TIME_GET_SET_EN        1u   /*     Include code for OSTimeGet() and OSTimeSet()             */
#define OS_TIME_TICK_HOOK_EN      1u   /*     Include code for OSTimeTickHook()                        */


                                       /* --------------------- TIMER MANAGEMENT --------------------- */
#define OS_TMR_EN                 1u   /* Enable (1) or Disable (0) code generation for TIMERS         */
#define OS_TMR_CFG_MAX           16u   /*     Maximum number of timers                                 */
#define OS_TMR_CFG_NAME_EN        1u   /*     Determine timer names                                    */
#define OS_TMR_CFG_WHEEL_SIZE     8u   /*     Size of timer wheel (#Spokes)                            */
#define OS_TMR_CFG_TICKS_PER_SEC 10u   /*     Rate at which timer management task runs (Hz)            */

#endif
	 	   	  		 			 	    		   		 		 	 	 			 	    		   	 			 	  	 		 				 		  			 		 					 	  	  		      		  	   		      		  	 		 	      		   		 		  	 		 	      		  		  		  
