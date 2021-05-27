#define size  250       //安全数据区初始大小，单位为B,为了能用byte类型的数组模拟安全数据区的内存，size最大只能为255
#define min  4    //安全数据区最小内存块大小，单位为B
#define interval  2     //安全数据区等差递增内存块间隔，单位为B
#define max  8    //安全数据区等差递增最大内存块大小，单位为B，同时也是翻倍的内存块仓的大小的最小值
#define count  5     //安全数据区内存块种类的最大个数
#define sameblk  5     //安全数据区同种内存块的最大个数
#define mallocMax 10
#define RANDOM	(seed * 3 + 14) % 100	/* 计算随机数 */
short BlockNum[count] = {3,3,3};
byte  mem[size];       //模拟安全数据区的内存
byte  memParts[count*sameblk];//存放大小标签相同的空闲内存块的数组

chan mallocAddress = [mallocMax] of {byte};
byte wait_size=0;//待申请的内存空间大小
byte max_block=0;//安全数据区最大空闲块的可用大小
byte malloc_block_size=0;//已成功分配内存大小，每次分配成功增加，回收成功减少
byte left_block_size=size;//剩余未分配的有效内存大小，包括用于管理安全数据区的数据结构(实链)所占的空间和可以存放数据的空间，在分割与合并时根据程序行为动态更新
byte left_block_count=0;//剩余未分配的内存块个数，在分割与合并时根据程序行为动态更新

proctype memGet(byte length){
	atomic{
		wait_size = 0;
		byte blksize,pblk;
		byte part=0,list;//遍历用的数字
		do
			::(part<count)->
				if
					::(part>(max-min)/interval)->
						list=sameblk-1;
						do//从后面往前依次寻找空闲内存块数组
							::(list!=255&&list>=0)->
								if
									::(memParts[part*sameblk+list]!=255)->
										pblk = memParts[part*sameblk+list];
										if
											::mem[pblk+1]==255->blksize = size-pblk-2;
											::else->blksize = mem[pblk+1] - pblk -2;
										fi;
										if
											::blksize>=length->
												blksize = blksize - length;
												mallocAddress!pblk;
												left_block_count = left_block_count - 1;//更新剩余内存块个数
												printf("malloc %d byte @ %d,cuting\n",length,pblk);
												memParts[part*sameblk+list] = 255;
												goto cut;
											::else->list--;
										fi;
									::else->list--;
								fi;
							::(list==255)->
								if
									::(part==count-1)->
										wait_size = length;
										printf("fail malloc %d byte, no enough space!\n",length);
										goto done;
									::else->
										part++;
										break;
								fi;
						od;
					::(part<=(max-min)/interval)->
						blksize = min + interval * part;
						if
							::blksize<length->skip;
							::else->
								list=sameblk-1;
								do//从后面往前依次寻找空闲内存块数组
									::(list!=255&&list>=0)->
										if
											::(memParts[part*sameblk+list]!=255)->
												pblk = memParts[part*sameblk+list];
												mallocAddress!pblk;//将分配的内存首地址存入通道
												if
													::mem[pblk+1]==255->
														malloc_block_size = malloc_block_size + size - pblk;//更新已经分配的内存大小
														left_block_count = left_block_count - 1;//更新剩余内存块个数
														left_block_size = left_block_size + (size-pblk) + 2;
													::else->
														malloc_block_size = malloc_block_size + (mem[pblk+1] - pblk);//更新已经分配的内存大小
														left_block_count = left_block_count - 1;//更新剩余内存块个数
														left_block_size = left_block_size - (mem[pblk+1] - pblk) + 2;
												fi;	
												printf("malloc %d byte @ %d\n",length,memParts[part*sameblk+list]);
												memParts[part*sameblk+list] = 255;
												goto done;
											::else->list--;
										fi;
									::(list==255)->break;
								od;
						fi;
						part++;
				fi;
			::(part>=count)->
				wait_size = length;
				printf("fail malloc %d byte, no enough space!\n",length);
				goto done;
		od;
		cut://拆分内存块的程序
		if
			::(blksize - 2 > max)->//拆分之后还可以放入翻倍内存区
				if
					::blksize-2 > 2*max -> part = 4;
					::else->part = 3;
				fi;
				list=0;
				do//从前面往后依次寻找空闲内存块数组
					::(list<=sameblk-1)->
						if
							::(memParts[part*sameblk+list]==255)->
								memParts[part*sameblk+list]=pblk+2+length;
								if
									::mem[pblk+1]==255->skip;
									::else->mem[mem[pblk+1]+0] = pblk+2+length;
								fi;
								mem[pblk+2+length] = pblk;
								mem[pblk+2+length+1] = mem[pblk+1];
								mem[pblk+1] = pblk+2+length;
								malloc_block_size = malloc_block_size + 2+length;//更新已经分配的内存大小
								left_block_count = left_block_count + 1;////更新剩余内存块个数
								left_block_size = left_block_size - length - 2;
								goto done;
							::else->list++;
						fi;
					::(list>sameblk-1)->
						malloc_block_size = malloc_block_size + 2 + length + blksize;//更新已经分配的内存大小
						left_block_size = left_block_size - length - 2 - blksize;
						goto done;//当前大小的空闲内存数组已满，不再拆分
				od;
			::else->
				do
					::(blksize<2+min)->goto done;
					::(blksize>=2+min)->
						part = (blksize-2-min)/interval;
						list=0;
						do//从前面往后依次寻找空闲内存块数组
							::(list<=sameblk-1)->
								if
									::(memParts[part*sameblk+list]==255)->
										memParts[part*sameblk+list]=mem[pblk+1]-(min+part*interval)-2;
										if
											::mem[pblk+1]==255->skip;
											::else->mem[mem[pblk+1]+0] = mem[pblk+1]-(min+part*interval)-2;
										fi;
										mem[pblk+2+length] = pblk;
										mem[pblk+2+length+1] = mem[pblk+1];
										mem[pblk+1] = mem[pblk+1]-(min+part*interval)-2;
										blksize = blksize - (min+part*interval)-2;
										left_block_count = left_block_count + 1;//更新剩余内存块个数
										left_block_size = left_block_size - 2;
										goto cut;
									::else->list++;
								fi;
							::(list>sameblk-1)->
								malloc_block_size = malloc_block_size + 2 + length + blksize;//更新已经分配的内存大小
								left_block_size = left_block_size - length - 2 - blksize;
								goto done;//当前大小的空闲内存数组已满，不再拆分
						od;
				od;
		fi;
		done:
		//更新最大内存块的大小
		max_block = 0;
		part = count-1;
		do					
			::(part!=255&&part>=0)->
				if
					::memParts[sameblk*part]!=255 ->
						list = 0;
						do
							::(list<sameblk)->
								if
									::memParts[sameblk*part+list]==255->break;
									::else->
										if//计算最大的内存块的大小
											::mem[memParts[sameblk*part+list]+1]==255->
												blksize = size-memParts[sameblk*part+list]-2;
											::else->
												blksize = mem[memParts[sameblk*part+list]+1] - memParts[sameblk*part+list] -2;
										fi;
										if
											::blksize>max_block->max_block=blksize;
											::else->skip;
										fi;
										list++;
								fi
							::(list>=sameblk)->break;
						od;
						break;
					::else->part--;
				fi;
			::(part==255)->break;
		od;
	}
}	

proctype memPut(byte pblk) {
	atomic{
		bit left=1,right=1;//是否需要尝试合并左边和右边相邻的空闲内存块
		byte part=0,list,blksize;//遍历用的数字
		if
			::mem[pblk+1]==255->
				malloc_block_size = malloc_block_size - (size-pblk);//更新已经分配的内存大小
				left_block_count = left_block_count + 1;//更新剩余内存块个数
				left_block_size = left_block_size + (size-pblk) - 2;
			::else->
				malloc_block_size = malloc_block_size - (mem[pblk+1] - pblk);//更新已经分配的内存大小
				left_block_count = left_block_count + 1;//更新剩余内存块个数
				left_block_size = left_block_size + (mem[pblk+1] - pblk) - 2;
		fi;					
		merge:
		do
			::(left==1)->//合并左边相邻的空闲内存块
				if
					::mem[pblk]==255->
						left = 0;
						goto merge;
					::else->
						part = 0;
						do					
							::(part<count)->
								list = 0;
								do
									::(list<sameblk)->
										if
											::memParts[sameblk*part+list]==mem[pblk]->goto mergel;
											::else->list++;
										fi;
									::(list>=sameblk)->break;
								od;
								part++;
							::(part>=count)->
								left = 0;
								goto merge;
						od;
						mergel:
							if
								::part<=(max-min)/interval&&memParts[sameblk*part+BlockNum[part]]==255->//现有该大小内存块较少，取消合并
									left = 0;
									goto merge;
								::else->
									mem[mem[pblk]+1] = mem[pblk+1];
									if//物理相邻的下块是否为空
										::mem[pblk+1]==255->skip;
										::else->mem[mem[pblk+1]+0] = mem[pblk];
									fi;
									memParts[sameblk*part+list] = 255;
									part = pblk;
									pblk = mem[pblk];
									//清空物理相邻的上块保存的实链信息
									mem[part] = 0;
									mem[part+1] = 0;
									left_block_count = left_block_count - 1;//更新剩余内存块个数
									left_block_size = left_block_size + 2;
							fi;
				fi;
			::(right==1)->//合并右边相邻的空闲内存块
				if
					::mem[pblk+1]==255->
						right = 0;
						goto merge;
					::else->
						part = 0;
						do					
							::(part<count)->
								list = 0;
								do
									::(list<sameblk)->
										if
											::memParts[sameblk*part+list]==mem[pblk+1]->goto mergeR;
											::else->list++;
										fi;
									::(list>=sameblk)->break;
								od;
								part++;
							::(part>=count)->
								right = 0;
								goto merge;
						od;
						mergeR:
							if
								::part<=(max-min)/interval&&memParts[sameblk*part+BlockNum[part]]==255->//现有该大小内存块较少，取消合并
									right = 0;
									goto merge;
								::else->
									if//物理相邻的下下块是否为空
										::mem[mem[pblk+1]+1]==255->skip;
										::else->mem[mem[mem[pblk+1]+1]+0] = pblk;
									fi;
									memParts[sameblk*part+list] = 255;
									part = mem[pblk+1];
									mem[pblk+1] = mem[mem[pblk+1]+1];
									//清空物理相邻的下块保存的实链信息
									mem[part+0] = 0;
									mem[part+1] = 0;
									left_block_count = left_block_count - 1;////更新剩余内存块个数
									left_block_size = left_block_size + 2;
							fi;
				fi;
			::(right==0&&left==0)->
				if//计算要插入的内存块的大小
					::mem[pblk+1]==255->blksize = size-pblk-2;
					::else->blksize = mem[pblk+1] - pblk -2;
				fi;
				//将合并的内存块插入空闲链表
				if
					::(blksize > max)->//可以放入翻倍内存区
						if
							::blksize > 2*max -> part = 4;
							::else->part = 3;
						fi;
						list=0;
						do//从前面往后依次寻找空闲内存块数组
							::(list<=sameblk-1)->
								if
									::(memParts[part*sameblk+list]==255)->
										memParts[part*sameblk+list]=pblk;
										break;
									::else->list++;
								fi;
							::(list>sameblk-1)->
								printf("too many blocks @%d ,%d can't insert!\n",part,blksize);
								break;
						od;
					::else->
						part = (blksize-min)/interval;
						list=0;
						do//从前面往后依次寻找空闲内存块数组
							::(list<=sameblk-1)->
								if
									::(memParts[part*sameblk+list]==255)->
										memParts[part*sameblk+list]=pblk;
										break;
									::else->list++;
								fi;
							::(list>sameblk-1)->
								printf("too many blocks @%d ,%d can't insert!\n",part,blksize);
								break;
						od;
				fi;
				if
					::wait_size!=0&&blksize>=wait_size->
						printf("after merge %d can satisfy wait task!\n",blksize);
						run memGet(wait_size);
					::(wait_size==0||blksize<wait_size)&&blksize>max_block->max_block=blksize;
					::else->skip;
				fi;
				break;
		od;
	}
}

//随机进行分配和回收的操作
proctype memTest() {
	byte pblk=0;
	byte seed = 15;
	do
		::	mallocAddress?pblk;
			printf("free address @ %d.\n",pblk);
			run memPut(pblk);
		::wait_size!=0->
			run memGet(wait_size);
			if
				::wait_size!=0->
					printf("malloc %d space timeout!\n",wait_size);
					wait_size = 0;
				::else->skip;
			fi;
		::wait_size==0->
				::	seed = RANDOM;
					run memGet(seed);
				::	seed = RANDOM;
					run memGet(min+interval*(seed%3));
		::timeout->skip;
	od;
}

proctype memInit() {
	byte pblk=0,lastPhyBlk=255,blksize;
	byte part=0,list=0;//遍历用的数字
	do					//将空闲内存块数组初始化为空
		::(part<count)->
			list = 0;
			do
				::(list<sameblk)->
					memParts[sameblk*part+list]=255;
					list++;
				::(list>=sameblk)->break;
			od;
			part++;
		::(part>=count)->break;
	od;
	part = 0;
	do
		::(part<=(max-min)/interval)->
			blksize = min + part*interval;
			list = 0;
			do
				::(list<BlockNum[part])->
					mem[pblk] = lastPhyBlk;//将物理相连的链表地址写入
					mem[pblk+1] = pblk + blksize +2;
					memParts[part*sameblk+list] = pblk;//将内存块加入相应标签下的链表
					lastPhyBlk = pblk;
					pblk = pblk + 2 + blksize;
					list++;
					atomic{
						left_block_count = left_block_count + 1;////更新剩余内存块个数
						left_block_size = left_block_size - 2;
					}
				::(list>=BlockNum[part])->break;
			od;
			part++;
		::(part>(max-min)/interval)->break;
	od;
	printf("left %d byte\n",size-pblk);
	max_block = size-pblk-2;
	do
		::(part<count)->
			blksize = blksize*2;
			if
				::(blksize>=max_block||part==(count-1))->
					mem[pblk] = lastPhyBlk;//将物理相连的链表地址写入
					mem[pblk+1] = 255;
					memParts[part*sameblk] = pblk;//将内存块加入相应标签下的链表
					atomic{
						left_block_count = left_block_count + 1;//更新剩余内存块个数
						left_block_size = left_block_size - 2;
					}
					break;
				::else->skip
			fi;
			part++;
		::(part>=count)->break;
	od;
	//初始化安全数据区之后，开始分配和回收安全数据区的内存
	run memTest();
} 

init
{
	run memInit();
}

//当无法分配内存时，最大的空闲内存块小于等待申请内存块大小
#define correctMalloc (wait_size!=0->wait_size>max_block)
ltl e1 { []correctMalloc }   
//已成功分配内存大小+剩余未分配的有效内存大小+用于管理未分配的内存块的数据结构空间=安全数据区初始大小
#define sizeConservation (size==malloc_block_size+left_block_size+left_block_count*2)
ltl e2 { []sizeConservation }  


//内存分配回收之后，所有空闲内存块总大小等于安全数据区初始大小 
#define finalMerge (mem[1]==255)
ltl e3 { <> finalMerge }

ltl e4 { [] mem[1]!=249 }