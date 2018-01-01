---
layout: post
title: ELF文件解析 
---
ELF文件是Unix和类Unix操作系统下的二进制文件格式，想要学习Linux系统下信息安全的相关知识，ELF文件格式的学习是一道绕不过去的坎。本文就简要分析下ELF文件格式，用以记录ELF学习的点滴。
本文从以下几个模块来对ELF文件进行分析：
1.ELF文件头
2.程序头
3.节头
4.符号
5.重定位
6.动态链接
先来看ELF文件头的格式，ELF文件头由以下结构来描述
```C
typedef struct {
	   unsigned char e_ident[EI_NIDENT];
	   uint16_t      e_type;
	   uint16_t      e_machine;
	   uint32_t      e_version;
	   ElfN_Addr     e_entry;
	   ElfN_Off      e_phoff;
	   ElfN_Off      e_shoff;
	   uint32_t      e_flags;
	   uint16_t      e_ehsize;
	   uint16_t      e_phentsize;
	   uint16_t      e_phnum;
	   uint16_t      e_shentsize;
	   uint16_t      e_shnum;
	   uint16_t      e_shstrndx;
} ElfN_Ehdr;
```
接下来对该结构的成员进行解析：  
```C
e_ident	这是一个长度为16个字节的数组，前4个字节是一组魔数，用来识别该文件是否为ELF格式。
		第一个字节必须为ELFMAG0（0x7f）
		第二个字节必须为ELFMAG1（'E'）
		第三个字节必须为ELFMAG2（'L'）
		第四个字节必须为ELFMAG3（'F'）
		第五个字节为二进制文件类型
			0:无效的类型
			1:ELF32文件格式
			2:ELF64文件格式
		六个字节为二进制数据的存储模式
			0:未知的数据模式
			1:小端模式
			2:大端模式
		七个字节为版本号，一般为01
		八个字节为操作系统和ABI
		九个字节为ABI版本
		剩下的是补齐字节

e_type	这个成员变量定义了文件的类型
		ET_REL	重定位文件
		ET_EXEC	可执行文件
		ET_DYN	共享库
		ET_CORE	核心文件

e_machine	该成员指定了文件的运行平台
		EM_NONE		An unknown machine
		EM_M32		AT&T WE 32100
		EM_SPARC	Sun Microsystems SPARC
		EM_386 		Intel 80386
		EM_68K	   	Motorola 68000
		EM_88K	   	Motorola 88000
		EM_860	   	Intel 80860
		EM_MIPS		MIPS RS3000 (big-endian only)
		EM_PARISC	HP/PA
		EM_SPARC32PLUS SPARC with enhanced instruction set
		EM_PPC		PowerPC
		EM_PPC64	PowerPC 64-bit
		EM_S390&IBM S/390
		EM_ARM		Advanced RISC Machines
		EM_SH&emsp	Renesas SuperH
		EM_SPARCV9	SPARC v9 64-bit
		EM_IA_64	Intel Itanium
		EM_X86_64	AMD x86-64
		EM_VAX		DEC Vax

e_version	这个成员定义了文件的版本，一般都为EV_CURRENT (值为1)

e_entry		这个成员指定了程序的入口地址

e_phoff		这个成员指定了程序头的相对偏移

e_shoff		这个成员指定了节头的相对偏移

e_flags		这个成员存储处理器指定的flags，目前尚未由flags被定义，所以该值为0

e_ehsize	这个成员存储了ELF文件头的大小，单位是字节

e_phentsize	这个成员存储了程序头的大小（程序头可能有多个，这里只是存储一个程序头的大小）

e_phnum		这个成员存储了程序头的数量

e_shentsize	这个成员存储了节头的大小（这里只是单个节头的大小）

e_shnum		这个成员存储了节头的数量

e_shstrndx	这个成员存储了节头表中节名称的字符串表的下标
```
接下来是程序头的数据结构，如下所示
```C
 typedef struct {
               uint32_t   p_type;
               Elf32_Off  p_offset;
               Elf32_Addr p_vaddr;
               Elf32_Addr p_paddr;
               uint32_t   p_filesz;
               uint32_t   p_memsz;
               uint32_t   p_flags;
               uint32_t   p_align;
           } Elf32_Phdr;

           typedef struct {
               uint32_t   p_type;
               uint32_t   p_flags;
               Elf64_Off  p_offset;
               Elf64_Addr p_vaddr;
               Elf64_Addr p_paddr;
               uint64_t   p_filesz;
               uint64_t   p_memsz;
               uint64_t   p_align;
           } Elf64_Phdr;

p_type		这个成员表明了该段的类型，主要类型如下
				PT_LOAD		表明了这是个可加载段。可加载段只有两个，Text段和Data段，其中p_offset为0的是Text段，否则是Data段
				PT_DYNAMIC	指定动态链接信息
				PT_INTERP	指定作为解释程序调用的路径名字符串的位置和大小
				PT_NOTE		指定辅助信息的位置
				PT_SHLIB	保留类型
				PT_PHDR		指定程序头表在文件和内存的位置和大小。

p_offset	这个成员指定了段的偏移

p_vaddr		这个成员指定了段在内存中的虚拟地址

p_paddr		在于物理地址相关的系统中，这个成员保存段的物理地址，在BSD系统下，这个值必须为0

p_filesz	这个成员保存了段在文件中的大小

p_memsz		这个成员保存了段在内存中的大小

p_flags		这个成员保存来了段的属性
				PF_X	一个可执行段
				PF_W	一个可写段
				PF_R	一个可读段

p_align		这个成员存储了段在内存和文件中的对齐
```
接下来是节头的数据结构和简析	
```C
typedef struct {
               uint32_t   sh_name;
               uint32_t   sh_type;
               uint32_t   sh_flags;
               Elf32_Addr sh_addr;
               Elf32_Off  sh_offset;
               uint32_t   sh_size;
               uint32_t   sh_link;
               uint32_t   sh_info;
               uint32_t   sh_addralign;
               uint32_t   sh_entsize;
           } Elf32_Shdr;

           typedef struct {
               uint32_t   sh_name;
               uint32_t   sh_type;
               uint64_t   sh_flags;
               Elf64_Addr sh_addr;
               Elf64_Off  sh_offset;
               uint64_t   sh_size;
               uint32_t   sh_link;
               uint32_t   sh_info;
               uint64_t   sh_addralign;
               uint64_t   sh_entsize;
           } Elf64_Shdr;

sh_name		节名称字符串的偏移

sh_type		用于将节的内容和语义分类，具体的类型，在后面讲述程序链接时再做介绍

sh_flags	节支持的描述杂项属性的1位标志

sh_addr		如果这个节存在于一个进程的内存镜像中，那么这个成员就是该节在内存中的地址，否则该成员为0

sh_offset	该成员保存了节的偏移

sh_size		该成员保存了节的大小

sh_link		该成员保存来了节头表的链接下标

sh_info		该成员保存了附加信息

sh_addralign	该成员表示一个节是否存在对齐，值为0和1表示无对齐

sh_entsize	一些节具有固定大小的表，比如符号表。对于这些节，该成员给出了表的大小，对于一些没有固定表的节，该值为0
```
到这里，对于ELF文件也有了一个前期的认识，现在先用代码来对一个ELF文件进行解析，当然，只是解析本文提到的程序头表和节头表更为详细的信息，后面的博客会陆续给出。代码如下

在parse_elf.h文件中定义了结构体
```C
struct file_info {

	int fd;
	unsigned long long length;
	unsigned char *mem;
};
```
下面是parse_elf.c文件的代码
```C
#include <stdio.h>
#include <elf.h>
#include <string.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "parse_elf.h"


int read_to_memory(char *file_name, struct file_info *f_info)
{
	struct stat st;

	if (NULL == file_name || NULL == f_info)
		return -1;

	f_info->fd = open(file_name, O_RDONLY);
	if (f_info->fd < 0) {

		printf("Failed to open %s\n", file_name);
		return -1;
	}

	if (fstat(f_info->fd, &st) < 0) {

		printf("Failed to get file stat\n");
		return -1;
	}

	f_info->length = (unsigned long long)st.st_size;

	f_info->mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, f_info->fd, 0);
	if (MAP_FAILED == f_info->mem) {

		printf("mmap failed\n");
		return -1;
	}

	return 0;
}

bool is_elf(struct file_info *f_info)
{
	bool result = false;

	if (NULL != f_info && NULL != f_info->mem) {

		if (0x7f == *f_info->mem && strcmp(f_info->mem + 1, "ELF"))
			result = true;
	}

	return result;
}

int parse_elf_segment(struct file_info *f_info)
{
	int i = 0;
	Elf32_Ehdr *elf_header = NULL;
	Elf32_Phdr *elf_phdr = NULL;

	if (NULL == f_info)
		return -1;

	if (!is_elf(f_info)) {

		printf("It is not a elf file\n");
		return -1;
	}

	elf_header = (Elf32_Ehdr*)(f_info->mem);
	elf_phdr = (Elf32_Phdr*)(f_info->mem + elf_header->e_phoff);
	for (i = 0; i < elf_header->e_phnum; i ++) {

		switch (elf_phdr[i].p_type) {

			case PT_LOAD:
				//PT_LOAD类型的段只有Text和Data，偏移为0的是Text
				if (0 == elf_phdr[i].p_offset)
					printf("Text segment: 0x%x\n", elf_phdr[i].p_vaddr);
				else
					printf("Data segment: 0x%x\n", elf_phdr[i].p_vaddr);
				break;
			case PT_DYNAMIC:
				printf("Dynamic segment: 0x%x\n", elf_phdr[i].p_vaddr);
				break;
			case PT_INTERP:
				printf("Interp segment: 0x%x\n", elf_phdr[i].p_vaddr);
				break;
			case PT_NOTE:
				printf("Note segment: 0x%x\n", elf_phdr[i].p_vaddr);
				break;
			case PT_SHLIB:
				printf("Shlib segment: 0x%x\n", elf_phdr[i].p_vaddr);
				break;
			case PT_PHDR:
				printf("Phdr segment: 0x%x\n", elf_phdr[i].p_vaddr);
				break;
		}
	}

	return 0;
}

int parse_elf_section(struct file_info* f_info)
{
	int i = 0;
	Elf32_Ehdr *elf_ehdr = NULL;
	Elf32_Shdr *elf_shdr = NULL;
	char *string_table = NULL;

	if (NULL == f_info || NULL == f_info->mem)
		return -1;

	elf_ehdr = (Elf32_Ehdr*)(f_info->mem);
	elf_shdr = (Elf32_Shdr*)(f_info->mem + elf_ehdr->e_shoff);
	string_table = f_info->mem + elf_shdr[elf_ehdr->e_shstrndx].sh_offset;
	for (i = 1; i < elf_ehdr->e_shnum; i ++) {

		printf("Section %s, addr 0x%x\n", string_table + elf_shdr[i].sh_name, elf_shdr[i].sh_addr);
	}

	return 0;
}

void release_memory(struct file_info *f_info)
{
	if (NULL != f_info) {

		if (NULL != f_info->mem)
			munmap(f_info->mem, f_info->length);
		//close(f_info->fd);
	}
}

int main (int argc, char **argv)
{
	struct file_info f_info = {0};

	if (argc < 2) {

		printf("Please input a elf file\n");
		return -1;
	}

	read_to_memory(argv[1], &f_info);
	parse_elf_segment(&f_info);
	parse_elf_section(&f_info);
	release_memory(&f_info);

	return 0;
}

```

