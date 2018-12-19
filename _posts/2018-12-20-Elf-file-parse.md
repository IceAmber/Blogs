---
layout: post
title: ELF�ļ����� 
---
ELF�ļ���Unix����Unix����ϵͳ�µĶ������ļ���ʽ����ҪѧϰLinuxϵͳ����Ϣ��ȫ�����֪ʶ��ELF�ļ���ʽ��ѧϰ��һ���Ʋ���ȥ�Ŀ������ľͼ�Ҫ������ELF�ļ���ʽ�����Լ�¼ELFѧϰ�ĵ�Ρ�
���Ĵ����¼���ģ������ELF�ļ����з�����
1.ELF�ļ�ͷ
2.����ͷ
3.��ͷ
4.����
5.�ض�λ
6.��̬����
������ELF�ļ�ͷ�ĸ�ʽ��ELF�ļ�ͷ�����½ṹ������
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
�������Ըýṹ�ĳ�Ա���н�����  
```C
e_ident	����һ������Ϊ16���ֽڵ����飬ǰ4���ֽ���һ��ħ��������ʶ����ļ��Ƿ�ΪELF��ʽ��
		��һ���ֽڱ���ΪELFMAG0��0x7f��
		�ڶ����ֽڱ���ΪELFMAG1��'E'��
		�������ֽڱ���ΪELFMAG2��'L'��
		���ĸ��ֽڱ���ΪELFMAG3��'F'��
		������ֽ�Ϊ�������ļ�����
			0:��Ч������
			1:ELF32�ļ���ʽ
			2:ELF64�ļ���ʽ
		�����ֽ�Ϊ���������ݵĴ洢ģʽ
			0:δ֪������ģʽ
			1:С��ģʽ
			2:���ģʽ
		�߸��ֽ�Ϊ�汾�ţ�һ��Ϊ01
		�˸��ֽ�Ϊ����ϵͳ��ABI
		�Ÿ��ֽ�ΪABI�汾
		ʣ�µ��ǲ����ֽ�

e_type	�����Ա�����������ļ�������
		ET_REL	�ض�λ�ļ�
		ET_EXEC	��ִ���ļ�
		ET_DYN	�����
		ET_CORE	�����ļ�

e_machine	�ó�Աָ�����ļ�������ƽ̨
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

e_version	�����Ա�������ļ��İ汾��һ�㶼ΪEV_CURRENT (ֵΪ1)

e_entry		�����Աָ���˳������ڵ�ַ

e_phoff		�����Աָ���˳���ͷ�����ƫ��

e_shoff		�����Աָ���˽�ͷ�����ƫ��

e_flags		�����Ա�洢������ָ����flags��Ŀǰ��δ��flags�����壬���Ը�ֵΪ0

e_ehsize	�����Ա�洢��ELF�ļ�ͷ�Ĵ�С����λ���ֽ�

e_phentsize	�����Ա�洢�˳���ͷ�Ĵ�С������ͷ�����ж��������ֻ�Ǵ洢һ������ͷ�Ĵ�С��

e_phnum		�����Ա�洢�˳���ͷ������

e_shentsize	�����Ա�洢�˽�ͷ�Ĵ�С������ֻ�ǵ�����ͷ�Ĵ�С��

e_shnum		�����Ա�洢�˽�ͷ������

e_shstrndx	�����Ա�洢�˽�ͷ���н����Ƶ��ַ�������±�
```
�������ǳ���ͷ�����ݽṹ��������ʾ
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

p_type		�����Ա�����˸öε����ͣ���Ҫ��������
				PT_LOAD		���������Ǹ��ɼ��ضΡ��ɼ��ض�ֻ��������Text�κ�Data�Σ�����p_offsetΪ0����Text�Σ�������Data��
				PT_DYNAMIC	ָ����̬������Ϣ
				PT_INTERP	ָ����Ϊ���ͳ�����õ�·�����ַ�����λ�úʹ�С
				PT_NOTE		ָ��������Ϣ��λ��
				PT_SHLIB	��������
				PT_PHDR		ָ������ͷ�����ļ����ڴ��λ�úʹ�С��

p_offset	�����Աָ���˶ε�ƫ��

p_vaddr		�����Աָ���˶����ڴ��е������ַ

p_paddr		���������ַ��ص�ϵͳ�У������Ա����ε������ַ����BSDϵͳ�£����ֵ����Ϊ0

p_filesz	�����Ա�����˶����ļ��еĴ�С

p_memsz		�����Ա�����˶����ڴ��еĴ�С

p_flags		�����Ա�������˶ε�����
				PF_X	һ����ִ�ж�
				PF_W	һ����д��
				PF_R	һ���ɶ���

p_align		�����Ա�洢�˶����ڴ���ļ��еĶ���
```
�������ǽ�ͷ�����ݽṹ�ͼ���	
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

sh_name		�������ַ�����ƫ��

sh_type		���ڽ��ڵ����ݺ�������࣬��������ͣ��ں��潲����������ʱ��������

sh_flags	��֧�ֵ������������Ե�1λ��־

sh_addr		�������ڴ�����һ�����̵��ڴ澵���У���ô�����Ա���Ǹý����ڴ��еĵ�ַ������ó�ԱΪ0

sh_offset	�ó�Ա�����˽ڵ�ƫ��

sh_size		�ó�Ա�����˽ڵĴ�С

sh_link		�ó�Ա�������˽�ͷ��������±�

sh_info		�ó�Ա�����˸�����Ϣ

sh_addralign	�ó�Ա��ʾһ�����Ƿ���ڶ��룬ֵΪ0��1��ʾ�޶���

sh_entsize	һЩ�ھ��й̶���С�ı�������ű�������Щ�ڣ��ó�Ա�����˱�Ĵ�С������һЩû�й̶���Ľڣ���ֵΪ0
```
���������ELF�ļ�Ҳ����һ��ǰ�ڵ���ʶ���������ô�������һ��ELF�ļ����н�������Ȼ��ֻ�ǽ��������ᵽ�ĳ���ͷ��ͽ�ͷ���Ϊ��ϸ����Ϣ������Ĳ��ͻ�½����������������

��parse_elf.h�ļ��ж����˽ṹ��
```C
struct file_info {

	int fd;
	unsigned long long length;
	unsigned char *mem;
};
```
������parse_elf.c�ļ��Ĵ���
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
				//PT_LOAD���͵Ķ�ֻ��Text��Data��ƫ��Ϊ0����Text
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

