#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

#define FILEPATH "C:/Windows/SysWOW64/aadtb.dll"
//#define FILEPATH "C:/Windows/System32/notepad.exe"

LPVOID ReadPEFile(LPSTR lpszFile);
void PrintNTHeaders();

int main(){
	PrintNTHeaders();
	return 0;
}


LPVOID ReadPEFile(LPSTR lpszFile) {
	FILE* pFile = NULL;
	DWORD fileSize = 0;
	LPVOID pFileBuffer = NULL;
	//打开文件	
	pFile = fopen(lpszFile, "rb");
	if (!pFile) {
		printf(" 无法打开文件! ");
		return NULL;
	}
	//读取文件大小		
	fseek(pFile, 0, SEEK_END);
	fileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);
	//分配缓冲区	
	pFileBuffer = malloc(fileSize);
	if (!pFileBuffer) {
		printf(" 分配空间失败! ");
		fclose(pFile);
		return NULL;
	}
	size_t n = fread(pFileBuffer, fileSize, 1, pFile);
	if (!n) {
		printf(" 读取数据失败! ");
		free(pFileBuffer);
		fclose(pFile);
		return NULL;
	}
	//关闭文件	
	fclose(pFile);
	return pFileBuffer;
}

void PrintNTHeaders() {
	LPVOID pFileBuffer = NULL;								//无类型指针，可接受任何类型
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	pFileBuffer = ReadPEFile(FILEPATH);
	if (!pFileBuffer) {
		printf("文件读取失败\n");
		return;
	}
	//判断是否是有效的MZ标志	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE) {		//winn.h中定义 IMAGE_DOS_SIGNATURE 为 0x5A4D
		printf("不是有效的MZ标志\n");
		free(pFileBuffer);
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//打印DOC头	
	printf("********************DOC头********************\n");
	printf("MZ标志：%x\n", pDosHeader->e_magic);
	printf("PE偏移：%x\n", pDosHeader->e_lfanew);
	//判断是否是有效的PE标志	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {	//有效NT头的判断
		printf("不是有效的PE标志\n");
		free(pFileBuffer);
		return;
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);			//在原地址基础上加上偏移，移到NT头
	//打印NT头	
	printf("********************NT头********************\n");
	printf("NT：%x\n", pNTHeader->Signature);					//打印NT头签名
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	printf("********************PE头********************\n");
	printf("PE：%x\n", pPEHeader->Machine);
	printf("节的数量：%x\n", pPEHeader->NumberOfSections);
	printf("时间戳：%x\n", pPEHeader->TimeDateStamp);
	printf("指向符号表：%x\n", pPEHeader->PointerToSymbolTable);
	printf("符号表中的符号数量：%x\n", pPEHeader->NumberOfSymbols);
	printf("可选PE头大小SizeOfOptionalHeader：%x\n", pPEHeader->SizeOfOptionalHeader);
	printf("文件属性：%x\n", pPEHeader->Characteristics);
	//可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);  //加上头部文件的大小
	printf("********************OPTIOIN_PE头********************\n");
	printf("OPTION_PE：%x\n", pOptionHeader->Magic);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//节表
	printf("********************节表信息********************\n");
	for (size_t i = 0; i < pPEHeader->NumberOfSections; i++) {
		printf("------------------节表%i------------------\n", i + 1);
		printf("名称：%s\n", pSectionHeader->Name);
		printf("真实尺寸：%.8x\n", pSectionHeader->Misc);
		printf("RVA地址：%.8x\n", pSectionHeader->VirtualAddress);
		printf("文件对齐后尺寸：%.8x\n", pSectionHeader->SizeOfRawData);
		printf("文件中偏移：%.8x\n", pSectionHeader->PointerToRawData);
		printf("行号表的位置：%.8x\n", pSectionHeader->PointerToLinenumbers);
		printf("重定位表个数：%.8x\n", pSectionHeader->NumberOfRelocations);
		printf("行号数量：%.8x\n", pSectionHeader->NumberOfLinenumbers);
		printf("节属性：%.8x\n", pSectionHeader->Characteristics);
		pSectionHeader++;
	}
	//释放内存	
	free(pFileBuffer);
}

