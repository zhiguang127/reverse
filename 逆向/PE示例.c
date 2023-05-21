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
	//���ļ�	
	pFile = fopen(lpszFile, "rb");
	if (!pFile) {
		printf(" �޷����ļ�! ");
		return NULL;
	}
	//��ȡ�ļ���С		
	fseek(pFile, 0, SEEK_END);
	fileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);
	//���仺����	
	pFileBuffer = malloc(fileSize);
	if (!pFileBuffer) {
		printf(" ����ռ�ʧ��! ");
		fclose(pFile);
		return NULL;
	}
	size_t n = fread(pFileBuffer, fileSize, 1, pFile);
	if (!n) {
		printf(" ��ȡ����ʧ��! ");
		free(pFileBuffer);
		fclose(pFile);
		return NULL;
	}
	//�ر��ļ�	
	fclose(pFile);
	return pFileBuffer;
}

void PrintNTHeaders() {
	LPVOID pFileBuffer = NULL;								//������ָ�룬�ɽ����κ�����
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	pFileBuffer = ReadPEFile(FILEPATH);
	if (!pFileBuffer) {
		printf("�ļ���ȡʧ��\n");
		return;
	}
	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE) {		//winn.h�ж��� IMAGE_DOS_SIGNATURE Ϊ 0x5A4D
		printf("������Ч��MZ��־\n");
		free(pFileBuffer);
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//��ӡDOCͷ	
	printf("********************DOCͷ********************\n");
	printf("MZ��־��%x\n", pDosHeader->e_magic);
	printf("PEƫ�ƣ�%x\n", pDosHeader->e_lfanew);
	//�ж��Ƿ�����Ч��PE��־	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) {	//��ЧNTͷ���ж�
		printf("������Ч��PE��־\n");
		free(pFileBuffer);
		return;
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);			//��ԭ��ַ�����ϼ���ƫ�ƣ��Ƶ�NTͷ
	//��ӡNTͷ	
	printf("********************NTͷ********************\n");
	printf("NT��%x\n", pNTHeader->Signature);					//��ӡNTͷǩ��
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	printf("********************PEͷ********************\n");
	printf("PE��%x\n", pPEHeader->Machine);
	printf("�ڵ�������%x\n", pPEHeader->NumberOfSections);
	printf("ʱ�����%x\n", pPEHeader->TimeDateStamp);
	printf("ָ����ű�%x\n", pPEHeader->PointerToSymbolTable);
	printf("���ű��еķ���������%x\n", pPEHeader->NumberOfSymbols);
	printf("��ѡPEͷ��СSizeOfOptionalHeader��%x\n", pPEHeader->SizeOfOptionalHeader);
	printf("�ļ����ԣ�%x\n", pPEHeader->Characteristics);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);  //����ͷ���ļ��Ĵ�С
	printf("********************OPTIOIN_PEͷ********************\n");
	printf("OPTION_PE��%x\n", pOptionHeader->Magic);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//�ڱ�
	printf("********************�ڱ���Ϣ********************\n");
	for (size_t i = 0; i < pPEHeader->NumberOfSections; i++) {
		printf("------------------�ڱ�%i------------------\n", i + 1);
		printf("���ƣ�%s\n", pSectionHeader->Name);
		printf("��ʵ�ߴ磺%.8x\n", pSectionHeader->Misc);
		printf("RVA��ַ��%.8x\n", pSectionHeader->VirtualAddress);
		printf("�ļ������ߴ磺%.8x\n", pSectionHeader->SizeOfRawData);
		printf("�ļ���ƫ�ƣ�%.8x\n", pSectionHeader->PointerToRawData);
		printf("�кű��λ�ã�%.8x\n", pSectionHeader->PointerToLinenumbers);
		printf("�ض�λ�������%.8x\n", pSectionHeader->NumberOfRelocations);
		printf("�к�������%.8x\n", pSectionHeader->NumberOfLinenumbers);
		printf("�����ԣ�%.8x\n", pSectionHeader->Characteristics);
		pSectionHeader++;
	}
	//�ͷ��ڴ�	
	free(pFileBuffer);
}

