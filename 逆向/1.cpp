#include<stdio.h>
#include<cstdlib>
#include<iostream>
#include<windows.h>
#include<winnt.h>
#include<string>
#include<string.h>

using namespace std;


DWORD Base;   //基地址
char filepath[100];


class FileOperate {
public:int CreatePEFile(char* FileName)
{
	HANDLE pFile;
	HANDLE pMap;

	pFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (!pFile)
		return 0;
	pMap = CreateFileMapping(pFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!pMap)
		return 0;

	LPVOID b;
	Base = (DWORD)MapViewOfFile(pMap, FILE_MAP_READ, 0, 0, 0);
	if (!Base){

		CloseHandle(pMap);
		CloseHandle(pFile);
		return 0;
	}
	return 1;
}
public:int IsPE()
{
	if (!Base)
		return 0;

	PIMAGE_DOS_HEADER pDH = (PIMAGE_DOS_HEADER)Base; //printf("%x,%x", pDH->e_magic,IMAGE_DOS_SIGNATURE);
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	PIMAGE_NT_HEADERS pNh = (PIMAGE_NT_HEADERS32)((DWORD)Base + pDH->e_lfanew);//printf("%x", pNh->Signature);
	if (pNh->Signature != IMAGE_NT_SIGNATURE)
		return 0;
	//cout << Base << pDH->e_magic << pNh->Signature;
	return 1;
}
public: PIMAGE_FILE_HEADER GetFileHeader(DWORD Based){//pe头

	if (!Based)
		return 0;
	PIMAGE_DOS_HEADER pDH = (PIMAGE_DOS_HEADER)Based;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;
	PIMAGE_NT_HEADERS pNH = (PIMAGE_NT_HEADERS32)((DWORD)Based + pDH->e_lfanew);
	if (pNH->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	PIMAGE_FILE_HEADER FileHeader = &(pNH->FileHeader);
	return FileHeader;
}
public:PIMAGE_OPTIONAL_HEADER GetOptionalHeader(DWORD Based)//可选头
{
	if (!Based)
		return 0;
	PIMAGE_DOS_HEADER pDH = (PIMAGE_DOS_HEADER)Based;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;
	PIMAGE_NT_HEADERS pNH = (PIMAGE_NT_HEADERS32)((DWORD)Based + pDH->e_lfanew);
	if (pNH->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &(pNH->OptionalHeader);
	return pOptionalHeader;
}
public: void ShowFileHeader() {
	PIMAGE_FILE_HEADER FileHeader = GetFileHeader(Base);

	printf("\n>>>>>>> Machine: 0x%lx", FileHeader->Machine);
	printf("\n>>>>>>> NumberOfSections: 0x%lx", FileHeader->NumberOfSections);
	printf("\n>>>>>>> NumberOfSymbols: 0x%lx", FileHeader->NumberOfSymbols);
	printf("\n>>>>>>> PointerToStmbolTable: 0x%lx", FileHeader->PointerToSymbolTable);
	printf("\n>>>>>>> SizeOfOptionalHeader: 0x%lx", FileHeader->SizeOfOptionalHeader);
	printf("\n>>>>>>> TimeDateStamp: 0x%lx\n>>>>>>> \ncommand:", FileHeader->TimeDateStamp);

}
public: void ShowOptionalHeader() {
	PIMAGE_OPTIONAL_HEADER OptionalHeader = GetOptionalHeader(Base);
	printf("\n>>>>>>> Magic: 0x%lx", OptionalHeader->Magic);
	printf("\n>>>>>>> AddressOfEntryPoint: 0x%lx", OptionalHeader->AddressOfEntryPoint);
	printf("\n>>>>>>> BaseOfCode: 0x%lx", OptionalHeader->BaseOfCode);
	printf("\n>>>>>>> BaseOfData: 0x%lx", OptionalHeader->BaseOfData);
	printf("\n>>>>>>> FileAlignment: 0x%lx", OptionalHeader->FileAlignment);
	printf("\n>>>>>>> SectionAlignmentL: 0x%lx", OptionalHeader->SectionAlignment);
	printf("\n>>>>>>> ImageBase: 0x%lx", OptionalHeader->ImageBase);
	printf("\n>>>>>>> SizeOfCode: 0x%lx", OptionalHeader->SizeOfCode);
	printf("\n>>>>>>> SizeOfHeader: 0x%lx", OptionalHeader->SizeOfHeaders);
	printf("\n>>>>>>> NumberOfRvaAndSizes: 0x%lx", OptionalHeader->NumberOfRvaAndSizes);
	printf("\n>>>>>>> CheckSum: 0x%lx", OptionalHeader->CheckSum);
	printf("\n>>>>>>> DataDirectory: 0x%lx", OptionalHeader->DataDirectory);
	printf("\n>>>>>>> DLLCharacteristics: 0x%lx", OptionalHeader->DllCharacteristics);
	printf("\n>>>>>>> LoaderFlags: 0x%lx", OptionalHeader->LoaderFlags);
	printf("\n>>>>>>> MajorImageVersion: 0x%lx", OptionalHeader->MajorImageVersion);
	printf("\n>>>>>>> Win32VersionValue: 0x%lx", OptionalHeader->Win32VersionValue);
	printf("\n>>>>>>> Subsysytem: 0x%lx", OptionalHeader->Subsystem);
	printf("\n>>>>>>> MajorImageVersion: 0x%lx", OptionalHeader->MajorImageVersion);
	printf("\n>>>>>>> MajorLinkerVersion: 0x%lx", OptionalHeader->MinorLinkerVersion);
	printf("\n>>>>>>> MinorOperatingSystemVersion: 0x%lx", OptionalHeader->MinorOperatingSystemVersion);
	printf("\n>>>>>>> NubirSubsystemVersion: 0x%lx", OptionalHeader->MinorSubsystemVersion);
	printf("\n>>>>>>> SizeOfHeapCommit: 0x%lx", OptionalHeader->SizeOfHeapCommit);
	printf("\n>>>>>>> NumberOfRvaAndSizes: 0x%lx", OptionalHeader->NumberOfRvaAndSizes);
	printf("\n>>>>>>> SizeOfHeapReserve: 0x%lx", OptionalHeader->SizeOfHeapReserve);
	printf("\n>>>>>>> SizeOfImage: 0x%lx", OptionalHeader->SizeOfImage);
	printf("\n>>>>>>> SizeOfInitializedData: 0x%lx", OptionalHeader->SizeOfInitializedData);
	printf("\n>>>>>>> SizeOfStackCommit: 0x%lx", OptionalHeader->SizeOfStackCommit);
	printf("\n>>>>>>> SizeOfStackReserve: 0x%lx", OptionalHeader->SizeOfStackReserve);
	printf("\n>>>>>>> SizeOfUnintializedData: 0x%lx\ncommand:", OptionalHeader->SizeOfUninitializedData);

}
};

class InteractiveMod {

public:void WelcomeLog()
{
	cout << "\n\n        - - - - - - - - - AirPe - - - - - - - - -\n\n";
	cout << "        - - - -                           - - - -\n\n";
	cout << "        - - - -          *  *  *          - - - -\n\n";
	cout << "        - - - -                           - - - -\n\n";
	cout << "        - - - - - - - - SysytemGo - - - - - - - -\n\n";
	cout << ">>>>>>> Please input the path of the PE file:";
	CommandIn();
}
public:void ShowCommand(){
	cout << "\n>>>>>>>       *^* Command List *^*\n>>>>>>> \n";
	cout << ">>>>>>> -h    for help --> this table\n" << ">>>>>>> -1    list the imformation of file header.";
	cout << "\n>>>>>>> -2    list the imformation of optional header.\n";
	CommandIn();
}
public:int CommandGetAndJudge()
{
	FileOperate File;
	string command;
	cin >> command;
	if (command == "-h")
		ShowCommand();
	else if (command == "-1")
		File.ShowFileHeader();
	else if (command == "-2")
		File.ShowOptionalHeader();
	else{
		ErrorReport(3); return 0;
	}
	return 1;
}
public:void ErrorReport(int a){
	if (a == 1){
		cout << "\n\n       Can not access to the file, maybe your file path is wrong.\n       ";
		exit(1);
	}
	if (a == 2) {
		cout << "       But this file isn't a pe file.\n       ";
		exit(1);
	}
	if (a == 3) {
		cout << "       Your use a wrong command.Please try again\n       ";
		CommandIn();
		return;
	}
}
public:void CommandIn() {
	cout << "command:";
}
};

int main(){
	FileOperate File;
	InteractiveMod IM;
	IM.WelcomeLog();
	cin >> filepath;
	if (!File.CreatePEFile(filepath)){	
		IM.ErrorReport(1);
	}
	cout << ">>>>>>> .\n>>>>>>> .\n>>>>>>> Success access to the file.\n>>>>>>> .\n>>>>>>> .\n>>>>>>> .       ";
	if (!File.IsPE()){
		IM.ErrorReport(2);
		char c = getchar();
		exit(1);
	}
	IM.ShowCommand();
	while (1) {
		IM.CommandGetAndJudge();
	}
}
