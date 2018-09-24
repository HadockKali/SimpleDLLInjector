#include "pch.h"
#include <windows.h> 
#include <tlhelp32.h> 
#include <shlwapi.h> 
#include <conio.h> 
#include <stdio.h> 


#define WIN32_LEAN_AND_MEAN 
#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ) 

BOOL Inject(DWORD pID, const char * DLL_NAME);
DWORD GetTargetThreadIDFromProcName(const char * ProcName);

int main(int argc, char * argv[])
{
	// detinere PID 
	DWORD pID = GetTargetThreadIDFromProcName("Process.exe");

	// path full name 
	char buf[MAX_PATH] = { 0 };
	GetFullPathName("Example.dll", MAX_PATH, buf, NULL);
	printf(buf);
	printf("\n");

	// Inject our main dll 
	if (!Inject(pID, buf))
	{

		printf("DLL 404");
	}
	else {
		printf("DLL 200");
	}

	_getch();
	return 0;
}

BOOL Inject(DWORD pID, const char * DLL_NAME)
{
	HANDLE Proc;
	HMODULE hLib;
	char buf[50] = { 0 };
	LPVOID RemoteString, LoadLibAddy;

	if (!pID)
		return false;

	Proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
	if (!Proc)
	{
		sprintf(buf, "OpenProcess() failed: %d", GetLastError());
		//MessageBox(NULL, buf, "Loader", MB_OK); 
		printf(buf);
		return false;
	}

	LoadLibAddy = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

	// Aloca memorie 
	RemoteString = (LPVOID)VirtualAllocEx(Proc, NULL, strlen(DLL_NAME), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// scrie char/string in memoria alocata 
	WriteProcessMemory(Proc, (LPVOID)RemoteString, DLL_NAME, strlen(DLL_NAME), NULL);

	// Secventa de load 
	CreateRemoteThread(Proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddy, (LPVOID)RemoteString, NULL, NULL);

	CloseHandle(Proc);
	return true;
}

DWORD GetTargetThreadIDFromProcName(const char * ProcName)
{
	PROCESSENTRY32 pe;
	HANDLE thSnapShot;
	BOOL retval, ProcFound = false;

	thSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (thSnapShot == INVALID_HANDLE_VALUE)
	{
		//MessageBox meh vectori, "2MLoader", MB_OK); 
		printf("Error: Toolhelp snapshot vezi SC pentru CVE_2017_0921 bug!");
		return false;
	}

	pe.dwSize = sizeof(PROCESSENTRY32);

	retval = Process32First(thSnapShot, &pe);
	while (retval)
	{
		if (StrStrI(pe.szExeFile, ProcName))
		{
			return pe.th32ProcessID;
		}
		retval = Process32Next(thSnapShot, &pe);
	}
	return 0;
}

//Copyright (c) Hadock Copyright Holder All Rights Reserved.
