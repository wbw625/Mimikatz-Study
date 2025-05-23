#pragma once
#include "sekurlsa.h"


VOID LocateUnprotectLsassMemoryKeys();
VOID GetCredentialsFromMSV();
VOID GetCredentialsFromWdigest();
BOOL EnableSeDebugPrivilege();