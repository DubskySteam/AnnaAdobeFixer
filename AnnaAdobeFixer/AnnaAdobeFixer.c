#include <stdio.h>
#include <windows.h>
#include <aclapi.h>
#include "lmcons.h"

void printAsciiArt() {
    printf("     _                              _        _         _             _____  _                  \n");
    printf("    / \\    _ __   _ __    __ _     / \\    __| |  ___  | |__    ___  |  ___|(_)__  __ ___  _ __ \n");
    printf("   / _ \\  | '_ \\ | '_ \\  / _` |   / _ \\  / _` | / _ \\ | '_ \\  / _ \\ | |_   | |\\ \\/ // _ \\| '__|\n");
    printf("  / ___ \\ | | | || | | || (_| |  / ___ \\| (_| || (_) || |_) ||  __/ |  _|  | | >  <|  __/| |   \n");
    printf(" /_/   \\_\\|_| |_||_| |_| \\__,_| /_/   \\_\\\\__,_| \\___/ |_.__/  \\___| |_|    |_|/_/\\_\\\\___||_|   \n");
    printf("                                                                                            \n");
}

void setFullControl(LPCWSTR path, LPCWSTR userName) {
    EXPLICIT_ACCESS_W ea;
    PACL pOldDACL = NULL, pNewDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;

    DWORD result = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        NULL, NULL, &pOldDACL, NULL, &pSD);
    if (result != ERROR_SUCCESS) {
        printf("GetNamedSecurityInfo error on %S: %lu\n", path, result);
        return;
    }

    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS_W));
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = (LPWSTR)userName;

    result = SetEntriesInAclW(1, &ea, pOldDACL, &pNewDACL);
    if (result != ERROR_SUCCESS) {
        printf("SetEntriesInAcl error on %S: %lu\n", path);
        return;
    }

    result = SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        NULL, NULL, pNewDACL, NULL);
    if (result != ERROR_SUCCESS) {
        printf("SetNamedSecurityInfo error on %S: %lu\n", path, result);
        return;
    }

    printf("Full control permissions set for %S on %S\n", userName, path);

    if (pSD != NULL)
        LocalFree((HLOCAL)pSD);
    if (pNewDACL != NULL)
        LocalFree((HLOCAL)pNewDACL);
}

int main() {
    printAsciiArt();

    char response;
    printf("Full send it? (Y/N): ");
    scanf(" %c", &response);

    if (response != 'Y' && response != 'y') {
        printf("Operation canceled.\n");
        return 0;
    }

    WCHAR userName[UNLEN + 1];
    printf("Enter the Windows user name: ");
    wscanf(L"%ls", userName);

    WCHAR paths[][MAX_PATH] = {
        L"C:\\Windows\\temp",
        L"C:\\Users\\%s\\AppData\\Local\\Temp",
        L"C:\\Users\\%s\\AppData\\Local\\Packages",
        L"C:\\Program Files (x86)\\Adobe",
        L"C:\\Program Files (x86)\\Common Files\\Adobe",
        L"C:\\Program Files\\Adobe",
        L"C:\\Program Files\\Common Files\\Adobe"
    };

    WCHAR fullPath[MAX_PATH];
    for (int i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        if (wcschr(paths[i], L'%')) {
            swprintf(fullPath, MAX_PATH, paths[i], userName);
        }
        else {
            wcscpy(fullPath, paths[i]);
        }
        setFullControl(fullPath, userName);
    }

    return 0;
}

