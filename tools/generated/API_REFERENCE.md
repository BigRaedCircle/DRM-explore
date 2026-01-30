# Windows API Functions Reference

Auto-generated from Windows SDK headers

## Summary

Total functions: **436**

- **advapi32.dll**: 91 functions
- **kernel32.dll**: 254 functions
- **unknown.dll**: 91 functions

## Functions by DLL

### advapi32.dll (91 functions)

| Function | Return Type | Parameters | Source |
|----------|-------------|------------|--------|
| `AbortSystemShutdownA` | BOOL | _In_opt_ LPSTR lpMachineName | winreg.h |
| `AbortSystemShutdownW` | BOOL | _In_opt_ LPWSTR lpMachineName | winreg.h |
| `CheckForHiberboot` | DWORD | _Inout_ PBOOLEAN pHiberboot, _In_ BOOLEAN bClea... | winreg.h |
| `InitiateShutdownA` | DWORD | _In_opt_ LPSTR lpMachineName, _In_opt_ LPSTR lp... | winreg.h |
| `InitiateShutdownW` | DWORD | _In_opt_ LPWSTR lpMachineName, _In_opt_ LPWSTR ... | winreg.h |
| `InitiateSystemShutdownA` | BOOL | _In_opt_ LPSTR lpMachineName, _In_opt_ LPSTR lp... | winreg.h |
| `InitiateSystemShutdownExA` | BOOL | _In_opt_ LPSTR lpMachineName, _In_opt_ LPSTR lp... | winreg.h |
| `InitiateSystemShutdownExW` | BOOL | _In_opt_ LPWSTR lpMachineName, _In_opt_ LPWSTR ... | winreg.h |
| `InitiateSystemShutdownW` | BOOL | _In_opt_ LPWSTR lpMachineName, _In_opt_ LPWSTR ... | winreg.h |
| `RegCloseKey` | LSTATUS | _In_ HKEY hKey | winreg.h |
| `RegConnectRegistryA` | LSTATUS | _In_opt_ LPCSTR lpMachineName, _In_ HKEY hKey, ... | winreg.h |
| `RegConnectRegistryExA` | LSTATUS | _In_opt_ LPCSTR lpMachineName, _In_ HKEY hKey, ... | winreg.h |
| `RegConnectRegistryExW` | LSTATUS | _In_opt_ LPCWSTR lpMachineName, _In_ HKEY hKey,... | winreg.h |
| `RegConnectRegistryW` | LSTATUS | _In_opt_ LPCWSTR lpMachineName, _In_ HKEY hKey,... | winreg.h |
| `RegCopyTreeA` | LSTATUS | _In_        HKEY hKeySrc, _In_opt_    LPCSTR lp... | winreg.h |
| `RegCopyTreeW` | LSTATUS | _In_ HKEY hKeySrc, _In_opt_ LPCWSTR lpSubKey, _... | winreg.h |
| `RegCreateKeyA` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _Out_... | winreg.h |
| `RegCreateKeyExA` | LSTATUS | _In_ HKEY hKey, _In_ LPCSTR lpSubKey, _Reserved... | winreg.h |
| `RegCreateKeyExW` | LSTATUS | _In_ HKEY hKey, _In_ LPCWSTR lpSubKey, _Reserve... | winreg.h |
| `RegCreateKeyTransactedA` | LSTATUS | _In_ HKEY hKey, _In_ LPCSTR lpSubKey, _Reserved... | winreg.h |
| `RegCreateKeyTransactedW` | LSTATUS | _In_ HKEY hKey, _In_ LPCWSTR lpSubKey, _Reserve... | winreg.h |
| `RegCreateKeyW` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCWSTR lpSubKey, _Out... | winreg.h |
| `RegDeleteKeyA` | LSTATUS | _In_ HKEY hKey, _In_ LPCSTR lpSubKey | winreg.h |
| `RegDeleteKeyExA` | LSTATUS | _In_ HKEY hKey, _In_ LPCSTR lpSubKey, _In_ REGS... | winreg.h |
| `RegDeleteKeyExW` | LSTATUS | _In_ HKEY hKey, _In_ LPCWSTR lpSubKey, _In_ REG... | winreg.h |
| `RegDeleteKeyTransactedA` | LSTATUS | _In_ HKEY hKey, _In_ LPCSTR lpSubKey, _In_ REGS... | winreg.h |
| `RegDeleteKeyTransactedW` | LSTATUS | _In_ HKEY hKey, _In_ LPCWSTR lpSubKey, _In_ REG... | winreg.h |
| `RegDeleteKeyValueA` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _In_o... | winreg.h |
| `RegDeleteKeyValueW` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCWSTR lpSubKey, _In_... | winreg.h |
| `RegDeleteKeyW` | LSTATUS | _In_ HKEY hKey, _In_ LPCWSTR lpSubKey | winreg.h |
| `RegDeleteTreeA` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey | winreg.h |
| `RegDeleteTreeW` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCWSTR lpSubKey | winreg.h |
| `RegDeleteValueA` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCSTR lpValueName | winreg.h |
| `RegDeleteValueW` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCWSTR lpValueName | winreg.h |
| `RegDisablePredefinedCache` | LSTATUS | VOID  | winreg.h |
| `RegDisablePredefinedCacheEx` | LSTATUS | VOID  | winreg.h |
| `RegDisableReflectionKey` | LONG | _In_ HKEY hBase | winreg.h |
| `RegEnableReflectionKey` | LONG | _In_ HKEY hBase | winreg.h |
| `RegEnumKeyA` | LSTATUS | _In_ HKEY hKey, _In_ DWORD dwIndex, _Out_writes... | winreg.h |
| `RegEnumKeyExA` | LSTATUS | _In_ HKEY hKey, _In_ DWORD dwIndex, _Out_writes... | winreg.h |
| `RegEnumKeyExW` | LSTATUS | _In_ HKEY hKey, _In_ DWORD dwIndex, _Out_writes... | winreg.h |
| `RegEnumKeyW` | LSTATUS | _In_ HKEY hKey, _In_ DWORD dwIndex, _Out_writes... | winreg.h |
| `RegEnumValueA` | LSTATUS | _In_ HKEY hKey, _In_ DWORD dwIndex, _Out_writes... | winreg.h |
| `RegEnumValueW` | LSTATUS | _In_ HKEY hKey, _In_ DWORD dwIndex, _Out_writes... | winreg.h |
| `RegFlushKey` | LSTATUS | _In_ HKEY hKey | winreg.h |
| `RegGetKeySecurity` | LSTATUS | _In_ HKEY hKey, _In_ SECURITY_INFORMATION Secur... | winreg.h |
| `RegGetValueA` | LSTATUS | _In_ HKEY hkey, _In_opt_ LPCSTR lpSubKey, _In_o... | winreg.h |
| `RegGetValueW` | LSTATUS | _In_ HKEY hkey, _In_opt_ LPCWSTR lpSubKey, _In_... | winreg.h |
| `RegLoadAppKeyA` | LSTATUS | _In_ LPCSTR lpFile, _Out_ PHKEY phkResult, _In_... | winreg.h |
| `RegLoadAppKeyW` | LSTATUS | _In_ LPCWSTR lpFile, _Out_ PHKEY phkResult, _In... | winreg.h |
| `RegLoadKeyA` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _In_ ... | winreg.h |
| `RegLoadKeyW` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCWSTR lpSubKey, _In_... | winreg.h |
| `RegLoadMUIStringA` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCSTR pszValue, _Out_... | winreg.h |
| `RegLoadMUIStringW` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCWSTR pszValue, _Out... | winreg.h |
| `RegNotifyChangeKeyValue` | LSTATUS | _In_ HKEY hKey, _In_ BOOL bWatchSubtree, _In_ D... | winreg.h |
| `RegOpenCurrentUser` | LSTATUS | _In_ REGSAM samDesired, _Out_ PHKEY phkResult | winreg.h |
| `RegOpenKeyA` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _Out_... | winreg.h |
| `RegOpenKeyExA` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _In_o... | winreg.h |
| `RegOpenKeyExW` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCWSTR lpSubKey, _In_... | winreg.h |
| `RegOpenKeyTransactedA` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _In_o... | winreg.h |
| `RegOpenKeyTransactedW` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCWSTR lpSubKey, _In_... | winreg.h |
| `RegOpenKeyW` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCWSTR lpSubKey, _Out... | winreg.h |
| `RegOpenUserClassesRoot` | LSTATUS | _In_ HANDLE hToken, _Reserved_ DWORD dwOptions,... | winreg.h |
| `RegOverridePredefKey` | LSTATUS | _In_ HKEY hKey, _In_opt_ HKEY hNewHKey | winreg.h |
| `RegQueryInfoKeyA` | LSTATUS | _In_ HKEY hKey, _Out_writes_to_opt_(*lpcchClass... | winreg.h |
| `RegQueryInfoKeyW` | LSTATUS | _In_ HKEY hKey, _Out_writes_to_opt_(*lpcchClass... | winreg.h |
| `RegQueryMultipleValuesA` | LSTATUS | _In_ HKEY hKey, _Out_writes_(num_vals) PVALENTA... | winreg.h |
| `RegQueryMultipleValuesW` | LSTATUS | _In_ HKEY hKey, _Out_writes_(num_vals) PVALENTW... | winreg.h |
| `RegQueryReflectionKey` | LONG | _In_ HKEY hBase, _Out_ BOOL* bIsReflectionDisabled | winreg.h |
| `RegQueryValueA` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _Out_... | winreg.h |
| `RegQueryValueExA` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCSTR lpValueName, _R... | winreg.h |
| `RegQueryValueExW` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCWSTR lpValueName, _... | winreg.h |
| `RegQueryValueW` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCWSTR lpSubKey, _Out... | winreg.h |
| `RegRenameKey` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCWSTR lpSubKeyName, ... | winreg.h |
| `RegReplaceKeyA` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _In_ ... | winreg.h |
| `RegReplaceKeyW` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCWSTR lpSubKey, _In_... | winreg.h |
| `RegRestoreKeyA` | LSTATUS | _In_ HKEY hKey, _In_ LPCSTR lpFile, _In_ DWORD ... | winreg.h |
| `RegRestoreKeyW` | LSTATUS | _In_ HKEY hKey, _In_ LPCWSTR lpFile, _In_ DWORD... | winreg.h |
| `RegSaveKeyA` | LSTATUS | _In_ HKEY hKey, _In_ LPCSTR lpFile, _In_opt_ CO... | winreg.h |
| `RegSaveKeyExA` | LSTATUS | _In_ HKEY hKey, _In_ LPCSTR lpFile, _In_opt_ CO... | winreg.h |
| `RegSaveKeyExW` | LSTATUS | _In_ HKEY hKey, _In_ LPCWSTR lpFile, _In_opt_ C... | winreg.h |
| `RegSaveKeyW` | LSTATUS | _In_ HKEY hKey, _In_ LPCWSTR lpFile, _In_opt_ C... | winreg.h |
| `RegSetKeySecurity` | LSTATUS | _In_ HKEY hKey, _In_ SECURITY_INFORMATION Secur... | winreg.h |
| `RegSetKeyValueA` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _In_o... | winreg.h |
| `RegSetKeyValueW` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCWSTR lpSubKey, _In_... | winreg.h |
| `RegSetValueA` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey, _In_ ... | winreg.h |
| `RegSetValueExA` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCSTR lpValueName, _R... | winreg.h |
| `RegSetValueExW` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCWSTR lpValueName, _... | winreg.h |
| `RegSetValueW` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCWSTR lpSubKey, _In_... | winreg.h |
| `RegUnLoadKeyA` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCSTR lpSubKey | winreg.h |
| `RegUnLoadKeyW` | LSTATUS | _In_ HKEY hKey, _In_opt_ LPCWSTR lpSubKey | winreg.h |

### kernel32.dll (254 functions)

| Function | Return Type | Parameters | Source |
|----------|-------------|------------|--------|
| `AreFileApisANSI` | BOOL | VOID  | fileapi.h |
| `AreShortNamesEnabled` | BOOL | _In_ HANDLE Handle, _Out_ BOOL* Enabled | fileapi.h |
| `CancelWaitableTimer` | BOOL | _In_ HANDLE hTimer | synchapi.h |
| `CompareFileTime` | LONG | _In_ CONST FILETIME* lpFileTime1, _In_ CONST FI... | fileapi.h |
| `CreateDirectory2A` | HANDLE | _In_z_ LPCSTR lpPathName, _In_ DWORD dwDesiredA... | fileapi.h |
| `CreateDirectory2W` | HANDLE | _In_z_ LPCWSTR lpPathName, _In_ DWORD dwDesired... | fileapi.h |
| `CreateDirectoryA` | BOOL | _In_ LPCSTR lpPathName, _In_opt_ LPSECURITY_ATT... | fileapi.h |
| `CreateDirectoryW` | BOOL | _In_ LPCWSTR lpPathName, _In_opt_ LPSECURITY_AT... | fileapi.h |
| `CreateEventA` | _Ret_maybenull_
HANDLE | _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttribute... | synchapi.h |
| `CreateEventExA` | _Ret_maybenull_
HANDLE | _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttribute... | synchapi.h |
| `CreateEventExW` | _Ret_maybenull_
HANDLE | _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttribute... | synchapi.h |
| `CreateEventW` | _Ret_maybenull_
HANDLE | _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttribute... | synchapi.h |
| `CreateFile2` | HANDLE | _In_ LPCWSTR lpFileName, _In_ DWORD dwDesiredAc... | fileapi.h |
| `CreateFile3` | HANDLE | _In_z_ LPCWSTR lpFileName, _In_ DWORD dwDesired... | fileapi.h |
| `CreateFileA` | HANDLE | _In_ LPCSTR lpFileName, _In_ DWORD dwDesiredAcc... | fileapi.h |
| `CreateFileMapping2` | _Ret_maybenull_
HANDLE | _In_ HANDLE File, _In_opt_ SECURITY_ATTRIBUTES*... | memoryapi.h |
| `CreateFileMappingFromApp` | _Ret_maybenull_
HANDLE | _In_ HANDLE hFile, _In_opt_ PSECURITY_ATTRIBUTE... | memoryapi.h |
| `CreateFileMappingNumaW` | _Ret_maybenull_
HANDLE | _In_ HANDLE hFile, _In_opt_ LPSECURITY_ATTRIBUT... | memoryapi.h |
| `CreateFileMappingW` | _Ret_maybenull_
HANDLE | _In_ HANDLE hFile, _In_opt_ LPSECURITY_ATTRIBUT... | memoryapi.h |
| `CreateFileW` | HANDLE | _In_ LPCWSTR lpFileName, _In_ DWORD dwDesiredAc... | fileapi.h |
| `CreateMemoryResourceNotification` | _Ret_maybenull_
HANDLE | _In_ MEMORY_RESOURCE_NOTIFICATION_TYPE Notifica... | memoryapi.h |
| `CreateMutexA` | _Ret_maybenull_
HANDLE | _In_opt_ LPSECURITY_ATTRIBUTES lpMutexAttribute... | synchapi.h |
| `CreateMutexExA` | _Ret_maybenull_
HANDLE | _In_opt_ LPSECURITY_ATTRIBUTES lpMutexAttribute... | synchapi.h |
| `CreateMutexExW` | _Ret_maybenull_
HANDLE | _In_opt_ LPSECURITY_ATTRIBUTES lpMutexAttribute... | synchapi.h |
| `CreateMutexW` | _Ret_maybenull_
HANDLE | _In_opt_ LPSECURITY_ATTRIBUTES lpMutexAttribute... | synchapi.h |
| `CreateProcessA` | BOOL | _In_opt_ LPCSTR lpApplicationName, _Inout_opt_ ... | processthreadsapi.h |
| `CreateProcessAsUserA` | BOOL | _In_opt_ HANDLE hToken, _In_opt_ LPCSTR lpAppli... | processthreadsapi.h |
| `CreateProcessAsUserW` | BOOL | _In_opt_ HANDLE hToken, _In_opt_ LPCWSTR lpAppl... | processthreadsapi.h |
| `CreateProcessW` | BOOL | _In_opt_ LPCWSTR lpApplicationName, _Inout_opt_... | processthreadsapi.h |
| `CreateRemoteThread` | _Ret_maybenull_
HANDLE | _In_ HANDLE hProcess, _In_opt_ LPSECURITY_ATTRI... | processthreadsapi.h |
| `CreateRemoteThreadEx` | _Ret_maybenull_
HANDLE | _In_ HANDLE hProcess, _In_opt_ LPSECURITY_ATTRI... | processthreadsapi.h |
| `CreateSemaphoreExW` | _Ret_maybenull_
HANDLE | _In_opt_ LPSECURITY_ATTRIBUTES lpSemaphoreAttri... | synchapi.h |
| `CreateSemaphoreW` | HANDLE | _In_opt_ LPSECURITY_ATTRIBUTES lpSemaphoreAttri... | synchapi.h |
| `CreateThread` | _Ret_maybenull_
HANDLE | _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttribut... | processthreadsapi.h |
| `CreateWaitableTimerExW` | _Ret_maybenull_
HANDLE | _In_opt_ LPSECURITY_ATTRIBUTES lpTimerAttribute... | synchapi.h |
| `CreateWaitableTimerW` | _Ret_maybenull_
HANDLE | _In_opt_ LPSECURITY_ATTRIBUTES lpTimerAttribute... | synchapi.h |
| `DefineDosDeviceW` | BOOL | _In_ DWORD dwFlags, _In_ LPCWSTR lpDeviceName, ... | fileapi.h |
| `DeleteCriticalSection` | VOID | _Inout_ LPCRITICAL_SECTION lpCriticalSection | synchapi.h |
| `DeleteFile2A` | BOOL | _In_z_ LPCSTR lpFileName, _In_ DWORD Flags | fileapi.h |
| `DeleteFile2W` | BOOL | _In_z_ LPCWSTR lpFileName, _In_ DWORD Flags | fileapi.h |
| `DeleteFileA` | BOOL | _In_ LPCSTR lpFileName | fileapi.h |
| `DeleteFileW` | BOOL | _In_ LPCWSTR lpFileName | fileapi.h |
| `DeleteProcThreadAttributeList` | VOID | _Inout_ LPPROC_THREAD_ATTRIBUTE_LIST lpAttribut... | processthreadsapi.h |
| `DeleteVolumeMountPointW` | BOOL | _In_ LPCWSTR lpszVolumeMountPoint | fileapi.h |
| `EnterCriticalSection` | VOID | _Inout_ LPCRITICAL_SECTION lpCriticalSection | synchapi.h |
| `ExitProcess` | DECLSPEC_NORETURN
VOID | _In_ UINT uExitCode | processthreadsapi.h |
| `ExitThread` | DECLSPEC_NORETURN
VOID | _In_ DWORD dwExitCode | processthreadsapi.h |
| `FileTimeToLocalFileTime` | BOOL | _In_ CONST FILETIME* lpFileTime, _Out_ LPFILETI... | fileapi.h |
| `FindClose` | BOOL | _Inout_ HANDLE hFindFile | fileapi.h |
| `FindCloseChangeNotification` | BOOL | _In_ HANDLE hChangeHandle | fileapi.h |
| `FindFirstChangeNotificationA` | HANDLE | _In_ LPCSTR lpPathName, _In_ BOOL bWatchSubtree... | fileapi.h |
| `FindFirstChangeNotificationW` | HANDLE | _In_ LPCWSTR lpPathName, _In_ BOOL bWatchSubtre... | fileapi.h |
| `FindFirstFileA` | HANDLE | _In_ LPCSTR lpFileName, _Out_ LPWIN32_FIND_DATA... | fileapi.h |
| `FindFirstFileExA` | HANDLE | _In_ LPCSTR lpFileName, _In_ FINDEX_INFO_LEVELS... | fileapi.h |
| `FindFirstFileExW` | HANDLE | _In_ LPCWSTR lpFileName, _In_ FINDEX_INFO_LEVEL... | fileapi.h |
| `FindFirstFileNameW` | HANDLE | _In_ LPCWSTR lpFileName, _In_ DWORD dwFlags, _I... | fileapi.h |
| `FindFirstFileW` | HANDLE | _In_ LPCWSTR lpFileName, _Out_ LPWIN32_FIND_DAT... | fileapi.h |
| `FindFirstStreamW` | HANDLE | _In_ LPCWSTR lpFileName, _In_ STREAM_INFO_LEVEL... | fileapi.h |
| `FindFirstVolumeW` | HANDLE | _Out_writes_(cchBufferLength) LPWSTR lpszVolume... | fileapi.h |
| `FindNextChangeNotification` | BOOL | _In_ HANDLE hChangeHandle | fileapi.h |
| `FindNextFileA` | BOOL | _In_ HANDLE hFindFile, _Out_ LPWIN32_FIND_DATAA... | fileapi.h |
| `FindNextFileNameW` | BOOL | _In_ HANDLE hFindStream, _Inout_ LPDWORD String... | fileapi.h |
| `FindNextFileW` | BOOL | _In_ HANDLE hFindFile, _Out_ LPWIN32_FIND_DATAW... | fileapi.h |
| `FindNextStreamW` | BOOL | _In_ HANDLE hFindStream, _Out_writes_bytes_(siz... | fileapi.h |
| `FindNextVolumeW` | BOOL | _Inout_ HANDLE hFindVolume, _Out_writes_(cchBuf... | fileapi.h |
| `FindVolumeClose` | BOOL | _In_ HANDLE hFindVolume | fileapi.h |
| `FlushFileBuffers` | BOOL | _In_ HANDLE hFile | fileapi.h |
| `FlushInstructionCache` | BOOL | _In_ HANDLE hProcess, _In_reads_bytes_opt_(dwSi... | processthreadsapi.h |
| `FlushProcessWriteBuffers` | VOID | VOID  | processthreadsapi.h |
| `FlushViewOfFile` | BOOL | _In_ LPCVOID lpBaseAddress, _In_ SIZE_T dwNumbe... | memoryapi.h |
| `GetCompressedFileSizeA` | DWORD | _In_ LPCSTR lpFileName, _Out_opt_ LPDWORD lpFil... | fileapi.h |
| `GetCompressedFileSizeW` | DWORD | _In_ LPCWSTR lpFileName, _Out_opt_ LPDWORD lpFi... | fileapi.h |
| `GetCurrentProcess` | HANDLE | VOID  | processthreadsapi.h |
| `GetCurrentProcessId` | DWORD | VOID  | processthreadsapi.h |
| `GetCurrentProcessorNumber` | DWORD | VOID  | processthreadsapi.h |
| `GetCurrentProcessorNumberEx` | VOID | _Out_ PPROCESSOR_NUMBER ProcNumber | processthreadsapi.h |
| `GetCurrentThread` | HANDLE | VOID  | processthreadsapi.h |
| `GetCurrentThreadId` | DWORD | VOID  | processthreadsapi.h |
| `GetCurrentThreadStackLimits` | VOID | _Out_ PULONG_PTR LowLimit, _Out_ PULONG_PTR Hig... | processthreadsapi.h |
| `GetDiskFreeSpaceA` | BOOL | _In_opt_ LPCSTR lpRootPathName, _Out_opt_ LPDWO... | fileapi.h |
| `GetDiskFreeSpaceExA` | BOOL | _In_opt_ LPCSTR lpDirectoryName, _Out_opt_ PULA... | fileapi.h |
| `GetDiskFreeSpaceExW` | BOOL | _In_opt_ LPCWSTR lpDirectoryName, _Out_opt_ PUL... | fileapi.h |
| `GetDiskFreeSpaceW` | BOOL | _In_opt_ LPCWSTR lpRootPathName, _Out_opt_ LPDW... | fileapi.h |
| `GetDiskSpaceInformationA` | HRESULT | _In_opt_ LPCSTR rootPath, _Out_ DISK_SPACE_INFO... | fileapi.h |
| `GetDiskSpaceInformationW` | HRESULT | _In_opt_ LPCWSTR rootPath, _Out_ DISK_SPACE_INF... | fileapi.h |
| `GetDriveTypeA` | UINT | _In_opt_ LPCSTR lpRootPathName | fileapi.h |
| `GetDriveTypeW` | UINT | _In_opt_ LPCWSTR lpRootPathName | fileapi.h |
| `GetExitCodeProcess` | BOOL | _In_ HANDLE hProcess, _Out_ LPDWORD lpExitCode | processthreadsapi.h |
| `GetFileAttributesA` | DWORD | _In_ LPCSTR lpFileName | fileapi.h |
| `GetFileAttributesExA` | BOOL | _In_ LPCSTR lpFileName, _In_ GET_FILEEX_INFO_LE... | fileapi.h |
| `GetFileAttributesExW` | BOOL | _In_ LPCWSTR lpFileName, _In_ GET_FILEEX_INFO_L... | fileapi.h |
| `GetFileAttributesW` | DWORD | _In_ LPCWSTR lpFileName | fileapi.h |
| `GetFileInformationByHandle` | BOOL | _In_ HANDLE hFile, _Out_ LPBY_HANDLE_FILE_INFOR... | fileapi.h |
| `GetFileSize` | DWORD | _In_ HANDLE hFile, _Out_opt_ LPDWORD lpFileSize... | fileapi.h |
| `GetFileSizeEx` | BOOL | _In_ HANDLE hFile, _Out_ PLARGE_INTEGER lpFileSize | fileapi.h |
| `GetFileTime` | BOOL | _In_ HANDLE hFile, _Out_opt_ LPFILETIME lpCreat... | fileapi.h |
| `GetFileType` | DWORD | _In_ HANDLE hFile | fileapi.h |
| `GetFinalPathNameByHandleA` | DWORD | _In_ HANDLE hFile, _Out_writes_(cchFilePath) LP... | fileapi.h |
| `GetFinalPathNameByHandleW` | DWORD | _In_ HANDLE hFile, _Out_writes_(cchFilePath) LP... | fileapi.h |
| `GetLargePageMinimum` | SIZE_T | VOID  | memoryapi.h |
| `GetLogicalDriveStringsW` | DWORD | _In_ DWORD nBufferLength, _Out_writes_to_opt_(n... | fileapi.h |
| `GetLogicalDrives` | DWORD | VOID  | fileapi.h |
| `GetPriorityClass` | DWORD | _In_ HANDLE hProcess | processthreadsapi.h |
| `GetProcessHandleCount` | BOOL | _In_ HANDLE hProcess, _Out_ PDWORD pdwHandleCount | processthreadsapi.h |
| `GetProcessId` | DWORD | _In_ HANDLE Process | processthreadsapi.h |
| `GetProcessIdOfThread` | DWORD | _In_ HANDLE Thread | processthreadsapi.h |
| `GetProcessInformation` | BOOL | _In_ HANDLE hProcess, _In_ PROCESS_INFORMATION_... | processthreadsapi.h |
| `GetProcessMitigationPolicy` | BOOL | _In_ HANDLE hProcess, _In_ PROCESS_MITIGATION_P... | processthreadsapi.h |
| `GetProcessPriorityBoost` | BOOL | _In_ HANDLE hProcess, _Out_ PBOOL pDisablePrior... | processthreadsapi.h |
| `GetProcessShutdownParameters` | BOOL | _Out_ LPDWORD lpdwLevel, _Out_ LPDWORD lpdwFlags | processthreadsapi.h |
| `GetProcessTimes` | BOOL | _In_ HANDLE hProcess, _Out_ LPFILETIME lpCreati... | processthreadsapi.h |
| `GetProcessVersion` | DWORD | _In_ DWORD ProcessId | processthreadsapi.h |
| `GetProcessWorkingSetSize` | BOOL | _In_ HANDLE hProcess, _Out_ PSIZE_T lpMinimumWo... | memoryapi.h |
| `GetStartupInfoW` | VOID | _Out_ LPSTARTUPINFOW lpStartupInfo | processthreadsapi.h |
| `GetSystemTimes` | BOOL | _Out_opt_ PFILETIME lpIdleTime, _Out_opt_ PFILE... | processthreadsapi.h |
| `GetTempFileNameA` | UINT | _In_ LPCSTR lpPathName, _In_ LPCSTR lpPrefixStr... | fileapi.h |
| `GetTempFileNameW` | UINT | _In_ LPCWSTR lpPathName, _In_ LPCWSTR lpPrefixS... | fileapi.h |
| `GetTempPathA` | DWORD | _In_ DWORD nBufferLength, _Out_writes_to_opt_(n... | fileapi.h |
| `GetTempPathW` | DWORD | _In_ DWORD nBufferLength, _Out_writes_to_opt_(n... | fileapi.h |
| `GetThreadContext` | BOOL | _In_ HANDLE hThread, _Inout_ LPCONTEXT lpContext | processthreadsapi.h |
| `GetThreadDescription` | HRESULT | _In_ HANDLE hThread, _Outptr_result_z_ PWSTR* p... | processthreadsapi.h |
| `GetThreadIOPendingFlag` | BOOL | _In_ HANDLE hThread, _Out_ PBOOL lpIOIsPending | processthreadsapi.h |
| `GetThreadId` | DWORD | _In_ HANDLE Thread | processthreadsapi.h |
| `GetThreadIdealProcessorEx` | BOOL | _In_ HANDLE hThread, _Out_ PPROCESSOR_NUMBER lp... | processthreadsapi.h |
| `GetThreadInformation` | BOOL | _In_ HANDLE hThread, _In_ THREAD_INFORMATION_CL... | processthreadsapi.h |
| `GetThreadPriority` | int | _In_ HANDLE hThread | processthreadsapi.h |
| `GetThreadPriorityBoost` | BOOL | _In_ HANDLE hThread, _Out_ PBOOL pDisablePriori... | processthreadsapi.h |
| `GetThreadTimes` | BOOL | _In_ HANDLE hThread, _Out_ LPFILETIME lpCreatio... | processthreadsapi.h |
| `GetVolumeInformationA` | BOOL | _In_opt_ LPCSTR lpRootPathName, _Out_writes_opt... | fileapi.h |
| `GetVolumeInformationByHandleW` | BOOL | _In_ HANDLE hFile, _Out_writes_opt_(nVolumeName... | fileapi.h |
| `GetVolumeInformationW` | BOOL | _In_opt_ LPCWSTR lpRootPathName, _Out_writes_op... | fileapi.h |
| `GetVolumeNameForVolumeMountPointW` | BOOL | _In_ LPCWSTR lpszVolumeMountPoint, _Out_writes_... | fileapi.h |
| `GetVolumePathNameW` | BOOL | _In_ LPCWSTR lpszFileName, _Out_writes_(cchBuff... | fileapi.h |
| `GetVolumePathNamesForVolumeNameW` | BOOL | _In_ LPCWSTR lpszVolumeName, _Out_writes_to_opt... | fileapi.h |
| `InitOnceBeginInitialize` | BOOL | _Inout_ LPINIT_ONCE lpInitOnce, _In_ DWORD dwFl... | synchapi.h |
| `InitOnceComplete` | BOOL | _Inout_ LPINIT_ONCE lpInitOnce, _In_ DWORD dwFl... | synchapi.h |
| `InitOnceExecuteOnce` | BOOL | _Inout_ PINIT_ONCE InitOnce, _In_ __callback PI... | synchapi.h |
| `InitOnceInitialize` | VOID | _Out_ PINIT_ONCE InitOnce | synchapi.h |
| `InitializeConditionVariable` | VOID | _Out_ PCONDITION_VARIABLE ConditionVariable | synchapi.h |
| `InitializeCriticalSection` | VOID | _Out_ LPCRITICAL_SECTION lpCriticalSection | synchapi.h |
| `InitializeCriticalSectionAndSpinCount` | _Must_inspect_result_
BOOL | _Out_ LPCRITICAL_SECTION lpCriticalSection, _In... | synchapi.h |
| `InitializeCriticalSectionEx` | BOOL | _Out_ LPCRITICAL_SECTION lpCriticalSection, _In... | synchapi.h |
| `InitializeSRWLock` | VOID | _Out_ PSRWLOCK SRWLock | synchapi.h |
| `IsProcessCritical` | BOOL | _In_ HANDLE hProcess, _Out_ PBOOL Critical | processthreadsapi.h |
| `IsProcessorFeaturePresent` | BOOL | _In_ DWORD ProcessorFeature | processthreadsapi.h |
| `LeaveCriticalSection` | VOID | _Inout_ LPCRITICAL_SECTION lpCriticalSection | synchapi.h |
| `LocalFileTimeToFileTime` | BOOL | _In_ CONST FILETIME* lpLocalFileTime, _Out_ LPF... | fileapi.h |
| `LockFile` | BOOL | _In_ HANDLE hFile, _In_ DWORD dwFileOffsetLow, ... | fileapi.h |
| `LockFileEx` | BOOL | _In_ HANDLE hFile, _In_ DWORD dwFlags, _Reserve... | fileapi.h |
| `OpenDedicatedMemoryPartition` | HANDLE | _In_ HANDLE Partition, _In_ ULONG64 DedicatedMe... | memoryapi.h |
| `OpenEventA` | _Ret_maybenull_
HANDLE | _In_ DWORD dwDesiredAccess, _In_ BOOL bInheritH... | synchapi.h |
| `OpenEventW` | _Ret_maybenull_
HANDLE | _In_ DWORD dwDesiredAccess, _In_ BOOL bInheritH... | synchapi.h |
| `OpenFileMappingFromApp` | _Ret_maybenull_
HANDLE | _In_ ULONG DesiredAccess, _In_ BOOL InheritHand... | memoryapi.h |
| `OpenFileMappingW` | _Ret_maybenull_
HANDLE | _In_ DWORD dwDesiredAccess, _In_ BOOL bInheritH... | memoryapi.h |
| `OpenMutexW` | _Ret_maybenull_
HANDLE | _In_ DWORD dwDesiredAccess, _In_ BOOL bInheritH... | synchapi.h |
| `OpenProcess` | HANDLE | _In_ DWORD dwDesiredAccess, _In_ BOOL bInheritH... | processthreadsapi.h |
| `OpenProcessToken` | BOOL | _In_ HANDLE ProcessHandle, _In_ DWORD DesiredAc... | processthreadsapi.h |
| `OpenSemaphoreW` | _Ret_maybenull_
HANDLE | _In_ DWORD dwDesiredAccess, _In_ BOOL bInheritH... | synchapi.h |
| `OpenThread` | _Ret_maybenull_
HANDLE | _In_ DWORD dwDesiredAccess, _In_ BOOL bInheritH... | processthreadsapi.h |
| `OpenThreadToken` | BOOL | _In_ HANDLE ThreadHandle, _In_ DWORD DesiredAcc... | processthreadsapi.h |
| `OpenWaitableTimerW` | _Ret_maybenull_
HANDLE | _In_ DWORD dwDesiredAccess, _In_ BOOL bInheritH... | synchapi.h |
| `PrefetchVirtualMemory` | BOOL | _In_ HANDLE hProcess, _In_ ULONG_PTR NumberOfEn... | memoryapi.h |
| `ProcessIdToSessionId` | BOOL | _In_ DWORD dwProcessId, _Out_ DWORD* pSessionId | processthreadsapi.h |
| `QueryDosDeviceW` | DWORD | _In_opt_ LPCWSTR lpDeviceName, _Out_writes_to_o... | fileapi.h |
| `QueryProcessAffinityUpdateMode` | BOOL | _In_ HANDLE hProcess, _Out_opt_ LPDWORD lpdwFlags | processthreadsapi.h |
| `QueryProtectedPolicy` | BOOL | _In_ LPCGUID PolicyGuid, _Out_ PULONG_PTR Polic... | processthreadsapi.h |
| `QueueUserAPC` | DWORD | _In_ PAPCFUNC pfnAPC, _In_ HANDLE hThread, _In_... | processthreadsapi.h |
| `QueueUserAPC2` | BOOL | _In_ PAPCFUNC ApcRoutine, _In_ HANDLE Thread, _... | processthreadsapi.h |
| `ReadFile` | _Must_inspect_result_
BOOL | _In_ HANDLE hFile, _Out_writes_bytes_to_opt_(nN... | fileapi.h |
| `ReadFileEx` | _Must_inspect_result_
BOOL | _In_ HANDLE hFile, _Out_writes_bytes_opt_(nNumb... | fileapi.h |
| `ReadFileScatter` | _Must_inspect_result_
BOOL | _In_ HANDLE hFile, _In_ FILE_SEGMENT_ELEMENT aS... | fileapi.h |
| `ReleaseMutex` | BOOL | _In_ HANDLE hMutex | synchapi.h |
| `ReleaseSemaphore` | BOOL | _In_ HANDLE hSemaphore, _In_ LONG lReleaseCount... | synchapi.h |
| `RemoveDirectory2A` | BOOL | _In_z_ LPCSTR lpPathName, _In_ DIRECTORY_FLAGS ... | fileapi.h |
| `RemoveDirectory2W` | BOOL | _In_z_ LPCWSTR lpPathName, _In_ DIRECTORY_FLAGS... | fileapi.h |
| `RemoveDirectoryA` | BOOL | _In_ LPCSTR lpPathName | fileapi.h |
| `RemoveDirectoryW` | BOOL | _In_ LPCWSTR lpPathName | fileapi.h |
| `ResetEvent` | BOOL | _In_ HANDLE hEvent | synchapi.h |
| `ResetWriteWatch` | UINT | _In_ LPVOID lpBaseAddress, _In_ SIZE_T dwRegion... | memoryapi.h |
| `ResumeThread` | DWORD | _In_ HANDLE hThread | processthreadsapi.h |
| `SetCriticalSectionSpinCount` | DWORD | _Inout_ LPCRITICAL_SECTION lpCriticalSection, _... | synchapi.h |
| `SetEndOfFile` | BOOL | _In_ HANDLE hFile | fileapi.h |
| `SetEvent` | BOOL | _In_ HANDLE hEvent | synchapi.h |
| `SetFileApisToANSI` | VOID | VOID  | fileapi.h |
| `SetFileApisToOEM` | VOID | VOID  | fileapi.h |
| `SetFileAttributesA` | BOOL | _In_ LPCSTR lpFileName, _In_ DWORD dwFileAttrib... | fileapi.h |
| `SetFileAttributesW` | BOOL | _In_ LPCWSTR lpFileName, _In_ DWORD dwFileAttri... | fileapi.h |
| `SetFileInformationByHandle` | BOOL | _In_ HANDLE hFile, _In_ FILE_INFO_BY_HANDLE_CLA... | fileapi.h |
| `SetFileIoOverlappedRange` | BOOL | _In_ HANDLE FileHandle, _In_ PUCHAR OverlappedR... | fileapi.h |
| `SetFilePointer` | DWORD | _In_ HANDLE hFile, _In_ LONG lDistanceToMove, _... | fileapi.h |
| `SetFilePointerEx` | BOOL | _In_ HANDLE hFile, _In_ LARGE_INTEGER liDistanc... | fileapi.h |
| `SetFileTime` | BOOL | _In_ HANDLE hFile, _In_opt_ CONST FILETIME* lpC... | fileapi.h |
| `SetFileValidData` | BOOL | _In_ HANDLE hFile, _In_ LONGLONG ValidDataLength | fileapi.h |
| `SetPriorityClass` | BOOL | _In_ HANDLE hProcess, _In_ DWORD dwPriorityClass | processthreadsapi.h |
| `SetProcessAffinityUpdateMode` | BOOL | _In_ HANDLE hProcess, _In_ DWORD dwFlags | processthreadsapi.h |
| `SetProcessDynamicEHContinuationTargets` | BOOL | _In_ HANDLE Process, _In_ USHORT NumberOfTarget... | processthreadsapi.h |
| `SetProcessDynamicEnforcedCetCompatibleRanges` | BOOL | _In_ HANDLE Process, _In_ USHORT NumberOfRanges... | processthreadsapi.h |
| `SetProcessInformation` | BOOL | _In_ HANDLE hProcess, _In_ PROCESS_INFORMATION_... | processthreadsapi.h |
| `SetProcessMitigationPolicy` | BOOL | _In_ PROCESS_MITIGATION_POLICY MitigationPolicy... | processthreadsapi.h |
| `SetProcessPriorityBoost` | BOOL | _In_ HANDLE hProcess, _In_ BOOL bDisablePriorit... | processthreadsapi.h |
| `SetProcessShutdownParameters` | BOOL | _In_ DWORD dwLevel, _In_ DWORD dwFlags | processthreadsapi.h |
| `SetProcessValidCallTargets` | BOOL | _In_ HANDLE hProcess, _In_ PVOID VirtualAddress... | memoryapi.h |
| `SetProcessValidCallTargetsForMappedView` | BOOL | _In_ HANDLE Process, _In_ PVOID VirtualAddress,... | memoryapi.h |
| `SetProcessWorkingSetSize` | BOOL | _In_ HANDLE hProcess, _In_ SIZE_T dwMinimumWork... | memoryapi.h |
| `SetProcessWorkingSetSizeEx` | BOOL | _In_ HANDLE hProcess, _In_ SIZE_T dwMinimumWork... | memoryapi.h |
| `SetProtectedPolicy` | BOOL | _In_ LPCGUID PolicyGuid, _In_ ULONG_PTR PolicyV... | processthreadsapi.h |
| `SetSystemFileCacheSize` | BOOL | _In_ SIZE_T MinimumFileCacheSize, _In_ SIZE_T M... | memoryapi.h |
| `SetThreadContext` | BOOL | _In_ HANDLE hThread, _In_ CONST CONTEXT* lpContext | processthreadsapi.h |
| `SetThreadDescription` | HRESULT | _In_ HANDLE hThread, _In_ PCWSTR lpThreadDescri... | processthreadsapi.h |
| `SetThreadIdealProcessor` | DWORD | _In_ HANDLE hThread, _In_ DWORD dwIdealProcessor | processthreadsapi.h |
| `SetThreadIdealProcessorEx` | BOOL | _In_ HANDLE hThread, _In_ PPROCESSOR_NUMBER lpI... | processthreadsapi.h |
| `SetThreadInformation` | BOOL | _In_ HANDLE hThread, _In_ THREAD_INFORMATION_CL... | processthreadsapi.h |
| `SetThreadPriority` | BOOL | _In_ HANDLE hThread, _In_ int nPriority | processthreadsapi.h |
| `SetThreadPriorityBoost` | BOOL | _In_ HANDLE hThread, _In_ BOOL bDisablePriority... | processthreadsapi.h |
| `SetThreadStackGuarantee` | BOOL | _Inout_ PULONG StackSizeInBytes | processthreadsapi.h |
| `SetThreadToken` | _Must_inspect_result_
BOOL | _In_opt_ PHANDLE Thread, _In_opt_ HANDLE Token | processthreadsapi.h |
| `SetWaitableTimer` | BOOL | _In_ HANDLE hTimer, _In_ const LARGE_INTEGER* l... | synchapi.h |
| `SignalObjectAndWait` | DWORD | _In_ HANDLE hObjectToSignal, _In_ HANDLE hObjec... | synchapi.h |
| `Sleep` | VOID | _In_ DWORD dwMilliseconds | synchapi.h |
| `SleepConditionVariableCS` | BOOL | _Inout_ PCONDITION_VARIABLE ConditionVariable, ... | synchapi.h |
| `SleepConditionVariableSRW` | BOOL | _Inout_ PCONDITION_VARIABLE ConditionVariable, ... | synchapi.h |
| `SleepEx` | DWORD | _In_ DWORD dwMilliseconds, _In_ BOOL bAlertable | synchapi.h |
| `SuspendThread` | DWORD | _In_ HANDLE hThread | processthreadsapi.h |
| `SwitchToThread` | BOOL | VOID  | processthreadsapi.h |
| `TerminateProcess` | BOOL | _In_ HANDLE hProcess, _In_ UINT uExitCode | processthreadsapi.h |
| `TerminateThread` | BOOL | _In_ HANDLE hThread, _In_ DWORD dwExitCode | processthreadsapi.h |
| `TlsAlloc` | DWORD | VOID  | processthreadsapi.h |
| `TlsFree` | BOOL | _In_ DWORD dwTlsIndex | processthreadsapi.h |
| `TlsGetValue` | LPVOID | _In_ DWORD dwTlsIndex | processthreadsapi.h |
| `TlsGetValue2` | LPVOID | _In_ DWORD dwTlsIndex | processthreadsapi.h |
| `TlsSetValue` | BOOL | _In_ DWORD dwTlsIndex, _In_opt_ LPVOID lpTlsValue | processthreadsapi.h |
| `TryEnterCriticalSection` | BOOL | _Inout_ LPCRITICAL_SECTION lpCriticalSection | synchapi.h |
| `UnlockFile` | BOOL | _In_ HANDLE hFile, _In_ DWORD dwFileOffsetLow, ... | fileapi.h |
| `UnlockFileEx` | BOOL | _In_ HANDLE hFile, _Reserved_ DWORD dwReserved,... | fileapi.h |
| `UnmapViewOfFile` | BOOL | _In_ LPCVOID lpBaseAddress | memoryapi.h |
| `UnmapViewOfFile2` | BOOL | _In_ HANDLE Process, _In_ PVOID BaseAddress, _I... | memoryapi.h |
| `UnmapViewOfFileEx` | BOOL | _In_ PVOID BaseAddress, _In_ ULONG UnmapFlags | memoryapi.h |
| `UpdateProcThreadAttribute` | BOOL | _Inout_ LPPROC_THREAD_ATTRIBUTE_LIST lpAttribut... | processthreadsapi.h |
| `VirtualFree` | BOOL | _Pre_notnull_ _When_(dwFreeType == MEM_DECOMMIT... | memoryapi.h |
| `VirtualFreeEx` | BOOL | _In_ HANDLE hProcess, _Pre_notnull_ _When_(dwFr... | memoryapi.h |
| `VirtualLock` | BOOL | _In_ LPVOID lpAddress, _In_ SIZE_T dwSize | memoryapi.h |
| `VirtualQuery` | SIZE_T | _In_opt_ LPCVOID lpAddress, _Out_writes_bytes_t... | memoryapi.h |
| `VirtualQueryEx` | SIZE_T | _In_ HANDLE hProcess, _In_opt_ LPCVOID lpAddres... | memoryapi.h |
| `VirtualUnlock` | BOOL | _In_ LPVOID lpAddress, _In_ SIZE_T dwSize | memoryapi.h |
| `VirtualUnlockEx` | BOOL | _In_opt_ HANDLE Process, _In_ LPVOID Address, _... | memoryapi.h |
| `WaitForMultipleObjects` | DWORD | _In_ DWORD nCount, _In_reads_(nCount) CONST HAN... | synchapi.h |
| `WaitForMultipleObjectsEx` | DWORD | _In_ DWORD nCount, _In_reads_(nCount) CONST HAN... | synchapi.h |
| `WaitForSingleObject` | DWORD | _In_ HANDLE hHandle, _In_ DWORD dwMilliseconds | synchapi.h |
| `WaitForSingleObjectEx` | DWORD | _In_ HANDLE hHandle, _In_ DWORD dwMilliseconds,... | synchapi.h |
| `WakeAllConditionVariable` | VOID | _Inout_ PCONDITION_VARIABLE ConditionVariable | synchapi.h |
| `WakeConditionVariable` | VOID | _Inout_ PCONDITION_VARIABLE ConditionVariable | synchapi.h |
| `WriteFile` | BOOL | _In_ HANDLE hFile, _In_reads_bytes_opt_(nNumber... | fileapi.h |
| `WriteFileEx` | BOOL | _In_ HANDLE hFile, _In_reads_bytes_opt_(nNumber... | fileapi.h |
| `WriteFileGather` | BOOL | _In_ HANDLE hFile, _In_ FILE_SEGMENT_ELEMENT aS... | fileapi.h |

### unknown.dll (91 functions)

| Function | Return Type | Parameters | Source |
|----------|-------------|------------|--------|
| `AddDllDirectory` | DLL_DIRECTORY_COOKIE | _In_ PCWSTR NewDirectory | libloaderapi.h |
| `AddVectoredContinueHandler` | _Ret_maybenull_
PVOID | _In_ ULONG First, _In_ PVECTORED_EXCEPTION_HAND... | errhandlingapi.h |
| `AddVectoredExceptionHandler` | _Ret_maybenull_
PVOID | _In_ ULONG First, _In_ PVECTORED_EXCEPTION_HAND... | errhandlingapi.h |
| `DisableThreadLibraryCalls` | BOOL | _In_ HMODULE hLibModule | libloaderapi.h |
| `EnumResourceLanguagesExA` | BOOL | _In_opt_ HMODULE hModule, _In_ LPCSTR lpType, _... | libloaderapi.h |
| `EnumResourceLanguagesExW` | BOOL | _In_opt_ HMODULE hModule, _In_ LPCWSTR lpType, ... | libloaderapi.h |
| `EnumResourceNamesA` | BOOL | _In_opt_ HMODULE hModule, _In_ LPCSTR lpType, _... | libloaderapi.h |
| `EnumResourceNamesExA` | BOOL | _In_opt_ HMODULE hModule, _In_ LPCSTR lpType, _... | libloaderapi.h |
| `EnumResourceNamesExW` | BOOL | _In_opt_ HMODULE hModule, _In_ LPCWSTR lpType, ... | libloaderapi.h |
| `EnumResourceNamesW` | BOOL | _In_opt_ HMODULE hModule, _In_ LPCWSTR lpType, ... | libloaderapi.h |
| `EnumResourceTypesExA` | BOOL | _In_opt_ HMODULE hModule, _In_ ENUMRESTYPEPROCA... | libloaderapi.h |
| `EnumResourceTypesExW` | BOOL | _In_opt_ HMODULE hModule, _In_ ENUMRESTYPEPROCW... | libloaderapi.h |
| `EnumSystemFirmwareTables` | UINT | _In_ DWORD FirmwareTableProviderSignature, _Out... | sysinfoapi.h |
| `FatalAppExitA` | VOID | _In_ UINT uAction, _In_ LPCSTR lpMessageText | errhandlingapi.h |
| `FatalAppExitW` | VOID | _In_ UINT uAction, _In_ LPCWSTR lpMessageText | errhandlingapi.h |
| `FindResourceExW` | _Ret_maybenull_
HRSRC | _In_opt_ HMODULE hModule, _In_ LPCWSTR lpType, ... | libloaderapi.h |
| `FindResourceW` | _Ret_maybenull_
HRSRC | _In_opt_ HMODULE hModule, _In_ LPCWSTR lpName, ... | libloaderapi.h |
| `FindStringOrdinal` | int | _In_ DWORD dwFindStringOrdinalFlags, _In_reads_... | libloaderapi.h |
| `FreeLibrary` | BOOL | _In_ HMODULE hLibModule | libloaderapi.h |
| `FreeLibraryAndExitThread` | DECLSPEC_NORETURN
VOID | _In_ HMODULE hLibModule, _In_ DWORD dwExitCode | libloaderapi.h |
| `FreeResource` | BOOL | _In_ HGLOBAL hResData | libloaderapi.h |
| `GetDeveloperDriveEnablementState` | DEVELOPER_DRIVE_ENABLEMENT_STATE | VOID  | sysinfoapi.h |
| `GetErrorMode` | UINT | VOID  | errhandlingapi.h |
| `GetIntegratedDisplaySize` | HRESULT | _Out_ double* sizeInInches | sysinfoapi.h |
| `GetLastError` | _Check_return_
_Post_equals_last_error_
DWORD | VOID  | errhandlingapi.h |
| `GetLocalTime` | VOID | _Out_ LPSYSTEMTIME lpSystemTime | sysinfoapi.h |
| `GetLogicalProcessorInformation` | BOOL | _Out_writes_bytes_to_opt_(*ReturnedLength,*Retu... | sysinfoapi.h |
| `GetLogicalProcessorInformationEx` | BOOL | _In_ LOGICAL_PROCESSOR_RELATIONSHIP Relationshi... | sysinfoapi.h |
| `GetModuleHandleExA` | BOOL | _In_ DWORD dwFlags, _In_opt_ LPCSTR lpModuleNam... | libloaderapi.h |
| `GetModuleHandleExW` | BOOL | _In_ DWORD dwFlags, _In_opt_ LPCWSTR lpModuleNa... | libloaderapi.h |
| `GetNativeSystemInfo` | VOID | _Out_ LPSYSTEM_INFO lpSystemInfo | sysinfoapi.h |
| `GetOsManufacturingMode` | BOOL | _Out_ PBOOL pbEnabled | sysinfoapi.h |
| `GetOsSafeBootMode` | BOOL | _Out_ PDWORD Flags | sysinfoapi.h |
| `GetProcAddress` | FARPROC | _In_ HMODULE hModule, _In_ LPCSTR lpProcName | libloaderapi.h |
| `GetProcessHeap` | HANDLE | VOID  | heapapi.h |
| `GetProcessHeaps` | DWORD | _In_ DWORD NumberOfHeaps, _Out_writes_to_(Numbe... | heapapi.h |
| `GetProcessorSystemCycleTime` | BOOL | _In_ USHORT Group, _Out_writes_bytes_to_opt_(*R... | sysinfoapi.h |
| `GetProductInfo` | BOOL | _In_ DWORD dwOSMajorVersion, _In_ DWORD dwOSMin... | sysinfoapi.h |
| `GetSystemFirmwareTable` | UINT | _In_ DWORD FirmwareTableProviderSignature, _In_... | sysinfoapi.h |
| `GetSystemInfo` | VOID | _Out_ LPSYSTEM_INFO lpSystemInfo | sysinfoapi.h |
| `GetSystemLeapSecondInformation` | BOOL | _Out_ PBOOL Enabled, _Out_ PDWORD Flags | sysinfoapi.h |
| `GetSystemTime` | VOID | _Out_ LPSYSTEMTIME lpSystemTime | sysinfoapi.h |
| `GetSystemTimeAsFileTime` | VOID | _Out_ LPFILETIME lpSystemTimeAsFileTime | sysinfoapi.h |
| `GetSystemTimePreciseAsFileTime` | VOID | _Out_ LPFILETIME lpSystemTimeAsFileTime | sysinfoapi.h |
| `GetThreadErrorMode` | DWORD | VOID  | errhandlingapi.h |
| `GetTickCount` | DWORD | VOID  | sysinfoapi.h |
| `GetTickCount64` | ULONGLONG | VOID  | sysinfoapi.h |
| `GlobalMemoryStatusEx` | BOOL | _Out_ LPMEMORYSTATUSEX lpBuffer | sysinfoapi.h |
| `HeapCompact` | SIZE_T | _In_ HANDLE hHeap, _In_ DWORD dwFlags | heapapi.h |
| `HeapCreate` | _Ret_maybenull_
HANDLE | _In_ DWORD flOptions, _In_ SIZE_T dwInitialSize... | heapapi.h |
| `HeapDestroy` | BOOL | _In_ HANDLE hHeap | heapapi.h |
| `HeapLock` | BOOL | _In_ HANDLE hHeap | heapapi.h |
| `HeapQueryInformation` | BOOL | _In_opt_ HANDLE HeapHandle, _In_ HEAP_INFORMATI... | heapapi.h |
| `HeapSetInformation` | BOOL | _In_opt_ HANDLE HeapHandle, _In_ HEAP_INFORMATI... | heapapi.h |
| `HeapSize` | SIZE_T | _In_ HANDLE hHeap, _In_ DWORD dwFlags, _In_ LPC... | heapapi.h |
| `HeapUnlock` | BOOL | _In_ HANDLE hHeap | heapapi.h |
| `HeapValidate` | BOOL | _In_ HANDLE hHeap, _In_ DWORD dwFlags, _In_opt_... | heapapi.h |
| `HeapWalk` | BOOL | _In_ HANDLE hHeap, _Inout_ LPPROCESS_HEAP_ENTRY... | heapapi.h |
| `InstallELAMCertificateInfo` | BOOL | _In_ HANDLE ELAMFile | sysinfoapi.h |
| `IsUserCetAvailableInEnvironment` | BOOL | _In_ DWORD UserCetEnvironment | sysinfoapi.h |
| `LoadLibraryA` | _Ret_maybenull_
HMODULE | _In_ LPCSTR lpLibFileName | libloaderapi.h |
| `LoadLibraryExA` | _Ret_maybenull_
HMODULE | _In_ LPCSTR lpLibFileName, _Reserved_ HANDLE hF... | libloaderapi.h |
| `LoadLibraryExW` | _Ret_maybenull_
HMODULE | _In_ LPCWSTR lpLibFileName, _Reserved_ HANDLE h... | libloaderapi.h |
| `LoadLibraryW` | _Ret_maybenull_
HMODULE | _In_ LPCWSTR lpLibFileName | libloaderapi.h |
| `LoadResource` | _Ret_maybenull_
HGLOBAL | _In_opt_ HMODULE hModule, _In_ HRSRC hResInfo | libloaderapi.h |
| `LoadStringA` | int | _In_opt_ HINSTANCE hInstance, _In_ UINT uID, _O... | libloaderapi.h |
| `LoadStringW` | int | _In_opt_ HINSTANCE hInstance, _In_ UINT uID, _O... | libloaderapi.h |
| `LockResource` | LPVOID | _In_ HGLOBAL hResData | libloaderapi.h |
| `QueryPerformanceCounter` | BOOL | _Out_ LARGE_INTEGER* lpPerformanceCount | profileapi.h |
| `QueryPerformanceFrequency` | BOOL | _Out_ LARGE_INTEGER* lpFrequency | profileapi.h |
| `RaiseException` | VOID | _In_ DWORD dwExceptionCode, _In_ DWORD dwExcept... | errhandlingapi.h |
| `RaiseFailFastException` | VOID | _In_opt_ PEXCEPTION_RECORD pExceptionRecord, _I... | errhandlingapi.h |
| `RemoveDllDirectory` | BOOL | _In_ DLL_DIRECTORY_COOKIE Cookie | libloaderapi.h |
| `RemoveVectoredContinueHandler` | ULONG | _In_ PVOID Handle | errhandlingapi.h |
| `RemoveVectoredExceptionHandler` | ULONG | _In_ PVOID Handle | errhandlingapi.h |
| `RestoreLastError` | VOID | _In_ DWORD dwErrCode | errhandlingapi.h |
| `SetComputerNameA` | BOOL | _In_ LPCSTR lpComputerName | sysinfoapi.h |
| `SetComputerNameEx2W` | BOOL | _In_ COMPUTER_NAME_FORMAT NameType, _In_ DWORD ... | sysinfoapi.h |
| `SetComputerNameExA` | BOOL | _In_ COMPUTER_NAME_FORMAT NameType, _In_ LPCSTR... | sysinfoapi.h |
| `SetComputerNameExW` | BOOL | _In_ COMPUTER_NAME_FORMAT NameType, _In_ LPCWST... | sysinfoapi.h |
| `SetComputerNameW` | BOOL | _In_ LPCWSTR lpComputerName | sysinfoapi.h |
| `SetDefaultDllDirectories` | BOOL | _In_ DWORD DirectoryFlags | libloaderapi.h |
| `SetErrorMode` | UINT | _In_ UINT uMode | errhandlingapi.h |
| `SetLastError` | VOID | _In_ DWORD dwErrCode | errhandlingapi.h |
| `SetLocalTime` | BOOL | _In_ CONST SYSTEMTIME* lpSystemTime | sysinfoapi.h |
| `SetSystemTime` | BOOL | _In_ CONST SYSTEMTIME* lpSystemTime | sysinfoapi.h |
| `SetThreadErrorMode` | BOOL | _In_ DWORD dwNewMode, _In_opt_ LPDWORD lpOldMode | errhandlingapi.h |
| `SetUnhandledExceptionFilter` | LPTOP_LEVEL_EXCEPTION_FILTER | _In_opt_ LPTOP_LEVEL_EXCEPTION_FILTER lpTopLeve... | errhandlingapi.h |
| `SizeofResource` | DWORD | _In_opt_ HMODULE hModule, _In_ HRSRC hResInfo | libloaderapi.h |
| `TerminateProcessOnMemoryExhaustion` | VOID | _In_ SIZE_T FailedAllocationSize | errhandlingapi.h |
| `UnhandledExceptionFilter` | LONG | _In_ struct _EXCEPTION_POINTERS* ExceptionInfo | errhandlingapi.h |
