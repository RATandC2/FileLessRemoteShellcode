						
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>
#pragma comment(lib, "ws2_32.lib")


DWORD g_BytesTransferred = 0;

VOID CALLBACK FileIOCompletionRoutine(
	__in  DWORD dwErrorCode,
	__in  DWORD dwNumberOfBytesTransfered,
	__in  LPOVERLAPPED lpOverlapped
);

VOID CALLBACK FileIOCompletionRoutine(
	__in  DWORD dwErrorCode,
	__in  DWORD dwNumberOfBytesTransfered,
	__in  LPOVERLAPPED lpOverlapped)
{
	_tprintf(TEXT("Error code:\t%x\n"), dwErrorCode);
	_tprintf(TEXT("Number of bytes:\t%x\n"), dwNumberOfBytesTransfered);
	g_BytesTransferred = dwNumberOfBytesTransfered;
}

int main(int argc, char** argv)
{
	LPWSADATA wsaData = new WSAData();
	ADDRINFOA* sockAddr = new ADDRINFOA();
	ADDRINFOA* addressInfo = new ADDRINFOA();
	SOCKET ServerSocket = INVALID_SOCKET;
	SOCKET clientSocket = INVALID_SOCKET;
	CHAR buffR[4096] = { 0 };
	//CHAR buffS[4096] = { 0 };
	INT recvBytes = 0;
	INT sendBytes = 0;
	PCSTR port = "443";
	HANDLE threadHandle;
	struct sockaddr_in client;
	socklen_t clientsz = sizeof(client);
		

	sockAddr->ai_family = AF_INET;
	sockAddr->ai_socktype = SOCK_STREAM;
	sockAddr->ai_protocol = IPPROTO_TCP;
	sockAddr->ai_flags = AI_PASSIVE;

	WSAStartup(MAKEWORD(2, 2), wsaData);
	GetAddrInfoA(NULL, port, sockAddr, &addressInfo);
	printf("[+] Creating the Server socket\n");
	ServerSocket = socket(addressInfo->ai_family, addressInfo->ai_socktype, addressInfo->ai_protocol);
	bind(ServerSocket, addressInfo->ai_addr, addressInfo->ai_addrlen);
	listen(ServerSocket, SOMAXCONN);
	printf("[+] Listening on port %s\n", port);

	printf("[+] Accepting Client Connections\n");
	clientSocket = accept(ServerSocket, NULL, NULL);
	getsockname(clientSocket, (struct sockaddr*)&client, &clientsz);

	printf("[+] Getting connection from %s:%u\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));

	DWORD  dwBytesRead = 0;
	char   ReadBuffer[4096] = { 0 };
	OVERLAPPED ol = { 0 };

	char* filePath = argv[1];

	HANDLE hFile = CreateFileA(filePath,               // file to open
		GENERIC_READ,          // open for reading
		FILE_SHARE_READ,       // share for reading
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_NORMAL, // normal file
		NULL);                 // no attr. template

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Failed in CreateFileA (%u)", GetLastError());
		return -1;
	}

	if (FALSE == ReadFileEx(hFile, ReadBuffer, 4096, &ol, FileIOCompletionRoutine))
	{
		printf("Failed in ReadFileEx (%u)", GetLastError());
		CloseHandle(hFile);
		return -1;
	}

	CloseHandle(hFile);
	recvBytes = recv(clientSocket, buffR, sizeof(buffR), NULL);
	if (recvBytes > 0) {
		printf("[+] Received %d bytes\n", recvBytes);
		sendBytes = send(clientSocket, ReadBuffer, 4096, NULL);
	}
	closesocket(clientSocket);
	closesocket(ServerSocket);
	return 0;
}