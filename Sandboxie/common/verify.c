/*
 * Copyright 2021 David Xanatos, xanasoft.com
 * 
 * Based on the processhacker's CustomSignTool, Copyright 2016 wj32
 *
 * This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <ntstatus.h>
#define WIN32_NO_STATUS
typedef long NTSTATUS;

#include <windows.h>
#include <bcrypt.h>
//#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <fileapi.h>

#include "..\..\Sandboxie\common\win32_ntddk.h"



static UCHAR KphpTrustedPublicKey[] =
{
    0x45, 0x43, 0x53, 0x31, 0x20, 0x00, 0x00, 0x00, 0xDF, 0xED, 0xA9, 0x17, 0x0D, 0x2A, 0xD0, 0xF2,
    0x96, 0x2D, 0x3E, 0xC0, 0x39, 0xD6, 0xB9, 0xE0, 0xCF, 0x27, 0x55, 0x08, 0x4B, 0x77, 0xEA, 0xC1,
    0x38, 0xE0, 0x66, 0x06, 0xE0, 0xE8, 0x84, 0xB8, 0x35, 0x30, 0xD0, 0x03, 0x6E, 0xE9, 0x5A, 0x66,
    0x9E, 0x0C, 0xB6, 0x58, 0xE1, 0x0B, 0x76, 0x7D, 0x52, 0x48, 0xA9, 0x35, 0xD7, 0x4F, 0xF5, 0x6A,
    0x50, 0x66, 0xA4, 0xA8, 0xC2, 0x51, 0x0A, 0x3C
};



#define CST_SIGN_ALGORITHM BCRYPT_ECDSA_P256_ALGORITHM
#define CST_SIGN_ALGORITHM_BITS 256
#define CST_HASH_ALGORITHM BCRYPT_SHA256_ALGORITHM
#define CST_BLOB_PRIVATE BCRYPT_ECCPRIVATE_BLOB
#define CST_BLOB_PUBLIC BCRYPT_ECCPUBLIC_BLOB

#define KPH_SIGNATURE_MAX_SIZE (128 * 1024) // 128 kB

#define FILE_BUFFER_SIZE 4096


static NTSTATUS MyCreateFile(_Out_ PHANDLE FileHandle, _In_ PCWSTR FileName, _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ ULONG FileAttributes, _In_ ULONG ShareAccess, _In_ ULONG CreateDisposition, _In_ ULONG CreateOptions)
{
    UNICODE_STRING uni;
	OBJECT_ATTRIBUTES attr;
    WCHAR wszBuffer[MAX_PATH];
    _snwprintf(wszBuffer, MAX_PATH, L"\\??\\%s", FileName);
	RtlInitUnicodeString(&uni, wszBuffer);
	InitializeObjectAttributes(&attr, &uni, OBJ_CASE_INSENSITIVE, NULL, 0);

	IO_STATUS_BLOCK Iosb;
	return NtCreateFile(FileHandle, DesiredAccess, &attr, &Iosb, NULL, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, NULL, 0);
}

static NTSTATUS CstReadFile(
    _In_ PWSTR FileName,
    _In_ ULONG FileSizeLimit,
    _Out_ PVOID* Buffer,
    _Out_ PULONG FileSize
    )
{
    NTSTATUS status;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    LARGE_INTEGER fileSize;
    PVOID buffer;
    IO_STATUS_BLOCK iosb;

    if (!NT_SUCCESS(status = MyCreateFile(&fileHandle, FileName, FILE_GENERIC_READ, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE)))
        goto CleanupExit;

    if (!GetFileSizeEx(fileHandle, &fileSize) || fileSize.QuadPart > FileSizeLimit)
        goto CleanupExit;

    buffer = malloc((ULONG)fileSize.QuadPart);
    if (!NT_SUCCESS(status = NtReadFile(fileHandle, NULL, NULL, NULL, &iosb, buffer, (ULONG)fileSize.QuadPart, NULL, NULL)))
        goto CleanupExit;

    *Buffer = buffer;
    *FileSize = (ULONG)fileSize.QuadPart;

CleanupExit:
    if(fileHandle != INVALID_HANDLE_VALUE)
        NtClose(fileHandle);

    return status;
}

typedef struct {
    BCRYPT_ALG_HANDLE algHandle;
    BCRYPT_HASH_HANDLE handle;
    PVOID object;
} MY_HASH_OBJ;

static VOID MyFreeHash(MY_HASH_OBJ* pHashObj)
{
    if (pHashObj->handle)
        BCryptDestroyHash(pHashObj->handle);
    if (pHashObj->object)
        free(pHashObj->object);
    if (pHashObj->algHandle)
        BCryptCloseAlgorithmProvider(pHashObj->algHandle, 0);
}

static NTSTATUS MyInitHash(MY_HASH_OBJ* pHashObj)
{
    NTSTATUS status;
    ULONG hashObjectSize;
    ULONG querySize;
    memset(pHashObj, 0, sizeof(MY_HASH_OBJ));

    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&pHashObj->algHandle, CST_HASH_ALGORITHM, NULL, 0)))
        goto CleanupExit;

    if (!NT_SUCCESS(status = BCryptGetProperty(pHashObj->algHandle, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectSize, sizeof(ULONG), &querySize, 0)))
        goto CleanupExit;

    pHashObj->object = malloc(hashObjectSize);
    if (!pHashObj->object) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto CleanupExit;
    }

    if (!NT_SUCCESS(status = BCryptCreateHash(pHashObj->algHandle, &pHashObj->handle, (PUCHAR)pHashObj->object, hashObjectSize, NULL, 0, 0)))
        goto CleanupExit;

CleanupExit:
    if (!NT_SUCCESS(status))
        MyFreeHash(pHashObj);

    return status;
}

static NTSTATUS MyHashData(MY_HASH_OBJ* pHashObj, PVOID Data, ULONG DataSize)
{
    return BCryptHashData(pHashObj->handle, (PUCHAR)Data, DataSize, 0);
}

static NTSTATUS MyFinishHash(MY_HASH_OBJ* pHashObj, PVOID* Hash, PULONG HashSize)
{
    NTSTATUS status;
    ULONG querySize;

    if (!NT_SUCCESS(status = BCryptGetProperty(pHashObj->algHandle, BCRYPT_HASH_LENGTH, (PUCHAR)HashSize, sizeof(ULONG), &querySize, 0)))
        goto CleanupExit;

    *Hash = malloc(*HashSize);
    if (!*Hash) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto CleanupExit;
    }

    if (!NT_SUCCESS(status = BCryptFinishHash(pHashObj->handle, (PUCHAR)*Hash, *HashSize, 0)))
        goto CleanupExit;

    return STATUS_SUCCESS;

CleanupExit:
    if (*Hash) {
        free(*Hash);
        *Hash = NULL;
    }

    return status;
}


static NTSTATUS CstHashFile(
    _In_ PCWSTR FileName,
    _Out_ PVOID* Hash,
    _Out_ PULONG HashSize
    )
{
    NTSTATUS status;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    PVOID buffer = NULL;
    IO_STATUS_BLOCK iosb;
    MY_HASH_OBJ hashObj;

    if (!NT_SUCCESS(status = MyInitHash(&hashObj)))
        goto CleanupExit;

    if (!NT_SUCCESS(status = MyCreateFile(&fileHandle, FileName, FILE_GENERIC_READ, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE)))
        goto CleanupExit;

    buffer = malloc(FILE_BUFFER_SIZE);
    if (!buffer) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto CleanupExit;
    }

    while (TRUE)
    {
        if (!NT_SUCCESS(status = NtReadFile(fileHandle, NULL, NULL, NULL, &iosb, buffer, FILE_BUFFER_SIZE, NULL, NULL)))
        {
            if (status == STATUS_END_OF_FILE)
                break;

            goto CleanupExit;
        }

        if (!NT_SUCCESS(status = MyHashData(&hashObj, buffer, (ULONG)iosb.Information)))
            goto CleanupExit;
    }

    if (!NT_SUCCESS(status = MyFinishHash(&hashObj, Hash, HashSize)))
        goto CleanupExit;

CleanupExit:
    if(buffer)
        free(buffer);
    if(fileHandle != INVALID_HANDLE_VALUE)
        NtClose(fileHandle);
    MyFreeHash(&hashObj);

    return status;
}

static NTSTATUS VerifyHashSignature(PVOID Hash, ULONG HashSize, PVOID Signature, ULONG SignatureSize)
{
    NTSTATUS status;
    BCRYPT_ALG_HANDLE signAlgHandle = NULL;
    BCRYPT_KEY_HANDLE keyHandle = NULL;
    
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&signAlgHandle, CST_SIGN_ALGORITHM, NULL, 0)))
        goto CleanupExit;

    if (!NT_SUCCESS(status = BCryptImportKeyPair(signAlgHandle, NULL, CST_BLOB_PUBLIC, &keyHandle, KphpTrustedPublicKey, sizeof(KphpTrustedPublicKey), 0)))
        goto CleanupExit;


    if (!NT_SUCCESS(status = BCryptVerifySignature(keyHandle, NULL, (PUCHAR)Hash, HashSize, (PUCHAR)Signature, SignatureSize, 0)))
        goto CleanupExit;

CleanupExit:
    if (keyHandle != NULL)
        BCryptDestroyKey(keyHandle);
    if (signAlgHandle)
        BCryptCloseAlgorithmProvider(signAlgHandle, 0);

    return status;
}

NTSTATUS VerifyFileSignature(const wchar_t* FilePath)
{
    NTSTATUS status;
    ULONG hashSize;
    PVOID hash = NULL;
    ULONG signatureSize;
    PVOID signature = NULL;
    WCHAR* signatureFileName = NULL;


    // Read the signature.
    signatureFileName = (WCHAR*)malloc((wcslen(FilePath) + 4 + 1) * sizeof(WCHAR));
    if(!signatureFileName) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto CleanupExit;
    }
    wcscpy(signatureFileName, FilePath);
    wcscat(signatureFileName, L".sig");

    // Read the signature file.

    if (!NT_SUCCESS(status = CstReadFile(signatureFileName, KPH_SIGNATURE_MAX_SIZE, &signature, &signatureSize)))
        goto CleanupExit;

    // Hash the file.

    if (!NT_SUCCESS(status = CstHashFile(FilePath, &hash, &hashSize)))
        goto CleanupExit;

    // Verify the hash.

    if (!NT_SUCCESS(status = VerifyHashSignature((PUCHAR)hash, hashSize, (PUCHAR)signature, signatureSize)))
    {
        goto CleanupExit;
    }

CleanupExit:
    if (signature)
        free(signature);
    if (hash)
        free(hash);
    if (signatureFileName)
        free(signatureFileName);

    return status;
}

