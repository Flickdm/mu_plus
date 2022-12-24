#ifndef AUTH_DATA_H_
#define AUTH_DATA_H_

#include <Uefi/UefiBaseType.h>

//
// Refer to "AuthData.c" for details on the following objects.
//
// Key Layout
//
//      ┌───┐* self signed
// ┌────┴───▼───┐         ┌────────────┐        ┌────────────┐
// │ Mock 2K PK ├─────────► Mock 3K PK ├────────► Mock 4K PK │
// └────┬───────┘         └────┬───────┘        └────┬───────┘
//      │                      │                     │
// ┌────▼────────┐        ┌────▼────────┐       ┌────▼────────┐
// │ Mock 2K KEK │        │ Mock 3K KEK │       │ Mock 4K KEK │
// └────┬────────┘        └────┬────────┘       └────┬────────┘
//      │                      │                     │
// ┌────▼─────────┐       ┌────▼─────────┐      ┌────▼─────────┐
// │ Mock 2K LC   │       │ Mock 3K LC   │      │ Mock 4K LC   │
// └──────────────┘       └──────────────┘      └──────────────┘
// 


// Variable: L"MockPK"
// Issuer: CN=2K Mock Platform Key
// Validity
//     Not Before: Dec 19 19:05:53 2022 GMT
//     Not After : Dec 16 19:05:53 2032 GMT
// Subject: CN=2K Mock Platform Key
// Attributes: EFI_VARIABLE_NON_VOLATILE,
//    EFI_VARIABLE_RUNTIME_ACCESS,
//    EFI_VARIABLE_BOOTSERVICE_ACCESS
//    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
// Data: Hello 2K MockPK\n
extern UINT8 m2kMockPK[];
extern UINTN m2kMockPKSize;

// Variable: L"MockPK"
// Issuer: CN=2K Mock Platform Key
// Validity
//     Not Before: Dec 19 19:05:53 2022 GMT
//     Not After : Dec 16 19:05:53 2032 GMT
// Subject: CN=2K Mock Platform Key
// Attributes: EFI_VARIABLE_NON_VOLATILE,
//    EFI_VARIABLE_RUNTIME_ACCESS,
//    EFI_VARIABLE_BOOTSERVICE_ACCESS
//    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
// Data: <empty> // Clears the variable
extern UINT8 m2kMockPKDelete[];
extern UINTN m2kMockPKDeleteSize;

// Variable: L"MockKEK"
// Issuer: CN=2K Mock Platform Key
// Validity
//      Not Before: Dec 19 20:47:31 2022 GMT
//      Not After : Dec 16 20:47:31 2032 GMT
// Signer: CN=2K Mock Key Exchange Key
// Attributes: EFI_VARIABLE_NON_VOLATILE,
//    EFI_VARIABLE_RUNTIME_ACCESS,
//    EFI_VARIABLE_BOOTSERVICE_ACCESS
//    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
// Data: Hello 2K MockKEK\n
extern UINT8 m2kMockKEK[];
extern UINTN m2kMockKEKSize;

// Variable: L"MockKEK"
// Issuer: CN=2K Mock Platform Key
// Validity
//      Not Before: Dec 19 20:47:31 2022 GMT
//      Not After : Dec 16 20:47:31 2032 GMT
// Signer: CN=2K Mock Key Exchange Key
// Attributes: EFI_VARIABLE_NON_VOLATILE,
//    EFI_VARIABLE_RUNTIME_ACCESS,
//    EFI_VARIABLE_BOOTSERVICE_ACCESS
//    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
// Data: <empty> // Clears the variable
extern UINT8 m2kMockKEKDelete[];
extern UINTN m2kMockKEKDeleteSize;

// Variable: L"MockLC"
// Issuer: CN=2K Mock Key Exchange Key
// Validity
//     Not Before: Dec 19 21:48:21 2022 GMT
//     Not After : Dec 19 21:48:21 2023 GMT
// Subject: CN=Mock 2K Leaf Certificate
// Attributes: EFI_VARIABLE_NON_VOLATILE,
//    EFI_VARIABLE_RUNTIME_ACCESS,
//    EFI_VARIABLE_BOOTSERVICE_ACCESS
//    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
// Data: Hello 2K Leaf Certificate
extern UINT8 m2kMockLeaf[];
extern UINTN m2kMockLeafSize;

// Variable: L"MockLC"
// Issuer: CN=2K Mock Key Exchange Key
// Validity
//     Not Before: Dec 19 21:48:21 2022 GMT
//     Not After : Dec 19 21:48:21 2023 GMT
// Subject: CN=Mock 2K Leaf Certificate
// Attributes: EFI_VARIABLE_NON_VOLATILE,
//    EFI_VARIABLE_RUNTIME_ACCESS,
//    EFI_VARIABLE_BOOTSERVICE_ACCESS
//    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
// Data: <empty>
extern UINT8 m2kMockLeafDelete[];
extern UINTN m2kMockLeafDeleteSize;

// ====================================== 3k =========================================

// Variable: L"MockPK"
// Issuer: CN=2K Mock Platform Key
// Validity
//    Not Before: Dec 20 03:38:48 2022 GMT
//    Not After : Dec 17 03:38:48 2032 GMT
// Subject: CN=3K Mock Platform Key
// Attributes: EFI_VARIABLE_NON_VOLATILE,
//    EFI_VARIABLE_RUNTIME_ACCESS,
//    EFI_VARIABLE_BOOTSERVICE_ACCESS
//    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
// Data: Hello 3K MockPK\n
extern UINT8 m3kMockPK[];
extern UINTN m3kMockPKSize;

// Variable: L"MockPK"
// Issuer: CN=2K Mock Platform Key
// Validity
//     Not Before: Dec 19 19:05:53 2022 GMT
//     Not After : Dec 16 19:05:53 2032 GMT
// Subject: CN=3K Mock Platform Key
// Attributes: EFI_VARIABLE_NON_VOLATILE,
//    EFI_VARIABLE_RUNTIME_ACCESS,
//    EFI_VARIABLE_BOOTSERVICE_ACCESS
//    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
// Data: <empty> // Clears the variable
extern UINT8 m3kMockPKDelete[];
extern UINTN m3kMockPKDeleteSize;

// Variable: L"MockKEK"
// Issuer: CN=3K Mock Platform Key
// Validity
//      Not Before: Dec 19 20:47:31 2022 GMT
//      Not After : Dec 16 20:47:31 2032 GMT
// Signer: CN=3K Mock Key Exchange Key
// Attributes: EFI_VARIABLE_NON_VOLATILE,
//    EFI_VARIABLE_RUNTIME_ACCESS,
//    EFI_VARIABLE_BOOTSERVICE_ACCESS
//    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
// Data: Hello 3K MockKEK\n
extern UINT8 m3kMockKEK[];
extern UINTN m3kMockKEKSize;

// Variable: L"MockKEK"
// Issuer: CN=3K Mock Platform Key
// Validity
//    Not Before: Dec 20 04:15:14 2022 GMT
//    Not After : Dec 17 04:15:14 2032 GMT
// Signer: CN=3K Mock Key Exchange Key
// Attributes: EFI_VARIABLE_NON_VOLATILE,
//    EFI_VARIABLE_RUNTIME_ACCESS,
//    EFI_VARIABLE_BOOTSERVICE_ACCESS
//    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
// Data: <empty> // Clears the variable
extern UINT8 m3kMockKEKDelete[];
extern UINTN m3kMockKEKDeleteSize;

// Variable: L"MockLC"
// Issuer: CN=3K Mock Key Exchange Key
// Validity
//     Not Before: Dec 20 05:20:51 2022 GMT
//     Not After : Dec 20 05:20:51 2023 GMT
// Subject: CN=Mock 3K Leaf Certificate
// Attributes: EFI_VARIABLE_NON_VOLATILE,
//    EFI_VARIABLE_RUNTIME_ACCESS,
//    EFI_VARIABLE_BOOTSERVICE_ACCESS
//    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
// Data: Hello 3K Leaf Certificate\n
extern UINT8 m3kMockLeaf[];
extern UINTN m3kMockLeafSize;

// Variable: L"MockLC"
// Issuer: CN=3K Mock Key Exchange Key
// Validity
//     Not Before: Dec 20 05:20:51 2022 GMT
//     Not After : Dec 20 05:20:51 2023 GMT
// Subject: CN=Mock 3K Leaf Certificate
// Attributes: EFI_VARIABLE_NON_VOLATILE,
//    EFI_VARIABLE_RUNTIME_ACCESS,
//    EFI_VARIABLE_BOOTSERVICE_ACCESS
//    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
// Data: <empty> // Clears the variable
extern UINT8 m3kMockLeafDelete[];
extern UINTN m3kMockLeafDeleteSize;

// ====================================== 4k =========================================

// Variable: L"MockPK"
// Issuer: CN=3K Mock Platform Key
// Validity
//    Not Before: Dec 20 06:00:15 2022 GMT
//    Not After : Dec 17 06:00:15 2032 GMT
// Subject: CN=4K Mock Platform Key
// Attributes: EFI_VARIABLE_NON_VOLATILE,
//    EFI_VARIABLE_RUNTIME_ACCESS,
//    EFI_VARIABLE_BOOTSERVICE_ACCESS
//    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
// Data: Hello 4K MockPK\n
extern UINT8 m4kMockPK[];
extern UINTN m4kMockPKSize;

// Variable: L"MockPK"
// Issuer: CN=3K Mock Platform Key
// Validity
//    Not Before: Dec 20 06:00:15 2022 GMT
//    Not After : Dec 17 06:00:15 2032 GMT
// Subject: CN=4K Mock Platform Key
// Attributes: EFI_VARIABLE_NON_VOLATILE,
//    EFI_VARIABLE_RUNTIME_ACCESS,
//    EFI_VARIABLE_BOOTSERVICE_ACCESS
//    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
// Data: <empty> // Clears the variable
extern UINT8 m4kMockPKDelete[];
extern UINTN m4kMockPKDeleteSize;

// Variable: L"MockKEK"
// Issuer: CN=4K Mock Platform Key
// Validity
//     Not Before: Dec 20 06:31:05 2022 GMT
//     Not After : Dec 17 06:31:05 2032 GMT
// Subject: CN=4K Mock Key Exchange Key
// Attributes: EFI_VARIABLE_NON_VOLATILE,
//    EFI_VARIABLE_RUNTIME_ACCESS,
//    EFI_VARIABLE_BOOTSERVICE_ACCESS
//    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
// Data: Hello 4K MockKEK\n
extern UINT8 m4kMockKEK[];
extern UINTN m4kMockKEKSize;

// Variable: L"MockKEK"
// Issuer: CN=4K Mock Platform Key
// Validity
//     Not Before: Dec 20 06:31:05 2022 GMT
//     Not After : Dec 17 06:31:05 2032 GMT
// Subject: CN=4K Mock Key Exchange Key
// Attributes: EFI_VARIABLE_NON_VOLATILE,
//    EFI_VARIABLE_RUNTIME_ACCESS,
//    EFI_VARIABLE_BOOTSERVICE_ACCESS
//    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
// Data: <empty> // Clears the variable
extern UINT8 m4kMockKEKDelete[];
extern UINTN m4kMockKEKDeleteSize;

// Variable: L"MockLC"
// Issuer: CN=4K Mock Key Exchange Key
// Validity
//    Not Before: Dec 20 06:34:58 2022 GMT
//    Not After : Dec 20 06:34:58 2023 GMT
// Subject: CN=Mock 4K Leaf Certificate
// Attributes: EFI_VARIABLE_NON_VOLATILE,
//    EFI_VARIABLE_RUNTIME_ACCESS,
//    EFI_VARIABLE_BOOTSERVICE_ACCESS
//    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
// Data: Hello 4K Leaf Certificate\n
extern UINT8 m4kMockLeaf[];
extern UINTN m4kMockLeafSize;

// Variable: L"MockLC"
// Issuer: CN=4K Mock Key Exchange Key
// Validity
//    Not Before: Dec 20 06:34:58 2022 GMT
//    Not After : Dec 20 06:34:58 2023 GMT
// Subject: CN=Mock 4K Leaf Certificate
// Attributes: EFI_VARIABLE_NON_VOLATILE,
//    EFI_VARIABLE_RUNTIME_ACCESS,
//    EFI_VARIABLE_BOOTSERVICE_ACCESS
//    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
// Data: <empty> // Clears the variable
extern UINT8 m4kMockLeafDelete[];
extern UINTN m4kMockLeafDeleteSize;


#endif // AUTH_DATA_H_