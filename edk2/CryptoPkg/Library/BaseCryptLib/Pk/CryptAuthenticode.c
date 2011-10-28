/** @file
  Authenticode Portable Executable Signature Verification over OpenSSL.

Copyright (c) 2011, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "InternalCryptLib.h"

#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>


/**
  Verifies the validility of a PE/COFF Authenticode Signature as described in "Windows
  Authenticode Portable Executable Signature Format".

  If AuthData is NULL, then ASSERT().
  If ImageHash is NULL, then ASSERT().

  @param[in]  AuthData     Pointer to the Authenticode Signature retrieved from signed
                           PE/COFF image to be verified.
  @param[in]  DataSize     Size of the Authenticode Signature in bytes.
  @param[in]  TrustedCert  Pointer to a trusted/root certificate encoded in DER, which
                           is used for certificate chain verification.
  @param[in]  CertSize     Size of the trusted certificate in bytes.
  @param[in]  ImageHash    Pointer to the original image file hash value. The procudure
                           for calculating the image hash value is described in Authenticode
                           specification.
  @param[in]  HashSize     Size of Image hash value in bytes.

  @retval  TRUE   The specified Authenticode Signature is valid.
  @retval  FALSE  Invalid Authenticode Signature.

**/
BOOLEAN
EFIAPI
AuthenticodeVerify (
  IN  CONST UINT8  *AuthData,
  IN  UINTN        DataSize,
  IN  CONST UINT8  *TrustedCert,
  IN  UINTN        CertSize,
  IN  CONST UINT8  *ImageHash,
  IN  UINTN        HashSize
  )
{
  BOOLEAN      Status;
  PKCS7        *Pkcs7;
  CONST UINT8  *OrigAuthData;
  UINT8        *SpcIndirectDataContent;
  UINT8        Asn1Byte;
  UINTN        ContentSize;

  //
  // ASSERT if Authenticode Signature Data or PE Image Hash is NULL
  //
  ASSERT (AuthData  != NULL);
  ASSERT (ImageHash != NULL);

  if (DataSize > INT_MAX) {
    return FALSE;
  }

  Status       = FALSE;
  Pkcs7        = NULL;
  OrigAuthData = AuthData;

  //
  // Retrieve & Parse PKCS#7 Data (DER encoding) from Authenticode Signature
  //
  Pkcs7 = d2i_PKCS7 (NULL, &AuthData, (int)DataSize);
  if (Pkcs7 == NULL) {
    goto _Exit;
  }

  //
  // Check if it's PKCS#7 Signed Data (for Authenticode Scenario)
  //
  if (!PKCS7_type_is_signed (Pkcs7)) {
    goto _Exit;
  }

  //
  // NOTE: OpenSSL PKCS7 Decoder didn't work for Authenticode-format signed data due to
  //       some authenticode-specific structure. Use opaque ASN.1 string to retrieve
  //       PKCS#7 ContentInfo here.
  //
  SpcIndirectDataContent = (UINT8 *)(Pkcs7->d.sign->contents->d.other->value.asn1_string->data);

  //
  // Retrieve the SEQUENCE data size from ASN.1-encoded SpcIndirectDataContent.
  //
  Asn1Byte = *(SpcIndirectDataContent + 1);
  if ((Asn1Byte & 0x80) == 0) {
    //
    // Short Form of Length Encoding
    //
    ContentSize = (UINTN) (Asn1Byte & 0x7F);
    //
    // Skip the SEQUENCE Tag;
    //
    SpcIndirectDataContent += 2;
  } else {
    //
    // Long Form of Length Encoding (Assume Only two bytes here)
    //
    ContentSize  = (UINTN) (*(SpcIndirectDataContent + 2));
    ContentSize = (ContentSize << 8) + (UINTN)(*(SpcIndirectDataContent + 3));
    //
    // Skip the SEQUENCE Tag;
    //
    SpcIndirectDataContent += 4;
  }

  //
  // Compare the original file hash value to the digest retrieve from SpcIndirectDataContent
  // defined in Authenticode
  // NOTE: Need to double-check HashLength here!
  //
  if (CompareMem (SpcIndirectDataContent + ContentSize - HashSize, ImageHash, HashSize) != 0) {
    //
    // Un-matched PE/COFF Hash Value
    //
    goto _Exit;
  }

  //
  // Verifies the PKCS#7 Signed Data in PE/COFF Authenticode Signature
  //
  Status = (BOOLEAN) Pkcs7Verify (OrigAuthData, DataSize, TrustedCert, CertSize, SpcIndirectDataContent, ContentSize);

_Exit:
  //
  // Release Resources
  //
  PKCS7_free (Pkcs7);

  return Status;
}
