/**@file
  This file contains the form processing code to the HII database.

Copyright (c) 2006 - 2008 Intel Corporation. <BR>
All rights reserved. This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/


#include "HiiDatabase.h"

EFI_STATUS
EFIAPI
HiiExportDatabase (
  IN     EFI_HII_PROTOCOL *This,
  IN     FRAMEWORK_EFI_HII_HANDLE    Handle,
  IN OUT UINTN            *BufferSize,
  OUT    VOID             *Buffer
  )
/*++

Routine Description:

  This function allows a program to extract a form or form package that has
  previously been registered with the EFI HII database.

Arguments:

Returns:

--*/
{
  ASSERT (FALSE);
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
HiiGetForms (
  IN     EFI_HII_PROTOCOL   *This,
  IN     FRAMEWORK_EFI_HII_HANDLE      Handle,
  IN     EFI_FORM_ID        FormId,
  IN OUT UINTN              *BufferLengthTemp,
  OUT    UINT8              *Buffer
  )
/*++

Routine Description:

  This function allows a program to extract a form or form package that has
  previously been registered with the EFI HII database.

Arguments:
  This         - A pointer to the EFI_HII_PROTOCOL instance.

  Handle       - Handle on which the form resides. Type FRAMEWORK_EFI_HII_HANDLE  is defined in
                 EFI_HII_PROTOCOL.NewPack() in the Packages section.

  FormId       - The ID of the form to return. If the ID is zero, the entire form package is returned.
                 Type EFI_FORM_ID is defined in "Related Definitions" below.

  BufferLength - On input, the length of the Buffer. On output, the length of the returned buffer, if
                 the length was sufficient and, if it was not, the length that is required to fit the
                 requested form(s).

  Buffer       - The buffer designed to receive the form(s).

Returns:

  EFI_SUCCESS           -  Buffer filled with the requested forms. BufferLength
                           was updated.

  EFI_INVALID_PARAMETER -  The handle is unknown.

  EFI_NOT_FOUND         -  A form on the requested handle cannot be found with the
                           requested FormId.

  EFI_BUFFER_TOO_SMALL  - The buffer provided was not large enough to allow the form to be stored.

--*/
{
  ASSERT (FALSE);
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
HiiGetDefaultImage (
  IN     EFI_HII_PROTOCOL            *This,
  IN     FRAMEWORK_EFI_HII_HANDLE    Handle,
  IN     UINTN                       DefaultMask,
  OUT    EFI_HII_VARIABLE_PACK_LIST  **VariablePackList
  )
/*++

  Routine Description:

  This function allows a program to extract the NV Image
  that represents the default storage image

  Arguments:
    This             - A pointer to the EFI_HII_PROTOCOL instance.
    Handle           - The HII handle from which will have default data retrieved.
    UINTN            - Mask used to retrieve the default image.
    VariablePackList - Callee allocated, tightly-packed, link list data
                         structure that contain all default varaible packs
                         from the Hii Database.

  Returns:
    EFI_NOT_FOUND         - If Hii database does not contain any default images.
    EFI_INVALID_PARAMETER - Invalid input parameter.
    EFI_SUCCESS           - Operation successful.

--*/
{
  return EFI_SUCCESS;
}

EFI_STATUS
ThunkUpdateFormCallBack (
  IN       EFI_HANDLE                                CallbackHandle,
  IN CONST HII_TRHUNK_HANDLE_MAPPING_DATABASE_ENTRY  *HandleMapEntry
  )
{
  EFI_STATUS                                Status;
  EFI_FORM_CALLBACK_PROTOCOL                *FrameworkFormCallbackProtocol;
  EFI_HII_CONFIG_ACCESS_PROTOCOL            *ConfigAccessProtocol;
  EFI_HANDLE                                UefiDriverHandle;
  HII_TRHUNK_CONFIG_ACCESS_PROTOCOL_INSTANCE *ConfigAccessProtocolInstance;
  
  Status = gBS->HandleProtocol (
                   CallbackHandle,
                   &gEfiFormCallbackProtocolGuid,
                   (VOID **) &FrameworkFormCallbackProtocol
                   );
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }
  
  Status = mUefiHiiDatabaseProtocol->GetPackageListHandle (
                                        mUefiHiiDatabaseProtocol,
                                        HandleMapEntry->UefiHiiHandle,
                                        &UefiDriverHandle
                                        );
  ASSERT_EFI_ERROR (Status);
  Status = gBS->HandleProtocol (
                   UefiDriverHandle,
                   &gEfiHiiConfigAccessProtocolGuid,
                   (VOID **) &ConfigAccessProtocol
                   );
  ASSERT_EFI_ERROR (Status);
  
  ConfigAccessProtocolInstance = HII_TRHUNK_CONFIG_ACCESS_PROTOCOL_INSTANCE_FROM_PROTOCOL (ConfigAccessProtocol);
  
  ConfigAccessProtocolInstance->FrameworkFormCallbackProtocol = FrameworkFormCallbackProtocol;

  return EFI_SUCCESS;
}

#define LOCAL_UPDATE_DATA_BUFFER_INCREMENTAL   0x1000

EFI_STATUS
AppendToUpdateBuffer (
  IN CONST  UINT8                *OpCodeBuf,
  IN        UINTN                BufSize,
  OUT       EFI_HII_UPDATE_DATA  *UefiData
  )
{
  UINT8 * NewBuff;
  
  if (UefiData->Offset + BufSize > UefiData->BufferSize) {
    NewBuff = AllocateCopyPool (UefiData->BufferSize + LOCAL_UPDATE_DATA_BUFFER_INCREMENTAL, UefiData->Data);
    if (NewBuff == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    UefiData->BufferSize += LOCAL_UPDATE_DATA_BUFFER_INCREMENTAL;
    FreePool (UefiData->Data);
    UefiData->Data = NewBuff;
  }
  
  CopyMem (UefiData->Data + UefiData->Offset, OpCodeBuf, BufSize);
  UefiData->Offset += (UINT32) BufSize;

  return EFI_SUCCESS;
}

EFI_STATUS
Framework2UefiCreateSubtitleOpCode (
  IN CONST FRAMEWORK_EFI_IFR_SUBTITLE  *FwSubTitle,
  OUT      EFI_HII_UPDATE_DATA         *UefiData
  )
{
  EFI_IFR_SUBTITLE USubTitle;

  ZeroMem (&USubTitle, sizeof(USubTitle));

  USubTitle.Header.OpCode = EFI_IFR_SUBTITLE_OP;
  USubTitle.Header.Length = sizeof (EFI_IFR_SUBTITLE);

  USubTitle.Statement.Prompt = FwSubTitle->SubTitle;

  return AppendToUpdateBuffer ((UINT8 *)&USubTitle, sizeof(EFI_IFR_SUBTITLE), UefiData);
}

EFI_STATUS
Framework2UefiCreateTextOpCode (
  IN CONST FRAMEWORK_EFI_IFR_TEXT      *FwText,
  OUT      EFI_HII_UPDATE_DATA         *UefiData
  )
{
  EFI_IFR_TEXT UText;

  ZeroMem (&UText, sizeof(UText));
  
  UText.Header.OpCode = EFI_IFR_TEXT_OP;
  UText.Header.Length = sizeof (EFI_IFR_TEXT);

  UText.Statement.Help   = FwText->Help;

  UText.Statement.Prompt = FwText->Text;
  UText.TextTwo          = FwText->TextTwo;
  
  return AppendToUpdateBuffer ((UINT8 *) &UText, sizeof(EFI_IFR_TEXT), UefiData);
}


EFI_STATUS
ThunkFrameworkUpdateDataToUefiUpdateData (
  IN CONST FRAMEWORK_EFI_HII_UPDATE_DATA    *Data,
  IN       BOOLEAN                          AddData,
  OUT      EFI_HII_UPDATE_DATA              **UefiData
  )
{
  FRAMEWORK_EFI_IFR_OP_HEADER          *FrameworkOpcodeBuffer;
  EFI_HII_UPDATE_DATA                  *UefiUpdateDataBuffer;
  UINTN                                Index;
  EFI_STATUS                           Status;

  UefiUpdateDataBuffer = AllocateZeroPool (sizeof (EFI_HII_UPDATE_DATA));
  if (UefiUpdateDataBuffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  
  UefiUpdateDataBuffer->Data = AllocateZeroPool (LOCAL_UPDATE_DATA_BUFFER_INCREMENTAL);
  if (UefiUpdateDataBuffer->Data == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  UefiUpdateDataBuffer->BufferSize = LOCAL_UPDATE_DATA_BUFFER_INCREMENTAL;
  UefiUpdateDataBuffer->Offset = 0;

  FrameworkOpcodeBuffer = (FRAMEWORK_EFI_IFR_OP_HEADER *) &Data->Data;

  for (Index = 0; Index < Data->DataCount; Index++) {
    switch (FrameworkOpcodeBuffer->OpCode) {
      case FRAMEWORK_EFI_IFR_SUBTITLE_OP:
        Status = Framework2UefiCreateSubtitleOpCode ((FRAMEWORK_EFI_IFR_SUBTITLE  *) FrameworkOpcodeBuffer, UefiUpdateDataBuffer);
        break;
        
      case FRAMEWORK_EFI_IFR_TEXT_OP:
        Status = Framework2UefiCreateTextOpCode ((FRAMEWORK_EFI_IFR_TEXT  *) FrameworkOpcodeBuffer, UefiUpdateDataBuffer);  
        break;
        
      default:
        ASSERT (FALSE);
        return EFI_UNSUPPORTED;
    }

    if (EFI_ERROR (Status)) {
      FreePool (UefiUpdateDataBuffer->Data);
      FreePool (UefiUpdateDataBuffer);
      return Status;
    }

    FrameworkOpcodeBuffer = (FRAMEWORK_EFI_IFR_OP_HEADER *)((UINT8 *) FrameworkOpcodeBuffer + FrameworkOpcodeBuffer->Length);
  }

  *UefiData = UefiUpdateDataBuffer;
  
  return EFI_SUCCESS;
}
EFI_STATUS
EFIAPI
HiiUpdateForm (
  IN EFI_HII_PROTOCOL       *This,
  IN FRAMEWORK_EFI_HII_HANDLE          Handle,
  IN EFI_FORM_LABEL         Label,
  IN BOOLEAN                AddData,
  IN FRAMEWORK_EFI_HII_UPDATE_DATA    *Data
  )
/*++

Routine Description:
  This function allows the caller to update a form that has
  previously been registered with the EFI HII database.

Arguments:
  Handle     - Hii Handle associated with the Formset to modify
  Label      - Update information starting immediately after this label in the IFR
  AddData    - If TRUE, add data.  If FALSE, remove data
  Data       - If adding data, this is the pointer to the data to add

Returns:
  EFI_SUCCESS - Update success.
  Other       - Update fail.

--*/
{
  EFI_STATUS                                Status;
  EFI_HII_THUNK_PRIVATE_DATA                *Private;
  HII_TRHUNK_HANDLE_MAPPING_DATABASE_ENTRY  *HandleMapEntry;
  EFI_HII_UPDATE_DATA                       *UefiHiiUpdateData;
  EFI_HII_HANDLE                            UefiHiiHandle;

  Status = EFI_SUCCESS;

  Private = EFI_HII_THUNK_PRIVATE_DATA_FROM_THIS(This);

  HandleMapEntry = FrameworkHiiHandleToMapDatabaseEntry (Private, Handle);

  if (HandleMapEntry == NULL) {
    return EFI_NOT_FOUND;
  }
  
  if (Data->FormSetUpdate) {
    Status = ThunkUpdateFormCallBack ((EFI_HANDLE) (UINTN) Data->FormCallbackHandle, HandleMapEntry);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  if (Data->DataCount != 0) {
    if (HandleMapEntry->IsPackageListWithOnlyStringPackages) {
      UefiHiiHandle = TagGuidToUefiIfrHiiHandle (Private, &HandleMapEntry->TagGuid);

      if (UefiHiiHandle == NULL) {
        return EFI_INVALID_PARAMETER;
      }
    } else {
      UefiHiiHandle = HandleMapEntry->UefiHiiHandle;
    }

    UefiHiiUpdateData = NULL;
    
    ThunkFrameworkUpdateDataToUefiUpdateData (Data, AddData, &UefiHiiUpdateData);

    Status = IfrLibUpdateForm (UefiHiiHandle, NULL, 0, Label, AddData, UefiHiiUpdateData);
    ASSERT_EFI_ERROR (Status);
    
    if (UefiHiiUpdateData != NULL) {
      SafeFreePool (UefiHiiUpdateData->Data);
      SafeFreePool (UefiHiiUpdateData);
    }
  }

  return Status;
}
