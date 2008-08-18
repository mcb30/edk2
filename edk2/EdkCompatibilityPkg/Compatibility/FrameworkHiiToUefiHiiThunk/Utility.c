/**@file

  This file contains the keyboard processing code to the HII database.

Copyright (c) 2006 - 2008, Intel Corporation
All rights reserved. This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/


#include "HiiDatabase.h"

EFI_GUID  gFrameworkHiiCompatbilityGuid = EFI_IFR_FRAMEWORK_GUID;
EFI_GUID  gTianoHiiIfrGuid              = EFI_IFR_TIANO_GUID;


EFI_GUID *
GetGuidOfFirstFormset (
  CONST EFI_HII_FORM_PACKAGE * FormPackage
) 
{
  UINT8                   *StartOfNextPackage;
  EFI_IFR_OP_HEADER       *OpCodeData;

  StartOfNextPackage = (UINT8 *) FormPackage + FormPackage->Header.Length;
  OpCodeData = (EFI_IFR_OP_HEADER *) (FormPackage + 1);

  while ((UINT8 *) OpCodeData < StartOfNextPackage) {
    if (OpCodeData->OpCode == EFI_IFR_FORM_SET_OP) {
      return AllocateCopyPool (sizeof(EFI_GUID), &(((EFI_IFR_FORM_SET *) OpCodeData)->Guid));
    }
    OpCodeData = (EFI_IFR_OP_HEADER *) ((UINT8 *) OpCodeData + OpCodeData->Length);
  }

  ASSERT (FALSE);

  return NULL;
}

EFI_HII_HANDLE
FwHiiHandleToUefiHiiHandle (
  IN CONST HII_THUNK_PRIVATE_DATA      *Private,
  IN FRAMEWORK_EFI_HII_HANDLE          FwHiiHandle
  )
{
  HII_THUNK_CONTEXT            *ThunkContext;

  ASSERT (FwHiiHandle != (FRAMEWORK_EFI_HII_HANDLE) 0);
  ASSERT (Private != NULL);

  ThunkContext = FwHiiHandleToThunkContext (Private, FwHiiHandle);

  if (ThunkContext != NULL) {
    return ThunkContext->UefiHiiHandle;
  }
  
  return (EFI_HII_HANDLE) NULL;
}


HII_THUNK_CONTEXT *
FwHiiHandleToThunkContext (
  IN CONST HII_THUNK_PRIVATE_DATA      *Private,
  IN FRAMEWORK_EFI_HII_HANDLE          FwHiiHandle
  )
{
  LIST_ENTRY                 *Link;
  HII_THUNK_CONTEXT           *ThunkContext;


  Link = GetFirstNode (&Private->ThunkContextListHead);

  while (!IsNull (&Private->ThunkContextListHead, Link)) {
    ThunkContext = HII_THUNK_CONTEXT_FROM_LINK (Link);

    if (FwHiiHandle == ThunkContext->FwHiiHandle) {
      return ThunkContext;
    }

    Link = GetNextNode (&Private->ThunkContextListHead, Link);
  }

  return NULL;
}

HII_THUNK_CONTEXT *
UefiHiiHandleToThunkContext (
  IN CONST HII_THUNK_PRIVATE_DATA     *Private,
  IN EFI_HII_HANDLE                   UefiHiiHandle
  )
{
  LIST_ENTRY                 *Link;
  HII_THUNK_CONTEXT           *ThunkContext;

  Link = GetFirstNode (&Private->ThunkContextListHead);

  while (!IsNull (&Private->ThunkContextListHead, Link)) {
    ThunkContext = HII_THUNK_CONTEXT_FROM_LINK (Link);

    if (UefiHiiHandle == ThunkContext->UefiHiiHandle) {
      return ThunkContext;
    }
    Link = GetNextNode (&Private->ThunkContextListHead, Link);
  }

  return NULL;
}

EFI_HII_HANDLE *
TagGuidToUefiHiiHandle (
  IN CONST HII_THUNK_PRIVATE_DATA *Private,
  IN CONST EFI_GUID                   *Guid
  )
{
  LIST_ENTRY                 *Link;
  HII_THUNK_CONTEXT           *ThunkContext;

  Link = GetFirstNode (&Private->ThunkContextListHead);

  while (!IsNull (&Private->ThunkContextListHead, Link)) {
    ThunkContext = HII_THUNK_CONTEXT_FROM_LINK (Link);

    if (CompareGuid (Guid, &ThunkContext->TagGuid) && (ThunkContext->IfrPackageCount != 0)) {
      return ThunkContext->UefiHiiHandle;
    }

    Link = GetNextNode (&Private->ThunkContextListHead, Link);
  }

  return NULL;
  
}

BOOLEAN
IsFrameworkHiiDatabaseHandleDepleted (
  IN CONST HII_THUNK_PRIVATE_DATA *Private
  )
{
  return (BOOLEAN) (Private->StaticHiiHandle == (UINTN) Private->StaticPureUefiHiiHandle);
}

EFI_STATUS
AssignFrameworkHiiHandle (
  IN OUT HII_THUNK_PRIVATE_DATA     *Private,
  IN     BOOLEAN                    FromFwHiiNewPack,
  OUT    FRAMEWORK_EFI_HII_HANDLE   *Handle
  )
{
  ASSERT (Handle != NULL);

  if (FromFwHiiNewPack) {

    *Handle = Private->StaticHiiHandle;
    Private->StaticHiiHandle += 1;

    if (IsFrameworkHiiDatabaseHandleDepleted (Private)) {
      return EFI_OUT_OF_RESOURCES;
    }

  } else {

    *Handle = Private->StaticPureUefiHiiHandle;
    Private->StaticPureUefiHiiHandle -= 1;
    
    if (IsFrameworkHiiDatabaseHandleDepleted (Private)) {
      return EFI_OUT_OF_RESOURCES;
    }

  }

  return EFI_SUCCESS;
}

EFI_STATUS
DestroyThunkContextForUefiHiiHandle (
  IN HII_THUNK_PRIVATE_DATA     *Private,
  IN EFI_HII_HANDLE             UefiHiiHandle
 )
{
  HII_THUNK_CONTEXT     *ThunkContext;

  ThunkContext = UefiHiiHandleToThunkContext (Private, UefiHiiHandle);
  ASSERT (ThunkContext != NULL);

  ASSERT (IsListEmpty (&ThunkContext->OneOfOptionMapListHead));
  ASSERT (IsListEmpty (&ThunkContext->QuestionIdMapListHead));
  
  RemoveEntryList (&ThunkContext->Link);

  FreePool (ThunkContext);
    
  return EFI_SUCCESS;
}


/**
  This function create a HII_THUNK_CONTEXT for a package list registered
  by a module calling EFI_HII_DATABASE_PROTOCOL.NewPackageList. It records
  the PackageListGuid in EFI_HII_PACKAGE_LIST_HEADER in the TagGuid in 
  HII_THUNK_CONTEXT created. This TagGuid will be used as a key to s

**/
HII_THUNK_CONTEXT *
CreateThunkContextForUefiHiiHandle (
  IN  HII_THUNK_PRIVATE_DATA     *Private,
  IN  EFI_HII_HANDLE             UefiHiiHandle
 )
{
  EFI_STATUS            Status;
  EFI_GUID              PackageGuid;
  HII_THUNK_CONTEXT      *ThunkContext;

  ThunkContext = AllocateZeroPool (sizeof (*ThunkContext));
  ASSERT (ThunkContext != NULL);
  
  ThunkContext->Signature = HII_THUNK_CONTEXT_SIGNATURE;

  Status = AssignFrameworkHiiHandle (Private, FALSE, &ThunkContext->FwHiiHandle);
  if (EFI_ERROR (Status)) {
    return NULL;
  }
  
  ThunkContext->UefiHiiHandle = UefiHiiHandle;
  
  Status = HiiLibExtractGuidFromHiiHandle (UefiHiiHandle, &PackageGuid);
  ASSERT_EFI_ERROR (Status);
  
  CopyGuid(&ThunkContext->TagGuid, &PackageGuid);

  InitializeListHead (&ThunkContext->QuestionIdMapListHead);
  InitializeListHead (&ThunkContext->OneOfOptionMapListHead);
  
  InsertTailList (&Private->ThunkContextListHead, &ThunkContext->Link);

  return ThunkContext;
}


UINTN
GetPackageCountByType (
  IN CONST EFI_HII_PACKAGE_LIST_HEADER     *PackageListHeader,
  IN       UINT8                           PackageType
  )
{
  UINTN                     Count;
  EFI_HII_PACKAGE_HEADER    *PackageHeader;

  PackageHeader = (EFI_HII_PACKAGE_HEADER *) ((UINT8 *) PackageListHeader + sizeof (EFI_HII_PACKAGE_LIST_HEADER));
  Count = 0;
  
  while (PackageHeader->Type != EFI_HII_PACKAGE_END) {
    if (PackageHeader->Type == PackageType ) {
      Count++;
    }
    PackageHeader = (EFI_HII_PACKAGE_HEADER *) ((UINT8 *) PackageHeader + PackageHeader->Length);
  }
  
  
  return Count;
}

LIST_ENTRY *
GetOneOfOptionMapEntryListHead (
  IN CONST HII_THUNK_CONTEXT  *ThunkContext,
  IN       UINT16             QuestionId
  )
{
  LIST_ENTRY            *Link;
  ONE_OF_OPTION_MAP     *Map;

  Link = GetFirstNode (&ThunkContext->OneOfOptionMapListHead);

  while (!IsNull (&ThunkContext->OneOfOptionMapListHead, Link)) {
    Map = ONE_OF_OPTION_MAP_FROM_LINK (Link);
    if (QuestionId == Map->QuestionId) {
      return &Map->OneOfOptionMapEntryListHead;
    }
    Link = GetNextNode (&ThunkContext->OneOfOptionMapListHead, Link);
  }
  
  return NULL;
}


EFI_STATUS
CreateQuestionIdMap (
  IN    OUT HII_THUNK_CONTEXT  *ThunkContext
  )
{
  EFI_STATUS                    Status;
  EFI_HII_PACKAGE_LIST_HEADER   *List;
  EFI_HII_PACKAGE_HEADER        *Package;
  UINTN                         Size;
  EFI_IFR_OP_HEADER             *OpCode;
  UINTN                         Offset;
  QUESTION_ID_MAP               *IdMap;
  EFI_IFR_VARSTORE              *VarStore;
  EFI_IFR_FORM_SET              *FormSet;
  EFI_IFR_QUESTION_HEADER       *Question;
  LIST_ENTRY                    *QuestionIdMapEntryListHead;
  LIST_ENTRY                    *OneOfOptinMapEntryListHead;
  QUESTION_ID_MAP_ENTRY         *IdMapEntry;
  EFI_IFR_GUID_OPTIONKEY        *OptionMap;
  ONE_OF_OPTION_MAP             *OneOfOptionMap;
  ONE_OF_OPTION_MAP_ENTRY       *OneOfOptionMapEntry;
  EFI_IFR_GUID_CLASS            *Class;
  

  Status = HiiLibExportPackageLists (ThunkContext->UefiHiiHandle, &List, &Size);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Get all VarStoreId and build the the QuestionId map.
  // EFI_IFR_QUESTION_HEADER.VarStoreInfo.VarOffset -> Framework Question ID
  // EFI_IFR_QUESTION_HEADER.QuestionId             -> UEFI Question ID
  //

  //
  // Skip the package list header.
  //
  Package = (EFI_HII_PACKAGE_HEADER *) (List + 1);

  while (Package->Type != EFI_HII_PACKAGE_END) {

    if (Package->Type == EFI_HII_PACKAGE_FORM) {

      //
      // Skip the package header
      //
      Offset = sizeof (EFI_HII_PACKAGE_HEADER);
      while (Offset < Package->Length) {
        OpCode = (EFI_IFR_OP_HEADER *)((UINT8 *) Package + Offset);

        switch (OpCode->OpCode) {
        case EFI_IFR_FORM_SET_OP:
          FormSet = (EFI_IFR_FORM_SET *) OpCode;
          ThunkContext->FormSetTitle = FormSet->FormSetTitle;
          ThunkContext->FormSetHelp  = FormSet->Help;
          break;
          
        case EFI_IFR_VARSTORE_OP:
          //
          // IFR built from Framework VFR only has UEFI Buffer Type Storage
          //
          VarStore = (EFI_IFR_VARSTORE *) OpCode;
          IdMap = AllocateZeroPool (sizeof (QUESTION_ID_MAP));
          ASSERT (IdMap != NULL);
          
          IdMap->Signature  = QUESTION_ID_MAP_SIGNATURE;
          IdMap->VarStoreId = VarStore->VarStoreId;
          IdMap->VarSize    = VarStore->Size;
          InitializeListHead (&IdMap->MapEntryListHead);
          InsertTailList (&ThunkContext->QuestionIdMapListHead, &IdMap->Link);
          break;

        case EFI_IFR_NUMERIC_OP:
        case EFI_IFR_CHECKBOX_OP:
        case EFI_IFR_ONE_OF_OP:
        case EFI_IFR_ORDERED_LIST_OP:
        case EFI_IFR_STRING_OP:
        //case EFI_IFR_PASSWORD_OP:
          Question = (EFI_IFR_QUESTION_HEADER *)(OpCode + 1);
          QuestionIdMapEntryListHead = GetMapEntryListHead (ThunkContext, Question->VarStoreId);

          if (QuestionIdMapEntryListHead != NULL) {
            //
            // If the Question is using Buffer (EFI_IFR_VARSTORE_OP) type VarStore.
            //
            IdMapEntry = AllocateZeroPool (sizeof (QUESTION_ID_MAP_ENTRY));
            ASSERT (IdMapEntry != NULL);

            IdMapEntry->FwQId = Question->VarStoreInfo.VarOffset;
            IdMapEntry->UefiQid = Question->QuestionId;
            IdMapEntry->Signature = QUESTION_ID_MAP_ENTRY_SIGNATURE;

            InsertTailList (QuestionIdMapEntryListHead, &IdMapEntry->Link);
          }

          break;
       
        case EFI_IFR_GUID_OP:
          OptionMap = (EFI_IFR_GUID_OPTIONKEY *) OpCode;
          if (CompareGuid (&OptionMap->Guid, &gFrameworkHiiCompatbilityGuid)) {
            if (OptionMap->ExtendOpCode == EFI_IFR_EXTEND_OP_OPTIONKEY) {
              OneOfOptinMapEntryListHead = GetOneOfOptionMapEntryListHead (ThunkContext, OptionMap->QuestionId);
              if (OneOfOptinMapEntryListHead == NULL) {
                OneOfOptionMap = AllocateZeroPool (sizeof (ONE_OF_OPTION_MAP));
                ASSERT (OneOfOptionMap != NULL);

                OneOfOptionMap->Signature = ONE_OF_OPTION_MAP_SIGNATURE;
                OneOfOptionMap->QuestionId = OptionMap->QuestionId;
                OneOfOptionMap->ValueType = EFI_IFR_TYPE_NUM_SIZE_8;
                InitializeListHead (&OneOfOptionMap->OneOfOptionMapEntryListHead);
                OneOfOptinMapEntryListHead = &OneOfOptionMap->OneOfOptionMapEntryListHead;
                InsertTailList (&ThunkContext->OneOfOptionMapListHead, &OneOfOptionMap->Link);
              }
              OneOfOptionMapEntry = AllocateZeroPool (sizeof (ONE_OF_OPTION_MAP_ENTRY));
              ASSERT (OneOfOptionMapEntry != NULL);

              OneOfOptionMapEntry->Signature = ONE_OF_OPTION_MAP_ENTRY_SIGNATURE;
              OneOfOptionMapEntry->FwKey = OptionMap->KeyValue;
              CopyMem (&OneOfOptionMapEntry->Value, &OptionMap->OptionValue, sizeof (EFI_IFR_TYPE_VALUE));
              
              InsertTailList (OneOfOptinMapEntryListHead, &OneOfOptionMapEntry->Link);
            }
          }else if (CompareGuid (&OptionMap->Guid, &gTianoHiiIfrGuid)) {
            Class = (EFI_IFR_GUID_CLASS *) OpCode;

            switch (Class->ExtendOpCode) {
              case EFI_IFR_EXTEND_OP_CLASS:
                ThunkContext->FormSetClass = Class->Class;
                break;
              case EFI_IFR_EXTEND_OP_SUBCLASS:
                ThunkContext->FormSetSubClass = ((EFI_IFR_GUID_SUBCLASS *) Class)->SubClass;
                break;

              default:
                break;
            }
          }
          break;
          
        default:
          break;
        
        }

        Offset += OpCode->Length;
      }
      //
      // Only Form Package is in a Package List.
      //
      break;
    }

    Package = (EFI_HII_PACKAGE_HEADER *) (UINT8 *) Package + Package->Length;
  }

  FreePool (List);
  return EFI_SUCCESS;
}


LIST_ENTRY *
GetMapEntryListHead (
  IN CONST HII_THUNK_CONTEXT  *ThunkContext,
  IN       UINT16             VarStoreId
  )
{
  LIST_ENTRY            *Link;
  QUESTION_ID_MAP       *Map;

  Link = GetFirstNode (&ThunkContext->QuestionIdMapListHead);

  while (!IsNull (&ThunkContext->QuestionIdMapListHead, Link)) {
    Map = QUESTION_ID_MAP_FROM_LINK (Link);
    if (VarStoreId == Map->VarStoreId) {
      return &Map->MapEntryListHead;
    }
    Link = GetNextNode (&ThunkContext->QuestionIdMapListHead, Link);
  }
  return NULL;
}


