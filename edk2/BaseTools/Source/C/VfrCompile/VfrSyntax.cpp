/*
 * A n t l r  T r a n s l a t i o n  H e a d e r
 *
 * Terence Parr, Will Cohen, and Hank Dietz: 1989-2001
 * Purdue University Electrical Engineering
 * With AHPCRC, University of Minnesota
 * ANTLR Version 1.33MR33
 *
 *   Pccts/antlr/antlr -CC -e3 -ck 3 -k 2 -fl VfrParser.dlg -ft VfrTokens.h -o . VfrSyntax.g
 *
 */

#define ANTLR_VERSION	13333
#include "pcctscfg.h"
#include "pccts_stdio.h"
#include "VfrTokens.h"


#include "EfiVfr.h"
#include "VfrFormPkg.h"
#include "VfrError.h"
#include "VfrUtilityLib.h"
#include "AToken.h"
#include "ATokPtr.h"
#include "AParser.h"
#include "EfiVfrParser.h"
#include "DLexerBase.h"
#include "ATokPtr.h"

/* MR23 In order to remove calls to PURIFY use the antlr -nopurify option */

#ifndef PCCTS_PURIFY
#define PCCTS_PURIFY(r,s) memset((char *) &(r),'\0',(s));
#endif


#include "stdio.h"
#include "PBlackBox.h"
#include "DLexerBase.h"
#include "VfrLexer.h"
#include "AToken.h"

#define GET_LINENO(Obj)       ((Obj)->getLine())
#define SET_LINE_INFO(Obj, L) {(Obj).SetLineNo((L)->getLine());} while (0)
#define CRT_END_OP(Obj)       {CIfrEnd EObj; if (Obj != NULL) EObj.SetLineNo ((Obj)->getLine());} while (0)

typedef ANTLRCommonToken ANTLRToken;

class CVfrDLGLexer : public VfrLexer
{
  public:
  CVfrDLGLexer (DLGFileInput *F) : VfrLexer (F) {};
  INT32 errstd (char *Text)
  {
    printf ("unrecognized input '%s'\n", Text);
  }
};

UINT8
VfrParserStart (
IN FILE *File,
IN BOOLEAN CompatibleMode
)
{
  ParserBlackBox<CVfrDLGLexer, EfiVfrParser, ANTLRToken> VfrParser(File);
  VfrParser.parser()->SetCompatibleMode (CompatibleMode);
  return VfrParser.parser()->vfrProgram();
}

UINT8
EfiVfrParser::vfrProgram(void)
{
  UINT8   _retv;
  zzRULE;
  PCCTS_PURIFY(_retv,sizeof(UINT8  ))
  
  mParserStatus   = 0;
  mCIfrOpHdrIndex = 0;
  mConstantOnlyInExpression = FALSE;
  {
    for (;;) {
      if ( !((setwd1[LA(1)]&0x1))) break;
      if ( (LA(1)==149) ) {
        vfrPragmaPackDefinition();
      }
      else {
        if ( (setwd1[LA(1)]&0x2) ) {
          vfrDataStructDefinition();
        }
        else break; /* MR6 code for exiting loop "for sure" */
      }
    }
  }
  vfrFormSetDefinition();
  _retv = mParserStatus;
  return _retv;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd1, 0x4);
  return _retv;
}

void
EfiVfrParser::pragmaPackShowDef(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  zzmatch(143);
  L = (ANTLRTokenPtr)LT(1);

  gCVfrVarDataTypeDB.Pack (L->getLine(), VFR_PACK_SHOW);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd1, 0x8);
}

void
EfiVfrParser::pragmaPackStackDef(void)
{
  zzRULE;
  ANTLRTokenPtr L1=NULL, L2=NULL, ID=NULL, N=NULL;
  
  UINT32 LineNum;
  UINT8  PackAction;
  CHAR8  *Identifier = NULL;
  UINT32 PackNumber  = DEFAULT_PACK_ALIGN;
  {
    if ( (LA(1)==144) ) {
      zzmatch(144);
      L1 = (ANTLRTokenPtr)LT(1);

      LineNum = L1->getLine(); PackAction = VFR_PACK_PUSH;
 consume();
    }
    else {
      if ( (LA(1)==145)
 ) {
        zzmatch(145);
        L2 = (ANTLRTokenPtr)LT(1);

        LineNum = L2->getLine(); PackAction = VFR_PACK_POP;
 consume();
      }
      else {FAIL(1,err1,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==146) && (LA(2)==StringIdentifier) ) {
      zzmatch(146); consume();
      zzmatch(StringIdentifier);
      ID = (ANTLRTokenPtr)LT(1);

      Identifier = ID->getText();
 consume();
    }
    else {
      if ( (setwd1[LA(1)]&0x10) && (setwd1[LA(2)]&0x20) ) {
      }
      else {FAIL(2,err2,err3,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==146)
 ) {
      zzmatch(146); consume();
      zzmatch(Number);
      N = (ANTLRTokenPtr)LT(1);

      PackAction |= VFR_PACK_ASSIGN; PackNumber = _STOU32(N->getText());
 consume();
    }
    else {
      if ( (LA(1)==CloseParen) ) {
      }
      else {FAIL(1,err4,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  gCVfrVarDataTypeDB.Pack (LineNum, PackAction, Identifier, PackNumber);
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd1, 0x40);
}

void
EfiVfrParser::pragmaPackNumber(void)
{
  zzRULE;
  ANTLRTokenPtr N=NULL;
  
  UINT32 LineNum;
  UINT32 PackNumber = DEFAULT_PACK_ALIGN;
  zzmatch(Number);
  N = (ANTLRTokenPtr)LT(1);

  LineNum = N->getLine(); PackNumber = _STOU32(N->getText());
 consume();
  gCVfrVarDataTypeDB.Pack (LineNum, VFR_PACK_ASSIGN, NULL, PackNumber);
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd1, 0x80);
}

void
EfiVfrParser::vfrPragmaPackDefinition(void)
{
  zzRULE;
  zzmatch(149); consume();
  zzmatch(150); consume();
  zzmatch(OpenParen); consume();
  {
    if ( (LA(1)==143) ) {
      pragmaPackShowDef();
    }
    else {
      if ( (setwd2[LA(1)]&0x1) ) {
        pragmaPackStackDef();
      }
      else {
        if ( (LA(1)==Number) ) {
          pragmaPackNumber();
        }
        else {
          if ( (LA(1)==CloseParen)
 ) {
          }
          else {FAIL(1,err5,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
        }
      }
    }
  }
  zzmatch(CloseParen); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd2, 0x2);
}

void
EfiVfrParser::vfrDataStructDefinition(void)
{
  zzRULE;
  ANTLRTokenPtr N1=NULL, N2=NULL;
  {
    if ( (LA(1)==TypeDef) ) {
      zzmatch(TypeDef); consume();
    }
    else {
      if ( (LA(1)==Struct) ) {
      }
      else {FAIL(1,err6,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(Struct);
  gCVfrVarDataTypeDB.DeclareDataTypeBegin ();
 consume();
  {
    if ( (LA(1)==NonNvDataMap) ) {
      zzmatch(NonNvDataMap); consume();
    }
    else {
      if ( (setwd2[LA(1)]&0x4) ) {
      }
      else {FAIL(1,err7,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==StringIdentifier)
 ) {
      zzmatch(StringIdentifier);
      N1 = (ANTLRTokenPtr)LT(1);

      _PCATCH(gCVfrVarDataTypeDB.SetNewTypeName (N1->getText()), N1);
 consume();
    }
    else {
      if ( (LA(1)==OpenBrace) ) {
      }
      else {FAIL(1,err8,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(OpenBrace); consume();
  vfrDataStructFields();
  zzmatch(CloseBrace); consume();
  {
    if ( (LA(1)==StringIdentifier) ) {
      zzmatch(StringIdentifier);
      N2 = (ANTLRTokenPtr)LT(1);

      _PCATCH(gCVfrVarDataTypeDB.SetNewTypeName (N2->getText()), N2);
 consume();
    }
    else {
      if ( (LA(1)==151) ) {
      }
      else {FAIL(1,err9,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(151);
  gCVfrVarDataTypeDB.DeclareDataTypeEnd ();
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd2, 0x8);
}

void
EfiVfrParser::vfrDataStructFields(void)
{
  zzRULE;
  {
    for (;;) {
      if ( !((setwd2[LA(1)]&0x10))) break;
      if ( (LA(1)==Uint64)
 ) {
        dataStructField64();
      }
      else {
        if ( (LA(1)==Uint32) ) {
          dataStructField32();
        }
        else {
          if ( (setwd2[LA(1)]&0x20) ) {
            dataStructField16();
          }
          else {
            if ( (LA(1)==Uint8) ) {
              dataStructField8();
            }
            else {
              if ( (LA(1)==Boolean) ) {
                dataStructFieldBool();
              }
              else {
                if ( (LA(1)==152)
 ) {
                  dataStructFieldString();
                }
                else {
                  if ( (LA(1)==153) ) {
                    dataStructFieldDate();
                  }
                  else {
                    if ( (LA(1)==154) ) {
                      dataStructFieldTime();
                    }
                    else {
                      if ( (LA(1)==StringIdentifier) ) {
                        dataStructFieldUser();
                      }
                      else break; /* MR6 code for exiting loop "for sure" */
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd2, 0x40);
}

void
EfiVfrParser::dataStructField64(void)
{
  zzRULE;
  ANTLRTokenPtr D=NULL, N=NULL, I=NULL;
  UINT32 ArrayNum = 0;
  zzmatch(Uint64);
  D = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(StringIdentifier);
  N = (ANTLRTokenPtr)LT(1);
 consume();
  {
    if ( (LA(1)==OpenBracket) ) {
      zzmatch(OpenBracket); consume();
      zzmatch(Number);
      I = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(CloseBracket);
      ArrayNum = _STOU32(I->getText());
 consume();
    }
    else {
      if ( (LA(1)==151)
 ) {
      }
      else {FAIL(1,err10,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(151);
  _PCATCH(gCVfrVarDataTypeDB.DataTypeAddField (N->getText(), D->getText(), ArrayNum), N);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd2, 0x80);
}

void
EfiVfrParser::dataStructField32(void)
{
  zzRULE;
  ANTLRTokenPtr D=NULL, N=NULL, I=NULL;
  UINT32 ArrayNum = 0;
  zzmatch(Uint32);
  D = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(StringIdentifier);
  N = (ANTLRTokenPtr)LT(1);
 consume();
  {
    if ( (LA(1)==OpenBracket) ) {
      zzmatch(OpenBracket); consume();
      zzmatch(Number);
      I = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(CloseBracket);
      ArrayNum = _STOU32(I->getText());
 consume();
    }
    else {
      if ( (LA(1)==151) ) {
      }
      else {FAIL(1,err11,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(151);
  _PCATCH(gCVfrVarDataTypeDB.DataTypeAddField (N->getText(), D->getText(), ArrayNum), N);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd3, 0x1);
}

void
EfiVfrParser::dataStructField16(void)
{
  zzRULE;
  ANTLRTokenPtr N=NULL, I=NULL;
  
  UINT32 ArrayNum = 0;
  {
    if ( (LA(1)==Uint16) ) {
      zzmatch(Uint16); consume();
    }
    else {
      if ( (LA(1)==Char16) ) {
        zzmatch(Char16); consume();
      }
      else {FAIL(1,err12,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(StringIdentifier);
  N = (ANTLRTokenPtr)LT(1);
 consume();
  {
    if ( (LA(1)==OpenBracket)
 ) {
      zzmatch(OpenBracket); consume();
      zzmatch(Number);
      I = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(CloseBracket);
      ArrayNum = _STOU32(I->getText());
 consume();
    }
    else {
      if ( (LA(1)==151) ) {
      }
      else {FAIL(1,err13,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(151);
  _PCATCH(gCVfrVarDataTypeDB.DataTypeAddField (N->getText(), (CHAR8 *) "UINT16", ArrayNum), N);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd3, 0x2);
}

void
EfiVfrParser::dataStructField8(void)
{
  zzRULE;
  ANTLRTokenPtr D=NULL, N=NULL, I=NULL;
  UINT32 ArrayNum = 0;
  zzmatch(Uint8);
  D = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(StringIdentifier);
  N = (ANTLRTokenPtr)LT(1);
 consume();
  {
    if ( (LA(1)==OpenBracket) ) {
      zzmatch(OpenBracket); consume();
      zzmatch(Number);
      I = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(CloseBracket);
      ArrayNum = _STOU32(I->getText());
 consume();
    }
    else {
      if ( (LA(1)==151) ) {
      }
      else {FAIL(1,err14,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(151);
  _PCATCH(gCVfrVarDataTypeDB.DataTypeAddField (N->getText(), D->getText(), ArrayNum), N);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd3, 0x4);
}

void
EfiVfrParser::dataStructFieldBool(void)
{
  zzRULE;
  ANTLRTokenPtr D=NULL, N=NULL, I=NULL;
  UINT32 ArrayNum = 0;
  zzmatch(Boolean);
  D = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(StringIdentifier);
  N = (ANTLRTokenPtr)LT(1);
 consume();
  {
    if ( (LA(1)==OpenBracket) ) {
      zzmatch(OpenBracket); consume();
      zzmatch(Number);
      I = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(CloseBracket);
      ArrayNum = _STOU32(I->getText());
 consume();
    }
    else {
      if ( (LA(1)==151)
 ) {
      }
      else {FAIL(1,err15,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(151);
  _PCATCH(gCVfrVarDataTypeDB.DataTypeAddField (N->getText(), D->getText(), ArrayNum), N);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd3, 0x8);
}

void
EfiVfrParser::dataStructFieldString(void)
{
  zzRULE;
  ANTLRTokenPtr D=NULL, N=NULL, I=NULL;
  UINT32 ArrayNum = 0;
  zzmatch(152);
  D = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(StringIdentifier);
  N = (ANTLRTokenPtr)LT(1);
 consume();
  {
    if ( (LA(1)==OpenBracket) ) {
      zzmatch(OpenBracket); consume();
      zzmatch(Number);
      I = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(CloseBracket);
      ArrayNum = _STOU32(I->getText());
 consume();
    }
    else {
      if ( (LA(1)==151) ) {
      }
      else {FAIL(1,err16,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(151);
  _PCATCH(gCVfrVarDataTypeDB.DataTypeAddField (N->getText(), D->getText(), ArrayNum), N);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd3, 0x10);
}

void
EfiVfrParser::dataStructFieldDate(void)
{
  zzRULE;
  ANTLRTokenPtr D=NULL, N=NULL, I=NULL;
  UINT32 ArrayNum = 0;
  zzmatch(153);
  D = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(StringIdentifier);
  N = (ANTLRTokenPtr)LT(1);
 consume();
  {
    if ( (LA(1)==OpenBracket) ) {
      zzmatch(OpenBracket); consume();
      zzmatch(Number);
      I = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(CloseBracket);
      ArrayNum = _STOU32(I->getText());
 consume();
    }
    else {
      if ( (LA(1)==151) ) {
      }
      else {FAIL(1,err17,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(151);
  _PCATCH(gCVfrVarDataTypeDB.DataTypeAddField (N->getText(), D->getText(), ArrayNum), N);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd3, 0x20);
}

void
EfiVfrParser::dataStructFieldTime(void)
{
  zzRULE;
  ANTLRTokenPtr D=NULL, N=NULL, I=NULL;
  UINT32 ArrayNum = 0;
  zzmatch(154);
  D = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(StringIdentifier);
  N = (ANTLRTokenPtr)LT(1);
 consume();
  {
    if ( (LA(1)==OpenBracket)
 ) {
      zzmatch(OpenBracket); consume();
      zzmatch(Number);
      I = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(CloseBracket);
      ArrayNum = _STOU32(I->getText());
 consume();
    }
    else {
      if ( (LA(1)==151) ) {
      }
      else {FAIL(1,err18,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(151);
  _PCATCH(gCVfrVarDataTypeDB.DataTypeAddField (N->getText(), D->getText(), ArrayNum), N);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd3, 0x40);
}

void
EfiVfrParser::dataStructFieldUser(void)
{
  zzRULE;
  ANTLRTokenPtr T=NULL, N=NULL, I=NULL;
  UINT32 ArrayNum = 0;
  zzmatch(StringIdentifier);
  T = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(StringIdentifier);
  N = (ANTLRTokenPtr)LT(1);
 consume();
  {
    if ( (LA(1)==OpenBracket) ) {
      zzmatch(OpenBracket); consume();
      zzmatch(Number);
      I = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(CloseBracket);
      ArrayNum = _STOU32(I->getText());
 consume();
    }
    else {
      if ( (LA(1)==151) ) {
      }
      else {FAIL(1,err19,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(151);
  _PCATCH(gCVfrVarDataTypeDB.DataTypeAddField (N->getText(), T->getText(), ArrayNum), T);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd3, 0x80);
}

void
EfiVfrParser::guidSubDefinition(EFI_GUID & Guid)
{
  zzRULE;
  ANTLRTokenPtr G4=NULL, G5=NULL, G6=NULL, G7=NULL, G8=NULL, G9=NULL, G10=NULL, G11=NULL;
  zzmatch(Number);
  G4 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146); consume();
  zzmatch(Number);
  G5 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146); consume();
  zzmatch(Number);
  G6 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146); consume();
  zzmatch(Number);
  G7 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146); consume();
  zzmatch(Number);
  G8 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146); consume();
  zzmatch(Number);
  G9 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146); consume();
  zzmatch(Number);
  G10 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146); consume();
  zzmatch(Number);
  G11 = (ANTLRTokenPtr)LT(1);

  
  Guid.Data4[0] = _STOU8(G4->getText());
  Guid.Data4[1] = _STOU8(G5->getText());
  Guid.Data4[2] = _STOU8(G6->getText());
  Guid.Data4[3] = _STOU8(G7->getText());
  Guid.Data4[4] = _STOU8(G8->getText());
  Guid.Data4[5] = _STOU8(G9->getText());
  Guid.Data4[6] = _STOU8(G10->getText());
  Guid.Data4[7] = _STOU8(G11->getText());
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd4, 0x1);
}

void
EfiVfrParser::guidDefinition(EFI_GUID & Guid)
{
  zzRULE;
  ANTLRTokenPtr G1=NULL, G2=NULL, G3=NULL;
  zzmatch(OpenBrace); consume();
  zzmatch(Number);
  G1 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146); consume();
  zzmatch(Number);
  G2 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146); consume();
  zzmatch(Number);
  G3 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146);
  
  Guid.Data1 = _STOU32 (G1->getText());
  Guid.Data2 = _STOU16 (G2->getText());
  Guid.Data3 = _STOU16 (G3->getText());
 consume();
  {
    if ( (LA(1)==OpenBrace) ) {
      zzmatch(OpenBrace); consume();
      guidSubDefinition( Guid );
      zzmatch(CloseBrace); consume();
    }
    else {
      if ( (LA(1)==Number)
 ) {
        guidSubDefinition( Guid );
      }
      else {FAIL(1,err20,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(CloseBrace); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd4, 0x2);
}

void
EfiVfrParser::vfrFormSetDefinition(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, S1=NULL, S2=NULL, FC=NULL, FSC=NULL, E=NULL;
  
  EFI_GUID    Guid;
  EFI_GUID    DefaultClassGuid = EFI_HII_PLATFORM_SETUP_FORMSET_GUID;
  EFI_GUID    ClassGuid1, ClassGuid2, ClassGuid3;
  UINT8       ClassGuidNum = 0;
  CIfrFormSet *FSObj = NULL;
  UINT16      C, SC;
  zzmatch(FormSet);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(Uuid); consume();
  zzmatch(155); consume();
  guidDefinition( Guid );
  zzmatch(146); consume();
  zzmatch(Title); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  S1 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen); consume();
  zzmatch(146); consume();
  zzmatch(Help); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  S2 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen); consume();
  zzmatch(146); consume();
  {
    if ( (LA(1)==ClassGuid) ) {
      zzmatch(ClassGuid); consume();
      zzmatch(155); consume();
      guidDefinition( ClassGuid1 );
      ++ClassGuidNum;
      {
        if ( (LA(1)==157) && (LA(2)==OpenBrace) && (LA(3)==Number) ) {
          zzmatch(157); consume();
          guidDefinition( ClassGuid2 );
          ++ClassGuidNum;
        }
        else {
          if ( (setwd4[LA(1)]&0x4) && (setwd4[LA(2)]&0x8) && 
(setwd4[LA(3)]&0x10) ) {
          }
          else {FAIL(3,err21,err22,err23,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
        }
      }
      {
        if ( (LA(1)==157) ) {
          zzmatch(157); consume();
          guidDefinition( ClassGuid3 );
          ++ClassGuidNum;
        }
        else {
          if ( (LA(1)==146) ) {
          }
          else {FAIL(1,err24,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
        }
      }
      zzmatch(146); consume();
    }
    else {
      if ( (setwd4[LA(1)]&0x20) ) {
      }
      else {FAIL(1,err25,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  
  switch (ClassGuidNum) {
    case 0:
    FSObj = new CIfrFormSet(sizeof(EFI_IFR_FORM_SET) + sizeof(EFI_GUID));
    FSObj->SetClassGuid(&DefaultClassGuid);
    break;
    case 1:
    FSObj = new CIfrFormSet(sizeof(EFI_IFR_FORM_SET) + ClassGuidNum * sizeof(EFI_GUID));
    FSObj->SetClassGuid(&ClassGuid1);
    break;
    case 2:
    FSObj = new CIfrFormSet(sizeof(EFI_IFR_FORM_SET) + ClassGuidNum * sizeof(EFI_GUID));
    FSObj->SetClassGuid(&ClassGuid1);
    FSObj->SetClassGuid(&ClassGuid2);
    break;
    case 3:
    FSObj = new CIfrFormSet(sizeof(EFI_IFR_FORM_SET) + ClassGuidNum * sizeof(EFI_GUID));
    FSObj->SetClassGuid(&ClassGuid1);
    FSObj->SetClassGuid(&ClassGuid2);
    FSObj->SetClassGuid(&ClassGuid3);
    break;
    default:
    break;
  }
  
  SET_LINE_INFO (*FSObj, L);
  FSObj->SetGuid (&Guid);
  //
  // for framework vfr to store formset guid used by varstore and efivarstore
  //
  if (mCompatibleMode) {
    memcpy (&mFormsetGuid, &Guid, sizeof (EFI_GUID));
  }
  FSObj->SetFormSetTitle (_STOSID(S1->getText()));
  FSObj->SetHelp (_STOSID(S2->getText()));
  {
    if ( (LA(1)==Class) ) {
      zzmatch(Class);
      FC = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(155); consume();
      classDefinition( C );
      zzmatch(146);
      {CIfrClass CObj;SET_LINE_INFO (CObj, FC); CObj.SetClass(C);}
 consume();
    }
    else {
      if ( (setwd4[LA(1)]&0x40)
 ) {
      }
      else {FAIL(1,err26,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==Subclass) ) {
      zzmatch(Subclass);
      FSC = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(155); consume();
      subclassDefinition( SC );
      zzmatch(146);
      {CIfrSubClass SCObj; SET_LINE_INFO (SCObj, FSC); SCObj.SetSubClass(SC);}
 consume();
    }
    else {
      if ( (setwd4[LA(1)]&0x80) ) {
      }
      else {FAIL(1,err27,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  
  _DeclareStandardDefaultStorage (GET_LINENO (L));
  vfrFormSetList();
  zzmatch(EndFormSet);
  E = (ANTLRTokenPtr)LT(1);

  
  if (mCompatibleMode) {
    //
    // declare all undefined varstore and efivarstore
    //
    _DeclareDefaultFrameworkVarStore (GET_LINENO(E));
  }
  CRT_END_OP (E); if (FSObj != NULL) delete FSObj;
 consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd5, 0x1);
}

void
EfiVfrParser::vfrFormSetList(void)
{
  zzRULE;
  {
    for (;;) {
      if ( !((setwd5[LA(1)]&0x2))) break;
      if ( (LA(1)==Form) ) {
        vfrFormDefinition();
      }
      else {
        if ( (LA(1)==FormMap)
 ) {
          vfrFormMapDefinition();
        }
        else {
          if ( (LA(1)==Image) ) {
            vfrStatementImage();
          }
          else {
            if ( (LA(1)==Varstore) ) {
              vfrStatementVarStoreLinear();
            }
            else {
              if ( (LA(1)==Efivarstore) ) {
                vfrStatementVarStoreEfi();
              }
              else {
                if ( (LA(1)==NameValueVarStore) ) {
                  vfrStatementVarStoreNameValue();
                }
                else {
                  if ( (LA(1)==DefaultStore)
 ) {
                    vfrStatementDefaultStore();
                  }
                  else {
                    if ( (LA(1)==DisableIf) ) {
                      vfrStatementDisableIfFormSet();
                    }
                    else {
                      if ( (LA(1)==SuppressIf) ) {
                        vfrStatementSuppressIfFormSet();
                      }
                      else break; /* MR6 code for exiting loop "for sure" */
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd5, 0x4);
}

void
EfiVfrParser::vfrStatementDefaultStore(void)
{
  zzRULE;
  ANTLRTokenPtr D=NULL, N=NULL, S=NULL, A=NULL;
  UINT16  DefaultId = EFI_HII_DEFAULT_CLASS_STANDARD;
  zzmatch(DefaultStore);
  D = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(StringIdentifier);
  N = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146); consume();
  zzmatch(Prompt); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  S = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen); consume();
  {
    if ( (LA(1)==146) ) {
      zzmatch(146); consume();
      zzmatch(Attribute); consume();
      zzmatch(155); consume();
      zzmatch(Number);
      A = (ANTLRTokenPtr)LT(1);

      DefaultId = _STOU16(A->getText());
 consume();
    }
    else {
      if ( (LA(1)==151) ) {
      }
      else {FAIL(1,err28,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  
  if (mCVfrDefaultStore.DefaultIdRegistered (DefaultId) == FALSE) {
    CIfrDefaultStore DSObj;
    _PCATCH(mCVfrDefaultStore.RegisterDefaultStore (DSObj.GetObjBinAddr(), N->getText(), _STOSID(S->getText()), DefaultId)), D->getLine();
    DSObj.SetLineNo(D->getLine());
    DSObj.SetDefaultName (_STOSID(S->getText()));
    DSObj.SetDefaultId (DefaultId);
  } else {
    _PCATCH(mCVfrDefaultStore.ReRegisterDefaultStoreById (DefaultId, N->getText(), _STOSID(S->getText()))), D->getLine();
  }
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd5, 0x8);
}

void
EfiVfrParser::vfrStatementVarStoreLinear(void)
{
  zzRULE;
  ANTLRTokenPtr V=NULL, TN=NULL, U8=NULL, U16=NULL, C16=NULL, U32=NULL, U64=NULL, D=NULL, T=NULL, FID=NULL, ID=NULL, SN=NULL;
  
  EFI_GUID        Guid;
  CIfrVarStore    VSObj;
  CHAR8           *TypeName;
  CHAR8           *StoreName;
  UINT32          LineNum;
  EFI_VARSTORE_ID VarStoreId = EFI_VARSTORE_ID_INVALID;
  UINT32          Size;
  zzmatch(Varstore);
  V = (ANTLRTokenPtr)LT(1);

  VSObj.SetLineNo(V->getLine());
 consume();
  {
    if ( (LA(1)==StringIdentifier)
 ) {
      zzmatch(StringIdentifier);
      TN = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(146);
      TypeName = TN->getText(); LineNum = TN->getLine();
 consume();
    }
    else {
      if ( (LA(1)==Uint8) ) {
        zzmatch(Uint8);
        U8 = (ANTLRTokenPtr)LT(1);
 consume();
        zzmatch(146);
        TypeName = U8->getText(); LineNum = U8->getLine();
 consume();
      }
      else {
        if ( (LA(1)==Uint16) ) {
          zzmatch(Uint16);
          U16 = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(146);
          TypeName = U16->getText(); LineNum = U16->getLine();
 consume();
        }
        else {
          if ( (LA(1)==Char16) ) {
            zzmatch(Char16);
            C16 = (ANTLRTokenPtr)LT(1);
 consume();
            zzmatch(146);
            TypeName = (CHAR8 *) "UINT16"; LineNum = C16->getLine();
 consume();
          }
          else {
            if ( (LA(1)==Uint32) ) {
              zzmatch(Uint32);
              U32 = (ANTLRTokenPtr)LT(1);
 consume();
              zzmatch(146);
              TypeName = U32->getText(); LineNum = U32->getLine();
 consume();
            }
            else {
              if ( (LA(1)==Uint64)
 ) {
                zzmatch(Uint64);
                U64 = (ANTLRTokenPtr)LT(1);
 consume();
                zzmatch(146);
                TypeName = U64->getText(); LineNum = U64->getLine();
 consume();
              }
              else {
                if ( (LA(1)==153) ) {
                  zzmatch(153);
                  D = (ANTLRTokenPtr)LT(1);
 consume();
                  zzmatch(146);
                  TypeName = D->getText(); LineNum = D->getLine();
 consume();
                }
                else {
                  if ( (LA(1)==154) ) {
                    zzmatch(154);
                    T = (ANTLRTokenPtr)LT(1);
 consume();
                    zzmatch(146);
                    TypeName = T->getText(); LineNum = T->getLine();
 consume();
                  }
                  else {FAIL(1,err29,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
                }
              }
            }
          }
        }
      }
    }
  }
  {
    if ( (LA(1)==Key) ) {
      zzmatch(Key); consume();
      zzmatch(155); consume();
      zzmatch(Number);
      FID = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(146);
      // Key is used to assign Varid in Framework VFR but no use in UEFI2.1 VFR
      if (mCompatibleMode) {
        VarStoreId = _STOU16(FID->getText());
      }
 consume();
    }
    else {
      if ( (setwd5[LA(1)]&0x10) ) {
      }
      else {FAIL(1,err30,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==VarId)
 ) {
      zzmatch(VarId); consume();
      zzmatch(155); consume();
      zzmatch(Number);
      ID = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(146);
      
      _PCATCH(
      (INTN)(VarStoreId = _STOU16(ID->getText())) != 0,
      (INTN)TRUE,
      ID,
      "varid 0 is not allowed."
      );
 consume();
    }
    else {
      if ( (LA(1)==Name) ) {
      }
      else {FAIL(1,err31,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(Name); consume();
  zzmatch(155); consume();
  zzmatch(StringIdentifier);
  SN = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146); consume();
  zzmatch(Uuid); consume();
  zzmatch(155); consume();
  guidDefinition( Guid );
  
  if (mCompatibleMode) {
    StoreName = TypeName;
  } else {
    StoreName = SN->getText();
  }
  _PCATCH(mCVfrDataStorage.DeclareBufferVarStore (
  StoreName,
  &Guid,
  &gCVfrVarDataTypeDB,
  TypeName,
  VarStoreId
  ), LineNum);
  VSObj.SetGuid (&Guid);
  _PCATCH(mCVfrDataStorage.GetVarStoreId(StoreName, &VarStoreId), SN);
  VSObj.SetVarStoreId (VarStoreId);
  _PCATCH(gCVfrVarDataTypeDB.GetDataTypeSize(TypeName, &Size), LineNum);
  VSObj.SetSize ((UINT16) Size);
  VSObj.SetName (SN->getText());
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd5, 0x20);
}

void
EfiVfrParser::vfrStatementVarStoreEfi(void)
{
  zzRULE;
  ANTLRTokenPtr E=NULL, SN=NULL, VN=NULL, N=NULL;
  
  EFI_GUID        Guid;
  CIfrVarStoreEfi VSEObj;
  EFI_VARSTORE_ID VarStoreId;
  UINT32          Attr = 0;
  zzmatch(Efivarstore);
  E = (ANTLRTokenPtr)LT(1);

  VSEObj.SetLineNo(E->getLine());
 consume();
  zzmatch(StringIdentifier);
  SN = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146); consume();
  zzmatch(Attribute); consume();
  zzmatch(155); consume();
  vfrVarStoreEfiAttr( Attr );
  {
    while ( (LA(1)==157) ) {
      zzmatch(157); consume();
      vfrVarStoreEfiAttr( Attr );
    }
  }
  zzmatch(146);
  VSEObj.SetAttributes (Attr);
 consume();
  zzmatch(Name); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  VN = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen); consume();
  zzmatch(146); consume();
  zzmatch(VarSize); consume();
  zzmatch(155); consume();
  zzmatch(Number);
  N = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146); consume();
  zzmatch(Uuid); consume();
  zzmatch(155); consume();
  guidDefinition( Guid );
  mCVfrDataStorage.DeclareEfiVarStore (SN->getText(), &Guid, _STOSID(VN->getText()), _STOU32(N->getText()));
  
  VSEObj.SetGuid (&Guid);
  _PCATCH(mCVfrDataStorage.GetVarStoreId(SN->getText(), &VarStoreId), SN);
  VSEObj.SetVarStoreId (VarStoreId);
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd5, 0x40);
}

void
EfiVfrParser::vfrVarStoreEfiAttr(UINT32 & Attr)
{
  zzRULE;
  ANTLRTokenPtr N=NULL;
  zzmatch(Number);
  N = (ANTLRTokenPtr)LT(1);

  Attr |= _STOU32(N->getText());
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd5, 0x80);
}

void
EfiVfrParser::vfrStatementVarStoreNameValue(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, SN=NULL, N=NULL;
  
  EFI_GUID              Guid;
  CIfrVarStoreNameValue VSNVObj;
  EFI_VARSTORE_ID       VarStoreId;
  zzmatch(NameValueVarStore);
  L = (ANTLRTokenPtr)LT(1);

  VSNVObj.SetLineNo(L->getLine());
 consume();
  zzmatch(StringIdentifier);
  SN = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146);
  _PCATCH(mCVfrDataStorage.DeclareNameVarStoreBegin (SN->getText()), SN);
 consume();
  {
    int zzcnt=1;
    do {
      zzmatch(Name); consume();
      zzmatch(155); consume();
      zzmatch(156); consume();
      zzmatch(OpenParen); consume();
      zzmatch(Number);
      N = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(CloseParen); consume();
      zzmatch(146);
      _PCATCH(mCVfrDataStorage.NameTableAddItem (_STOSID(N->getText())), SN);
 consume();
    } while ( (LA(1)==Name) );
  }
  zzmatch(Uuid); consume();
  zzmatch(155); consume();
  guidDefinition( Guid );
  _PCATCH(mCVfrDataStorage.DeclareNameVarStoreEnd (&Guid), SN);
  
  VSNVObj.SetGuid (&Guid);
  _PCATCH(mCVfrDataStorage.GetVarStoreId(SN->getText(), &VarStoreId), SN);
  VSNVObj.SetVarStoreId (VarStoreId);
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd6, 0x1);
}

void
EfiVfrParser::classDefinition(UINT16 & Class)
{
  zzRULE;
  Class = 0;
  validClassNames(  Class );
  {
    while ( (LA(1)==157) ) {
      zzmatch(157); consume();
      validClassNames(  Class );
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd6, 0x2);
}

void
EfiVfrParser::validClassNames(UINT16 & Class)
{
  zzRULE;
  ANTLRTokenPtr N=NULL;
  if ( (LA(1)==ClassNonDevice)
 ) {
    zzmatch(ClassNonDevice);
    Class |= EFI_NON_DEVICE_CLASS;
 consume();
  }
  else {
    if ( (LA(1)==ClassDiskDevice) ) {
      zzmatch(ClassDiskDevice);
      Class |= EFI_DISK_DEVICE_CLASS;
 consume();
    }
    else {
      if ( (LA(1)==ClassVideoDevice) ) {
        zzmatch(ClassVideoDevice);
        Class |= EFI_VIDEO_DEVICE_CLASS;
 consume();
      }
      else {
        if ( (LA(1)==ClassNetworkDevice) ) {
          zzmatch(ClassNetworkDevice);
          Class |= EFI_NETWORK_DEVICE_CLASS;
 consume();
        }
        else {
          if ( (LA(1)==ClassInputDevice) ) {
            zzmatch(ClassInputDevice);
            Class |= EFI_INPUT_DEVICE_CLASS;
 consume();
          }
          else {
            if ( (LA(1)==ClassOnBoardDevice)
 ) {
              zzmatch(ClassOnBoardDevice);
              Class |= EFI_ON_BOARD_DEVICE_CLASS;
 consume();
            }
            else {
              if ( (LA(1)==ClassOtherDevice) ) {
                zzmatch(ClassOtherDevice);
                Class |= EFI_OTHER_DEVICE_CLASS;
 consume();
              }
              else {
                if ( (LA(1)==Number) ) {
                  zzmatch(Number);
                  N = (ANTLRTokenPtr)LT(1);

                  Class |= _STOU16(N->getText());
 consume();
                }
                else {FAIL(1,err32,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
              }
            }
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd6, 0x4);
}

void
EfiVfrParser::subclassDefinition(UINT16 & SubClass)
{
  zzRULE;
  ANTLRTokenPtr N=NULL;
  SubClass = 0;
  if ( (LA(1)==SubclassSetupApplication) ) {
    zzmatch(SubclassSetupApplication);
    SubClass |= EFI_SETUP_APPLICATION_SUBCLASS;
 consume();
  }
  else {
    if ( (LA(1)==SubclassGeneralApplication) ) {
      zzmatch(SubclassGeneralApplication);
      SubClass |= EFI_GENERAL_APPLICATION_SUBCLASS;
 consume();
    }
    else {
      if ( (LA(1)==SubclassFrontPage)
 ) {
        zzmatch(SubclassFrontPage);
        SubClass |= EFI_FRONT_PAGE_SUBCLASS;
 consume();
      }
      else {
        if ( (LA(1)==SubclassSingleUse) ) {
          zzmatch(SubclassSingleUse);
          SubClass |= EFI_SINGLE_USE_SUBCLASS;
 consume();
        }
        else {
          if ( (LA(1)==Number) ) {
            zzmatch(Number);
            N = (ANTLRTokenPtr)LT(1);

            SubClass |= _STOU16(N->getText());
 consume();
          }
          else {FAIL(1,err33,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd6, 0x8);
}

void
EfiVfrParser::vfrStatementDisableIfFormSet(void)
{
  zzRULE;
  ANTLRTokenPtr D=NULL, E=NULL;
  
  CIfrDisableIf DIObj;
  mConstantOnlyInExpression = TRUE;
  zzmatch(DisableIf);
  D = (ANTLRTokenPtr)LT(1);

  DIObj.SetLineNo(D->getLine());
 consume();
  vfrStatementExpression( 0 );
  zzmatch(151);
  mConstantOnlyInExpression = FALSE;
 consume();
  vfrFormSetList();
  zzmatch(EndIf);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd6, 0x10);
}

void
EfiVfrParser::vfrStatementSuppressIfFormSet(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, E=NULL;
  CIfrSuppressIf SIObj;
  zzmatch(SuppressIf);
  L = (ANTLRTokenPtr)LT(1);

  
  if (mCompatibleMode) {
    _PCATCH (VFR_RETURN_UNSUPPORTED, L);
  }
  SIObj.SetLineNo(L->getLine());
 consume();
  {
    if ( (LA(1)==FLAGS) ) {
      zzmatch(FLAGS); consume();
      zzmatch(155); consume();
      flagsField();
      {
        while ( (LA(1)==157) ) {
          zzmatch(157); consume();
          flagsField();
        }
      }
      zzmatch(146); consume();
    }
    else {
      if ( (setwd6[LA(1)]&0x20)
 ) {
      }
      else {FAIL(1,err34,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  vfrStatementExpression( 0 );
  zzmatch(151); consume();
  vfrFormSetList();
  zzmatch(EndIf);
  E = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(151);
  CRT_END_OP (E);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd6, 0x40);
}

void
EfiVfrParser::vfrStatementHeader(CIfrStatementHeader * SHObj)
{
  zzRULE;
  ANTLRTokenPtr S1=NULL, S2=NULL;
  zzmatch(Prompt); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  S1 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen); consume();
  zzmatch(146);
  SHObj->SetPrompt (_STOSID(S1->getText()));
 consume();
  zzmatch(Help); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  S2 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen);
  SHObj->SetHelp (_STOSID(S2->getText()));
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd6, 0x80);
}

void
EfiVfrParser::vfrQuestionHeader(CIfrQuestionHeader & QHObj,EFI_QUESION_TYPE QType)
{
  zzRULE;
  ANTLRTokenPtr QN=NULL, V=NULL, ID=NULL;
  
  EFI_VARSTORE_INFO Info;
  EFI_QUESTION_ID   QId       = EFI_QUESTION_ID_INVALID;
  CHAR8             *QName    = NULL;
  CHAR8             *VarIdStr = NULL;
  {
    if ( (LA(1)==Name) ) {
      zzmatch(Name); consume();
      zzmatch(155); consume();
      zzmatch(StringIdentifier);
      QN = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(146);
      
      QName = QN->getText();
      _PCATCH(mCVfrQuestionDB.FindQuestion (QName), VFR_RETURN_UNDEFINED, QN, "has already been used please used anther name");
 consume();
    }
    else {
      if ( (setwd7[LA(1)]&0x1) ) {
      }
      else {FAIL(1,err35,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==VarId) ) {
      zzmatch(VarId);
      V = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(155); consume();
      vfrStorageVarId( Info, VarIdStr );
      zzmatch(146); consume();
    }
    else {
      if ( (setwd7[LA(1)]&0x2) ) {
      }
      else {FAIL(1,err36,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==QuestionId)
 ) {
      zzmatch(QuestionId); consume();
      zzmatch(155); consume();
      zzmatch(Number);
      ID = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(146);
      
      QId = _STOQID(ID->getText());
      _PCATCH(mCVfrQuestionDB.FindQuestion (QId), VFR_RETURN_UNDEFINED, ID, "has already been used please assign another number");
 consume();
    }
    else {
      if ( (LA(1)==Prompt) ) {
      }
      else {FAIL(1,err37,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  
  switch (QType) {
    case QUESTION_NORMAL:
    mCVfrQuestionDB.RegisterQuestion (QName, VarIdStr, QId);
    break;
    case QUESTION_DATE:
    mCVfrQuestionDB.RegisterNewDateQuestion (QName, VarIdStr, QId);
    break;
    case QUESTION_TIME:
    mCVfrQuestionDB.RegisterNewTimeQuestion (QName, VarIdStr, QId);
    break;
    default:
    _PCATCH(VFR_RETURN_FATAL_ERROR);
  }
  QHObj.SetQuestionId (QId);
  QHObj.SetVarStoreInfo (&Info);
  vfrStatementHeader( & QHObj );
  _SAVE_CURRQEST_VARINFO (Info);
  if (VarIdStr != NULL) delete VarIdStr;
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd7, 0x4);
}

void
EfiVfrParser::vfrQuestionHeaderWithNoStorage(CIfrQuestionHeader * QHObj)
{
  zzRULE;
  ANTLRTokenPtr QN=NULL, ID=NULL;
  
  EFI_QUESTION_ID   QId = EFI_QUESTION_ID_INVALID;
  CHAR8             *QName = NULL;
  {
    if ( (LA(1)==Name) ) {
      zzmatch(Name); consume();
      zzmatch(155); consume();
      zzmatch(StringIdentifier);
      QN = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(146);
      
      QName = QN->getText();
      _PCATCH(mCVfrQuestionDB.FindQuestion (QName), VFR_RETURN_UNDEFINED, QN, "has already been used please used anther name");
 consume();
    }
    else {
      if ( (setwd7[LA(1)]&0x8) ) {
      }
      else {FAIL(1,err38,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==QuestionId) ) {
      zzmatch(QuestionId); consume();
      zzmatch(155); consume();
      zzmatch(Number);
      ID = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(146);
      
      QId = _STOQID(ID->getText());
      _PCATCH(mCVfrQuestionDB.FindQuestion (QId), VFR_RETURN_UNDEFINED, ID, "redefined quesiont ID");
 consume();
    }
    else {
      if ( (LA(1)==Prompt)
 ) {
      }
      else {FAIL(1,err39,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  
  mCVfrQuestionDB.RegisterQuestion (QName, NULL, QId);
  QHObj->SetQuestionId (QId);
  vfrStatementHeader(  QHObj );
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd7, 0x10);
}

void
EfiVfrParser::questionheaderFlagsField(UINT8 & Flags)
{
  zzRULE;
  if ( (LA(1)==ReadOnlyFlag) ) {
    zzmatch(ReadOnlyFlag);
    Flags |= 0x01;
 consume();
  }
  else {
    if ( (LA(1)==InteractiveFlag) ) {
      zzmatch(InteractiveFlag);
      Flags |= 0x04;
 consume();
    }
    else {
      if ( (LA(1)==ResetRequiredFlag) ) {
        zzmatch(ResetRequiredFlag);
        Flags |= 0x10;
 consume();
      }
      else {
        if ( (LA(1)==OptionOnlyFlag) ) {
          zzmatch(OptionOnlyFlag);
          Flags |= 0x80;
 consume();
        }
        else {
          if ( (LA(1)==NVAccessFlag)
 ) {
            zzmatch(NVAccessFlag); consume();
          }
          else {
            if ( (LA(1)==LateCheckFlag) ) {
              zzmatch(LateCheckFlag); consume();
            }
            else {FAIL(1,err40,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd7, 0x20);
}

void
EfiVfrParser::vfrStorageVarId(EFI_VARSTORE_INFO & Info,CHAR8 *& QuestVarIdStr,BOOLEAN CheckFlag)
{
  zzRULE;
  ANTLRTokenPtr SN1=NULL, I1=NULL, SN2=NULL, SF=NULL, I2=NULL;
  
  UINT32                Idx;
  UINT32                LineNo;
  EFI_VFR_VARSTORE_TYPE VarStoreType = EFI_VFR_VARSTORE_INVALID;
  CHAR8                 *VarIdStr    = NULL;
  CHAR8                 *VarStr      = NULL;
  CHAR8                 *SName       = NULL;
  CHAR8                 *TName       = NULL;
  EFI_VFR_RETURN_CODE   VfrReturnCode = VFR_RETURN_SUCCESS;
  EFI_IFR_TYPE_VALUE    Dummy        = gZeroEfiIfrTypeValue;
  if ( (LA(1)==StringIdentifier) && (LA(2)==OpenBracket) ) {
    {
      zzmatch(StringIdentifier);
      SN1 = (ANTLRTokenPtr)LT(1);

      SName = SN1->getText(); _STRCAT(&VarIdStr, SN1->getText());
 consume();
      zzmatch(OpenBracket); consume();
      zzmatch(Number);
      I1 = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(CloseBracket);
      
      Idx = _STOU32(I1->getText());
      _STRCAT(&VarIdStr, "[");
      _STRCAT(&VarIdStr, I1->getText());
      _STRCAT(&VarIdStr, "]");
 consume();
      
      VfrReturnCode = mCVfrDataStorage.GetVarStoreType (SName, VarStoreType);
      if (mCompatibleMode && VfrReturnCode == VFR_RETURN_UNDEFINED) {
        mCVfrDataStorage.DeclareBufferVarStore (
        SName,
        &mFormsetGuid,
        &gCVfrVarDataTypeDB,
        SName,
        EFI_VARSTORE_ID_INVALID,
        FALSE
        );
        VfrReturnCode = mCVfrDataStorage.GetVarStoreType (SName, VarStoreType);
      }
      if (CheckFlag || VfrReturnCode == VFR_RETURN_SUCCESS) {
        _PCATCH(VfrReturnCode, SN1);
        _PCATCH(mCVfrDataStorage.GetVarStoreId (SName, & Info.mVarStoreId), SN1);
        _PCATCH(mCVfrDataStorage.GetNameVarStoreInfo (& Info, Idx), SN1);
      }
    }
  }
  else {
    if ( (LA(1)==StringIdentifier) && (setwd7[LA(2)]&0x40)
 ) {
      {
        zzmatch(StringIdentifier);
        SN2 = (ANTLRTokenPtr)LT(1);

        SName = SN2->getText(); _STRCAT(&VarIdStr, SName);
 consume();
        
        VfrReturnCode = mCVfrDataStorage.GetVarStoreType (SName, VarStoreType);
        if (mCompatibleMode && VfrReturnCode == VFR_RETURN_UNDEFINED) {
          mCVfrDataStorage.DeclareBufferVarStore (
          SName,
          &mFormsetGuid,
          &gCVfrVarDataTypeDB,
          SName,
          EFI_VARSTORE_ID_INVALID,
          FALSE
          );
          VfrReturnCode = mCVfrDataStorage.GetVarStoreType (SName, VarStoreType);
        }
        if (CheckFlag || VfrReturnCode == VFR_RETURN_SUCCESS) {
          _PCATCH(VfrReturnCode, SN2);
          _PCATCH(mCVfrDataStorage.GetVarStoreId (SName, & Info.mVarStoreId), SN2);
          if (VarStoreType == EFI_VFR_VARSTORE_BUFFER) {
            _PCATCH(mCVfrDataStorage.GetBufferVarStoreDataTypeName(SName, &TName), SN2);
            _STRCAT(&VarStr, TName);
          }
        }
        {
          while ( (LA(1)==158) ) {
            zzmatch(158);
            
            if (CheckFlag || VfrReturnCode == VFR_RETURN_SUCCESS) {
              _PCATCH(((VarStoreType != EFI_VFR_VARSTORE_BUFFER) ? VFR_RETURN_EFIVARSTORE_USE_ERROR : VFR_RETURN_SUCCESS), SN2);
            }
            _STRCAT(&VarIdStr, "."); _STRCAT(&VarStr, ".");
 consume();
            zzmatch(StringIdentifier);
            SF = (ANTLRTokenPtr)LT(1);

            _STRCAT(&VarIdStr, SF->getText()); _STRCAT(&VarStr, SF->getText());
 consume();
            {
              if ( (LA(1)==OpenBracket) ) {
                zzmatch(OpenBracket); consume();
                zzmatch(Number);
                I2 = (ANTLRTokenPtr)LT(1);
 consume();
                zzmatch(CloseBracket);
                
                Idx = _STOU32(I2->getText());
                if (mCompatibleMode) Idx --;
                if (Idx > 0) {
                  //
                  // Idx == 0, [0] can be ignored.
                  // Array[0] is same to Array for unify the varid name to cover [0]
                  //
                  _STRCAT(&VarIdStr, "[");
                  _STRCAT(&VarIdStr, I2->getText());
                  _STRCAT(&VarIdStr, "]");
                }
                _STRCAT(&VarStr, "[");
                _STRCAT(&VarStr, I2->getText());
                _STRCAT(&VarStr, "]");
 consume();
              }
              else {
                if ( (setwd7[LA(1)]&0x80) ) {
                }
                else {FAIL(1,err41,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
              }
            }
          }
        }
        
        switch (VarStoreType) {
          case EFI_VFR_VARSTORE_EFI:
          _PCATCH(mCVfrDataStorage.GetEfiVarStoreInfo (& Info), SN2);
          break;
          case EFI_VFR_VARSTORE_BUFFER:
          _PCATCH(gCVfrVarDataTypeDB.GetDataFieldInfo (VarStr,  Info.mInfo.mVarOffset,  Info.mVarType,  Info.mVarTotalSize), SN2->getLine(), VarStr);
          _PCATCH((EFI_VFR_RETURN_CODE)gCVfrBufferConfig.Register (
          SName,
          NULL),
          SN2->getLine());
          _PCATCH((EFI_VFR_RETURN_CODE)gCVfrBufferConfig.Write (
          'a',
          SName,
          NULL,
          Info.mVarType,
          Info.mInfo.mVarOffset,
          Info.mVarTotalSize,
          Dummy),
          SN2->getLine());
          break;
          case EFI_VFR_VARSTORE_NAME:
          default: break;
        }
        
        QuestVarIdStr = VarIdStr;
        if (VarStr != NULL) {delete VarStr;}
      }
    }
    else {FAIL(2,err42,err43,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd8, 0x1);
}

void
EfiVfrParser::vfrQuestionDataFieldName(EFI_QUESTION_ID & QId,UINT32 & Mask,CHAR8 *& VarIdStr,UINT32 & LineNo)
{
  zzRULE;
  ANTLRTokenPtr SN1=NULL, I1=NULL, SN2=NULL, SF=NULL, I2=NULL;
  
  UINT32  Idx;
  VarIdStr = NULL; LineNo = 0;
  if ( (LA(1)==StringIdentifier) && (LA(2)==OpenBracket)
 ) {
    {
      zzmatch(StringIdentifier);
      SN1 = (ANTLRTokenPtr)LT(1);

      _STRCAT(&VarIdStr, SN1->getText()); LineNo = SN1->getLine();
 consume();
      zzmatch(OpenBracket); consume();
      zzmatch(Number);
      I1 = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(CloseBracket);
      
      _STRCAT(&VarIdStr, "[");
      _STRCAT(&VarIdStr, I1->getText());
      _STRCAT(&VarIdStr, "]");
      mCVfrQuestionDB.GetQuestionId (NULL, VarIdStr,  QId,  Mask);
      if (mConstantOnlyInExpression) {
        _PCATCH(VFR_RETURN_CONSTANT_ONLY, LineNo);
      }
 consume();
    }
  }
  else {
    if ( (LA(1)==StringIdentifier) && (setwd8[LA(2)]&0x2) ) {
      {
        zzmatch(StringIdentifier);
        SN2 = (ANTLRTokenPtr)LT(1);

        _STRCAT (&VarIdStr, SN2->getText()); LineNo = SN2->getLine();
 consume();
        {
          while ( (LA(1)==158) ) {
            zzmatch(158);
            
            _STRCAT (&VarIdStr, ".");
            if (mConstantOnlyInExpression) {
              _PCATCH(VFR_RETURN_CONSTANT_ONLY, LineNo);
            }
 consume();
            zzmatch(StringIdentifier);
            SF = (ANTLRTokenPtr)LT(1);

            _STRCAT (&VarIdStr, SF->getText());
 consume();
            {
              if ( (LA(1)==OpenBracket) ) {
                zzmatch(OpenBracket); consume();
                zzmatch(Number);
                I2 = (ANTLRTokenPtr)LT(1);
 consume();
                zzmatch(CloseBracket);
                
                Idx = _STOU32(I2->getText());
                if (mCompatibleMode) Idx --;
                if (Idx > 0) {
                  //
                  // Idx == 0, [0] can be ignored.
                  // Array[0] is same to Array
                  //
                  _STRCAT(&VarIdStr, "[");
                  _STRCAT(&VarIdStr, I2->getText());
                  _STRCAT(&VarIdStr, "]");
                }
 consume();
              }
              else {
                if ( (setwd8[LA(1)]&0x4)
 ) {
                }
                else {FAIL(1,err44,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
              }
            }
          }
        }
        mCVfrQuestionDB.GetQuestionId (NULL, VarIdStr,  QId,  Mask);
      }
    }
    else {FAIL(2,err45,err46,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd8, 0x8);
}

EFI_IFR_TYPE_VALUE
EfiVfrParser::vfrConstantValueField(UINT8 Type)
{
  EFI_IFR_TYPE_VALUE   _retv;
  zzRULE;
  ANTLRTokenPtr N1=NULL, B1=NULL, B2=NULL, O1=NULL, O2=NULL, Z=NULL, HOUR=NULL, MINUTE=NULL, SECOND=NULL, YEAR=NULL, MONTH=NULL, DAY=NULL, S1=NULL;
  PCCTS_PURIFY(_retv,sizeof(EFI_IFR_TYPE_VALUE  ))
  if ( (LA(1)==Number) && (LA(2)==146) ) {
    zzmatch(Number);
    N1 = (ANTLRTokenPtr)LT(1);

    
    switch ( Type) {
      case EFI_IFR_TYPE_NUM_SIZE_8 :
      _retv.u8     = _STOU8(N1->getText());
      break;
      case EFI_IFR_TYPE_NUM_SIZE_16 :
      _retv.u16    = _STOU16(N1->getText());
      break;
      case EFI_IFR_TYPE_NUM_SIZE_32 :
      _retv.u32    = _STOU32(N1->getText());
      break;
      case EFI_IFR_TYPE_NUM_SIZE_64 :
      _retv.u64    = _STOU64(N1->getText());
      break;
      case EFI_IFR_TYPE_BOOLEAN :
      _retv.b      = _STOU8(N1->getText());
      break;
      case EFI_IFR_TYPE_STRING :
      _retv.string = _STOU16(N1->getText());
      break;
      case EFI_IFR_TYPE_TIME :
      case EFI_IFR_TYPE_DATE :
      default :
      break;
    }
 consume();
  }
  else {
    if ( (LA(1)==True) ) {
      zzmatch(True);
      B1 = (ANTLRTokenPtr)LT(1);

      _retv.b      = TRUE;
 consume();
    }
    else {
      if ( (LA(1)==False) ) {
        zzmatch(False);
        B2 = (ANTLRTokenPtr)LT(1);

        _retv.b      = FALSE;
 consume();
      }
      else {
        if ( (LA(1)==One)
 ) {
          zzmatch(One);
          O1 = (ANTLRTokenPtr)LT(1);

          _retv.u8     = _STOU8(O1->getText());
 consume();
        }
        else {
          if ( (LA(1)==Ones) ) {
            zzmatch(Ones);
            O2 = (ANTLRTokenPtr)LT(1);

            _retv.u64    = _STOU64(O2->getText());
 consume();
          }
          else {
            if ( (LA(1)==Zero) ) {
              zzmatch(Zero);
              Z = (ANTLRTokenPtr)LT(1);

              _retv.u8     = _STOU8(Z->getText());
 consume();
            }
            else {
              if ( (LA(1)==Number) && (LA(2)==164) ) {
                zzmatch(Number);
                HOUR = (ANTLRTokenPtr)LT(1);
 consume();
                zzmatch(164); consume();
                zzmatch(Number);
                MINUTE = (ANTLRTokenPtr)LT(1);
 consume();
                zzmatch(164); consume();
                zzmatch(Number);
                SECOND = (ANTLRTokenPtr)LT(1);

                _retv.time   = _STOT(HOUR->getText(), MINUTE->getText(), SECOND->getText());
 consume();
              }
              else {
                if ( (LA(1)==Number) && 
(LA(2)==165) ) {
                  zzmatch(Number);
                  YEAR = (ANTLRTokenPtr)LT(1);
 consume();
                  zzmatch(165); consume();
                  zzmatch(Number);
                  MONTH = (ANTLRTokenPtr)LT(1);
 consume();
                  zzmatch(165); consume();
                  zzmatch(Number);
                  DAY = (ANTLRTokenPtr)LT(1);

                  _retv.date   = _STOD(YEAR->getText(), MONTH->getText(), DAY->getText());
 consume();
                }
                else {
                  if ( (LA(1)==156) ) {
                    zzmatch(156); consume();
                    zzmatch(OpenParen); consume();
                    zzmatch(Number);
                    S1 = (ANTLRTokenPtr)LT(1);
 consume();
                    zzmatch(CloseParen);
                    _retv.string = _STOSID(S1->getText());
 consume();
                  }
                  else {FAIL(2,err47,err48,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
                }
              }
            }
          }
        }
      }
    }
  }
  return _retv;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd8, 0x10);
  return _retv;
}

void
EfiVfrParser::vfrFormDefinition(void)
{
  zzRULE;
  ANTLRTokenPtr F=NULL, S1=NULL, S2=NULL, E=NULL;
  CIfrForm FObj;
  zzmatch(Form);
  F = (ANTLRTokenPtr)LT(1);

  FObj.SetLineNo(F->getLine());
 consume();
  zzmatch(FormId); consume();
  zzmatch(155); consume();
  zzmatch(Number);
  S1 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146);
  _PCATCH(FObj.SetFormId (_STOFID(S1->getText())), S1);
 consume();
  zzmatch(Title); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  S2 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen); consume();
  zzmatch(151);
  FObj.SetFormTitle (_STOSID(S2->getText()));
 consume();
  {
    for (;;) {
      if ( !((setwd8[LA(1)]&0x20))) break;
      if ( (LA(1)==Image) ) {
        vfrStatementImage();
      }
      else {
        if ( (LA(1)==Locked)
 ) {
          vfrStatementLocked();
        }
        else {
          if ( (LA(1)==Rule) ) {
            vfrStatementRules();
          }
          else {
            if ( (LA(1)==Default) ) {
              vfrStatementDefault();
            }
            else {
              if ( (setwd8[LA(1)]&0x40) ) {
                vfrStatementStat();
              }
              else {
                if ( (setwd8[LA(1)]&0x80) ) {
                  vfrStatementQuestions();
                }
                else {
                  if ( (setwd9[LA(1)]&0x1)
 ) {
                    vfrStatementConditional();
                  }
                  else {
                    if ( (LA(1)==Label) ) {
                      vfrStatementLabel();
                    }
                    else {
                      if ( (LA(1)==Banner) ) {
                        vfrStatementBanner();
                      }
                      else {
                        if ( (setwd9[LA(1)]&0x2) ) {
                          vfrStatementInvalid();
                        }
                        else break; /* MR6 code for exiting loop "for sure" */
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  zzmatch(EndForm);
  E = (ANTLRTokenPtr)LT(1);

  
  if (mCompatibleMode) {
    //
    // Add Label for Framework Vfr
    //
    CIfrLabel LObj1;
    LObj1.SetLineNo(E->getLine());
    LObj1.SetNumber (0xffff);  //add end label for UEFI, label number hardcode 0xffff
    CIfrLabel LObj2;
    LObj2.SetLineNo(E->getLine());
    LObj2.SetNumber (0x0);     //add dummy label for UEFI, label number hardcode 0x0
    CIfrLabel LObj3;
    LObj3.SetLineNo(E->getLine());
    LObj3.SetNumber (0xffff);  //add end label for UEFI, label number hardcode 0xffff
    //
    // Declare undefined Question
    //
    if (gCFormPkg.HavePendingUnassigned()) {
      gCFormPkg.DeclarePendingQuestion (
      gCVfrVarDataTypeDB,
      mCVfrDataStorage,
      mCVfrQuestionDB,
      &mFormsetGuid,
      E->getLine()
      );
    }
  }
  //
  // mCVfrQuestionDB.PrintAllQuestion();
  //
  CRT_END_OP (E);
 consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd9, 0x4);
}

void
EfiVfrParser::vfrFormMapDefinition(void)
{
  zzRULE;
  ANTLRTokenPtr F=NULL, S1=NULL, S2=NULL, E=NULL;
  
  CIfrFormMap *FMapObj = NULL;
  UINT32      FormMapMethodNumber = 0;
  EFI_GUID    Guid;
  zzmatch(FormMap);
  F = (ANTLRTokenPtr)LT(1);

  FMapObj = new CIfrFormMap(); FMapObj->SetLineNo(F->getLine());
 consume();
  zzmatch(FormId); consume();
  zzmatch(155); consume();
  zzmatch(Number);
  S1 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146);
  _PCATCH(FMapObj->SetFormId (_STOFID(S1->getText())), S1);
 consume();
  {
    while ( (LA(1)==MapTitle) ) {
      zzmatch(MapTitle); consume();
      zzmatch(155); consume();
      zzmatch(156); consume();
      zzmatch(OpenParen); consume();
      zzmatch(Number);
      S2 = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(CloseParen); consume();
      zzmatch(151); consume();
      zzmatch(MapGuid); consume();
      zzmatch(155); consume();
      guidDefinition( Guid );
      zzmatch(151);
      FMapObj->SetFormMapMethod (_STOFID(S2->getText()), &Guid); FormMapMethodNumber ++;
 consume();
    }
  }
  if (FormMapMethodNumber == 0) {_PCATCH (VFR_RETURN_INVALID_PARAMETER, F->getLine(), "No MapMethod is set for FormMap!");} delete FMapObj;
  {
    for (;;) {
      if ( !((setwd9[LA(1)]&0x8)
)) break;
      if ( (LA(1)==Image) ) {
        vfrStatementImage();
      }
      else {
        if ( (LA(1)==Locked) ) {
          vfrStatementLocked();
        }
        else {
          if ( (LA(1)==Rule) ) {
            vfrStatementRules();
          }
          else {
            if ( (LA(1)==Default) ) {
              vfrStatementDefault();
            }
            else {
              if ( (setwd9[LA(1)]&0x10)
 ) {
                vfrStatementStat();
              }
              else {
                if ( (setwd9[LA(1)]&0x20) ) {
                  vfrStatementQuestions();
                }
                else {
                  if ( (setwd9[LA(1)]&0x40) ) {
                    vfrStatementConditional();
                  }
                  else {
                    if ( (LA(1)==Label) ) {
                      vfrStatementLabel();
                    }
                    else {
                      if ( (LA(1)==Banner) ) {
                        vfrStatementBanner();
                      }
                      else break; /* MR6 code for exiting loop "for sure" */
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  zzmatch(EndForm);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd9, 0x80);
}

void
EfiVfrParser::vfrStatementRules(void)
{
  zzRULE;
  ANTLRTokenPtr R=NULL, S1=NULL, E=NULL;
  CIfrRule RObj;
  zzmatch(Rule);
  R = (ANTLRTokenPtr)LT(1);

  RObj.SetLineNo(R->getLine());
 consume();
  zzmatch(StringIdentifier);
  S1 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146);
  
  mCVfrRulesDB.RegisterRule (S1->getText());
  RObj.SetRuleId (mCVfrRulesDB.GetRuleId(S1->getText()));
 consume();
  vfrStatementExpression( 0 );
  zzmatch(EndRule);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd10, 0x1);
}

void
EfiVfrParser::vfrStatementDefault(void)
{
  zzRULE;
  ANTLRTokenPtr D=NULL, SN=NULL;
  
  BOOLEAN               IsExp         = FALSE;
  EFI_IFR_TYPE_VALUE    Val           = gZeroEfiIfrTypeValue;
  CIfrDefault           DObj;
  EFI_DEFAULT_ID        DefaultId     = EFI_HII_DEFAULT_CLASS_STANDARD;
  CHAR8                 *VarStoreName = NULL;
  EFI_VFR_VARSTORE_TYPE VarStoreType  = EFI_VFR_VARSTORE_INVALID;
  zzmatch(Default);
  D = (ANTLRTokenPtr)LT(1);

  DObj.SetLineNo(D->getLine());
 consume();
  {
    {
      if ( (LA(1)==Value)
 ) {
        vfrStatementValue();
        zzmatch(146);
        IsExp = TRUE; DObj.SetScope (1); CIfrEnd EndObj1; EndObj1.SetLineNo(D->getLine());
 consume();
      }
      else {
        if ( (LA(1)==155) ) {
          zzmatch(155); consume();
           Val  = vfrConstantValueField( _GET_CURRQEST_DATATYPE() );

          zzmatch(146);
          
          if (gCurrentMinMaxData != NULL && gCurrentMinMaxData->IsNumericOpcode()) {
            //check default value is valid for Numeric Opcode
            if (Val.u64 < gCurrentMinMaxData->GetMinData(_GET_CURRQEST_DATATYPE()) || Val.u64 > gCurrentMinMaxData->GetMaxData(_GET_CURRQEST_DATATYPE())) {
              _PCATCH (VFR_RETURN_INVALID_PARAMETER, D->getLine(), "Numeric default value must be between MinValue and MaxValue.");
            }
          }
          DObj.SetType (_GET_CURRQEST_DATATYPE()); 
          DObj.SetValue(Val);
 consume();
        }
        else {FAIL(1,err49,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
      }
    }
    {
      if ( (LA(1)==DefaultStore) ) {
        zzmatch(DefaultStore); consume();
        zzmatch(155); consume();
        zzmatch(StringIdentifier);
        SN = (ANTLRTokenPtr)LT(1);
 consume();
        zzmatch(146);
        _PCATCH(mCVfrDefaultStore.GetDefaultId (SN->getText(), &DefaultId), SN); DObj.SetDefaultId (DefaultId);
 consume();
      }
      else {
        if ( (setwd10[LA(1)]&0x2) ) {
        }
        else {FAIL(1,err50,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
      }
    }
    
    _PCATCH(mCVfrDataStorage.GetVarStoreName (_GET_CURRQEST_VARTINFO().mVarStoreId, &VarStoreName), D->getLine());
    _PCATCH(mCVfrDataStorage.GetVarStoreType (VarStoreName, VarStoreType), D->getLine());
    if ((IsExp == FALSE) && (VarStoreType == EFI_VFR_VARSTORE_BUFFER)) {
      _PCATCH(mCVfrDefaultStore.BufferVarStoreAltConfigAdd (
      DefaultId,
      _GET_CURRQEST_VARTINFO(),
      VarStoreName,
      _GET_CURRQEST_DATATYPE (),
      Val),
      D->getLine()
      );
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd10, 0x4);
}

void
EfiVfrParser::vfrStatementStat(void)
{
  zzRULE;
  if ( (LA(1)==Subtitle) ) {
    vfrStatementSubTitle();
  }
  else {
    if ( (LA(1)==Text)
 ) {
      vfrStatementStaticText();
    }
    else {
      if ( (setwd10[LA(1)]&0x8) ) {
        vfrStatementCrossReference();
      }
      else {FAIL(1,err51,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd10, 0x10);
}

void
EfiVfrParser::vfrStatementQuestions(void)
{
  zzRULE;
  if ( (setwd10[LA(1)]&0x20) ) {
    vfrStatementBooleanType();
  }
  else {
    if ( (LA(1)==Date) ) {
      vfrStatementDate();
    }
    else {
      if ( (setwd10[LA(1)]&0x40) ) {
        vfrStatementNumericType();
      }
      else {
        if ( (setwd10[LA(1)]&0x80)
 ) {
          vfrStatementStringType();
        }
        else {
          if ( (LA(1)==OrderedList) ) {
            vfrStatementOrderedList();
          }
          else {
            if ( (LA(1)==Time) ) {
              vfrStatementTime();
            }
            else {FAIL(1,err52,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd11, 0x1);
}

void
EfiVfrParser::vfrStatementConditional(void)
{
  zzRULE;
  if ( (LA(1)==DisableIf) ) {
    vfrStatementDisableIfStat();
  }
  else {
    if ( (LA(1)==SuppressIf) ) {
      vfrStatementSuppressIfStat();
    }
    else {
      if ( (LA(1)==GrayOutIf)
 ) {
        vfrStatementGrayOutIfStat();
      }
      else {
        if ( (LA(1)==InconsistentIf) ) {
          vfrStatementInconsistentIfStat();
        }
        else {FAIL(1,err53,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd11, 0x2);
}

void
EfiVfrParser::vfrStatementConditionalNew(void)
{
  zzRULE;
  if ( (LA(1)==DisableIf) ) {
    vfrStatementDisableIfStat();
  }
  else {
    if ( (LA(1)==SuppressIf) ) {
      vfrStatementSuppressIfStatNew();
    }
    else {
      if ( (LA(1)==GrayOutIf) ) {
        vfrStatementGrayOutIfStatNew();
      }
      else {
        if ( (LA(1)==InconsistentIf)
 ) {
          vfrStatementInconsistentIfStat();
        }
        else {FAIL(1,err54,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd11, 0x4);
}

void
EfiVfrParser::vfrStatementSuppressIfStat(void)
{
  zzRULE;
  if ( (LA(1)==SuppressIf) && (setwd11[LA(2)]&0x8) && (setwd11[LA(3)]&0x10)&&(mCompatibleMode) ) {
    if (!(mCompatibleMode)      ) {zzfailed_pred("  mCompatibleMode",0 /* report */, { 0; /* no user action */ } );}
    vfrStatementSuppressIfStatOld();
  }
  else {
    if ( (LA(1)==SuppressIf) && (setwd11[LA(2)]&0x20) && (setwd11[LA(3)]&0x40) ) {
      vfrStatementSuppressIfStatNew();
    }
    else {FAIL(3,err55,err56,err57,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd11, 0x80);
}

void
EfiVfrParser::vfrStatementGrayOutIfStat(void)
{
  zzRULE;
  if ( (LA(1)==GrayOutIf) && 
(setwd12[LA(2)]&0x1) && (setwd12[LA(3)]&0x2)&&(mCompatibleMode) ) {
    if (!(mCompatibleMode)      ) {zzfailed_pred("  mCompatibleMode",0 /* report */, { 0; /* no user action */ } );}
    vfrStatementGrayOutIfStatOld();
  }
  else {
    if ( (LA(1)==GrayOutIf) && (setwd12[LA(2)]&0x4) && (setwd12[LA(3)]&0x8) ) {
      vfrStatementGrayOutIfStatNew();
    }
    else {FAIL(3,err58,err59,err60,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd12, 0x10);
}

void
EfiVfrParser::vfrStatementInvalid(void)
{
  zzRULE;
  {
    if ( (LA(1)==Hidden) ) {
      vfrStatementInvalidHidden();
    }
    else {
      if ( (LA(1)==Inventory)
 ) {
        vfrStatementInvalidInventory();
      }
      else {
        if ( (setwd12[LA(1)]&0x20) ) {
          vfrStatementInvalidSaveRestoreDefaults();
        }
        else {FAIL(1,err61,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
      }
    }
  }
  _CRT_OP (TRUE);
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd12, 0x40);
}

void
EfiVfrParser::flagsField(void)
{
  zzRULE;
  if ( (LA(1)==Number) ) {
    zzmatch(Number); consume();
  }
  else {
    if ( (LA(1)==InteractiveFlag) ) {
      zzmatch(InteractiveFlag); consume();
    }
    else {
      if ( (LA(1)==ManufacturingFlag) ) {
        zzmatch(ManufacturingFlag); consume();
      }
      else {
        if ( (LA(1)==DefaultFlag)
 ) {
          zzmatch(DefaultFlag); consume();
        }
        else {
          if ( (LA(1)==NVAccessFlag) ) {
            zzmatch(NVAccessFlag); consume();
          }
          else {
            if ( (LA(1)==ResetRequiredFlag) ) {
              zzmatch(ResetRequiredFlag); consume();
            }
            else {
              if ( (LA(1)==LateCheckFlag) ) {
                zzmatch(LateCheckFlag); consume();
              }
              else {FAIL(1,err62,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
            }
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd12, 0x80);
}

void
EfiVfrParser::vfrStatementValue(void)
{
  zzRULE;
  ANTLRTokenPtr V=NULL;
  CIfrValue VObj;
  zzmatch(Value);
  V = (ANTLRTokenPtr)LT(1);

  VObj.SetLineNo(V->getLine());
 consume();
  zzmatch(155); consume();
  vfrStatementExpression( 0 );
  {CIfrEnd EndObj; EndObj.SetLineNo(V->getLine());}
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd13, 0x1);
}

void
EfiVfrParser::vfrStatementRead(void)
{
  zzRULE;
  ANTLRTokenPtr R=NULL;
  CIfrRead RObj;
  zzmatch(Read);
  R = (ANTLRTokenPtr)LT(1);

  RObj.SetLineNo(R->getLine());
 consume();
  vfrStatementExpression( 0 );
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd13, 0x2);
}

void
EfiVfrParser::vfrStatementWrite(void)
{
  zzRULE;
  ANTLRTokenPtr W=NULL;
  CIfrWrite WObj;
  zzmatch(Write);
  W = (ANTLRTokenPtr)LT(1);

  WObj.SetLineNo(W->getLine());
 consume();
  vfrStatementExpression( 0 );
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd13, 0x4);
}

void
EfiVfrParser::vfrStatementSubTitle(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, S=NULL, E=NULL;
  CIfrSubtitle SObj;
  zzmatch(Subtitle);
  L = (ANTLRTokenPtr)LT(1);

  SObj.SetLineNo(L->getLine());
 consume();
  zzmatch(Text); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  S = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen);
  SObj.SetPrompt (_STOSID(S->getText()));
 consume();
  {
    if ( (LA(1)==146) ) {
      zzmatch(146); consume();
      zzmatch(FLAGS); consume();
      zzmatch(155); consume();
      vfrSubtitleFlags( SObj );
    }
    else {
      if ( (setwd13[LA(1)]&0x8)
 ) {
      }
      else {FAIL(1,err63,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (setwd13[LA(1)]&0x10) ) {
      vfrStatementStatTagList();
      zzmatch(146); consume();
    }
    else {
      if ( (LA(1)==151) ) {
      }
      else {FAIL(1,err64,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(151);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd13, 0x20);
}

void
EfiVfrParser::vfrSubtitleFlags(CIfrSubtitle & SObj)
{
  zzRULE;
  UINT8 LFlags = 0;
  subtitleFlagsField( LFlags );
  {
    while ( (LA(1)==157) ) {
      zzmatch(157); consume();
      subtitleFlagsField( LFlags );
    }
  }
  _PCATCH(SObj.SetFlags (LFlags));
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd13, 0x40);
}

void
EfiVfrParser::subtitleFlagsField(UINT8 & Flags)
{
  zzRULE;
  ANTLRTokenPtr N=NULL;
  if ( (LA(1)==Number) ) {
    zzmatch(Number);
    N = (ANTLRTokenPtr)LT(1);

    Flags |= _STOU8(N->getText());
 consume();
  }
  else {
    if ( (LA(1)==166)
 ) {
      zzmatch(166);
      Flags |= 0x01;
 consume();
    }
    else {FAIL(1,err65,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd13, 0x80);
}

void
EfiVfrParser::vfrStatementStaticText(void)
{
  zzRULE;
  ANTLRTokenPtr T=NULL, S1=NULL, S2=NULL, S3=NULL, F=NULL, KN=NULL;
  
  UINT8           Flags   = 0;
  EFI_QUESTION_ID QId     = EFI_QUESTION_ID_INVALID;
  EFI_STRING_ID   TxtTwo  = EFI_STRING_ID_INVALID;
  zzmatch(Text);
  T = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(Help); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  S1 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen); consume();
  zzmatch(146); consume();
  zzmatch(Text); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  S2 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen); consume();
  {
    if ( (LA(1)==146) && (LA(2)==Text) && (LA(3)==155) ) {
      zzmatch(146); consume();
      zzmatch(Text); consume();
      zzmatch(155); consume();
      zzmatch(156); consume();
      zzmatch(OpenParen); consume();
      zzmatch(Number);
      S3 = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(CloseParen);
      TxtTwo = _STOSID(S3->getText());
 consume();
    }
    else {
      if ( (setwd14[LA(1)]&0x1) && (setwd14[LA(2)]&0x2) && (setwd14[LA(3)]&0x4) ) {
      }
      else {FAIL(3,err66,err67,err68,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==146) && 
(LA(2)==FLAGS) ) {
      zzmatch(146); consume();
      zzmatch(FLAGS);
      F = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(155); consume();
      staticTextFlagsField( Flags );
      {
        while ( (LA(1)==157) ) {
          zzmatch(157); consume();
          staticTextFlagsField( Flags );
        }
      }
      zzmatch(146); consume();
      zzmatch(Key); consume();
      zzmatch(155); consume();
      zzmatch(Number);
      KN = (ANTLRTokenPtr)LT(1);
 consume();
    }
    else {
      if ( (setwd14[LA(1)]&0x8) && (setwd14[LA(2)]&0x10) ) {
      }
      else {FAIL(2,err69,err70,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  
  if (Flags & EFI_IFR_FLAG_CALLBACK) {
    CIfrAction AObj;
    mCVfrQuestionDB.RegisterQuestion (NULL, NULL, QId);
    AObj.SetLineNo (F->getLine());
    AObj.SetQuestionId (QId);
    AObj.SetPrompt (_STOSID(S2->getText()));
    AObj.SetHelp (_STOSID(S1->getText()));
    _PCATCH(AObj.SetFlags (Flags), F->getLine());
    AssignQuestionKey (AObj, KN);
    CRT_END_OP (KN);
  } else {
    CIfrText TObj;
    TObj.SetLineNo (T->getLine());
    TObj.SetHelp (_STOSID(S1->getText()));
    TObj.SetPrompt (_STOSID(S2->getText()));
    TObj.SetTextTwo (TxtTwo);
  }
  {
    if ( (LA(1)==146)
 ) {
      zzmatch(146); consume();
      vfrStatementStatTagList();
    }
    else {
      if ( (LA(1)==151) ) {
      }
      else {FAIL(1,err71,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd14, 0x20);
}

void
EfiVfrParser::staticTextFlagsField(UINT8 & HFlags)
{
  zzRULE;
  ANTLRTokenPtr N=NULL;
  if ( (LA(1)==Number) ) {
    zzmatch(Number);
    N = (ANTLRTokenPtr)LT(1);

    _PCATCH(_STOU8(N->getText()) == 0 ? VFR_RETURN_SUCCESS : VFR_RETURN_UNSUPPORTED, N->getLine());
 consume();
  }
  else {
    if ( (setwd14[LA(1)]&0x40) ) {
      questionheaderFlagsField( HFlags );
    }
    else {FAIL(1,err72,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd14, 0x80);
}

void
EfiVfrParser::vfrStatementCrossReference(void)
{
  zzRULE;
  if ( (LA(1)==Goto) ) {
    vfrStatementGoto();
  }
  else {
    if ( (LA(1)==ResetButton)
 ) {
      vfrStatementResetButton();
    }
    else {FAIL(1,err73,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd15, 0x1);
}

void
EfiVfrParser::vfrStatementGoto(void)
{
  zzRULE;
  ANTLRTokenPtr G=NULL, P=NULL, F1=NULL, QN1=NULL, F2=NULL, QN2=NULL, F3=NULL, QN3=NULL, QN4=NULL, F4=NULL, F=NULL, KN=NULL;
  
  UINT8               RefType = 1;
  EFI_STRING_ID       DevPath = EFI_STRING_ID_INVALID;
  EFI_GUID            FSId = {0,};
  EFI_FORM_ID         FId;
  EFI_QUESTION_ID     QId    = EFI_QUESTION_ID_INVALID;
  UINT32              BitMask;
  CIfrQuestionHeader  *QHObj = NULL;
  CIfrRef             *R1Obj = NULL;
  CIfrRef2            *R2Obj = NULL;
  CIfrRef3            *R3Obj = NULL;
  CIfrRef4            *R4Obj = NULL;
  zzmatch(Goto);
  G = (ANTLRTokenPtr)LT(1);
 consume();
  {
    if ( (LA(1)==DevicePath) ) {
      {
        zzmatch(DevicePath); consume();
        zzmatch(155); consume();
        zzmatch(156); consume();
        zzmatch(OpenParen); consume();
        zzmatch(Number);
        P = (ANTLRTokenPtr)LT(1);
 consume();
        zzmatch(CloseParen); consume();
        zzmatch(146); consume();
        zzmatch(FormSetGuid); consume();
        zzmatch(155); consume();
        guidDefinition( FSId );
        zzmatch(146); consume();
        zzmatch(FormId); consume();
        zzmatch(155); consume();
        zzmatch(Number);
        F1 = (ANTLRTokenPtr)LT(1);
 consume();
        zzmatch(146); consume();
        zzmatch(Question); consume();
        zzmatch(155); consume();
        zzmatch(Number);
        QN1 = (ANTLRTokenPtr)LT(1);
 consume();
        zzmatch(146);
        
        RefType = 4;
        DevPath = _STOSID(P->getText());
        FId = _STOFID(F1->getText());
        QId = _STOQID(QN1->getText());
 consume();
      }
    }
    else {
      if ( (LA(1)==FormSetGuid) ) {
        {
          zzmatch(FormSetGuid); consume();
          zzmatch(155); consume();
          guidDefinition( FSId );
          zzmatch(146); consume();
          zzmatch(FormId); consume();
          zzmatch(155); consume();
          zzmatch(Number);
          F2 = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(146); consume();
          zzmatch(Question); consume();
          zzmatch(155); consume();
          zzmatch(Number);
          QN2 = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(146);
          
          RefType = 3;
          FId = _STOFID(F2->getText());
          QId = _STOQID(QN2->getText());
 consume();
        }
      }
      else {
        if ( (LA(1)==FormId) ) {
          {
            zzmatch(FormId); consume();
            zzmatch(155); consume();
            zzmatch(Number);
            F3 = (ANTLRTokenPtr)LT(1);
 consume();
            zzmatch(146);
            RefType = 2; FId = _STOFID(F3->getText());
 consume();
            zzmatch(Question); consume();
            zzmatch(155); consume();
            {
              if ( (LA(1)==StringIdentifier) ) {
                zzmatch(StringIdentifier);
                QN3 = (ANTLRTokenPtr)LT(1);
 consume();
                zzmatch(146);
                mCVfrQuestionDB.GetQuestionId (QN3->getText (), NULL, QId, BitMask);
 consume();
              }
              else {
                if ( (LA(1)==Number)
 ) {
                  zzmatch(Number);
                  QN4 = (ANTLRTokenPtr)LT(1);
 consume();
                  zzmatch(146);
                  QId = _STOQID(QN4->getText());
 consume();
                }
                else {FAIL(1,err74,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
              }
            }
          }
        }
        else {
          if ( (LA(1)==Number) ) {
            {
              zzmatch(Number);
              F4 = (ANTLRTokenPtr)LT(1);
 consume();
              zzmatch(146);
              
              RefType = 1;
              FId = _STOFID(F4->getText());
 consume();
            }
          }
          else {FAIL(1,err75,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
        }
      }
    }
  }
  
  switch (RefType) {
    case 4:
    {
      R4Obj = new CIfrRef4;
      QHObj = R4Obj;
      R4Obj->SetLineNo(G->getLine());
      R4Obj->SetDevicePath (DevPath);
      R4Obj->SetFormSetId (FSId);
      R4Obj->SetFormId (FId);
      R4Obj->SetQuestionId (QId);
      break;
    }
    case 3:
    {
      R3Obj = new CIfrRef3;
      QHObj = R3Obj;
      R3Obj->SetLineNo(G->getLine());
      R3Obj->SetFormSetId (FSId);
      R3Obj->SetFormId (FId);
      R3Obj->SetQuestionId (QId);
      break;
    }
    case 2:
    {
      R2Obj = new CIfrRef2;
      QHObj = R2Obj;
      R2Obj->SetLineNo(G->getLine());
      R2Obj->SetFormId (FId);
      _PCATCH(R2Obj->SetQuestionId (QId), QN3);
      break;
    }
    case 1:
    {
      R1Obj = new CIfrRef;
      QHObj = R1Obj;
      R1Obj->SetLineNo(G->getLine());
      R1Obj->SetFormId (FId);
      break;
    }
    default: break;
  }
  vfrQuestionHeaderWithNoStorage( QHObj );
  {
    if ( (LA(1)==146) && (setwd15[LA(2)]&0x2) && (setwd15[LA(3)]&0x4) ) {
      zzmatch(146); consume();
      vfrStatementStatTagList();
    }
    else {
      if ( (setwd15[LA(1)]&0x8) && (setwd15[LA(2)]&0x10) && 
(setwd15[LA(3)]&0x20) ) {
      }
      else {FAIL(3,err76,err77,err78,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==146) && (LA(2)==FLAGS) ) {
      zzmatch(146); consume();
      zzmatch(FLAGS);
      F = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(155); consume();
      vfrGotoFlags( QHObj, F->getLine() );
    }
    else {
      if ( (setwd15[LA(1)]&0x40) && (setwd15[LA(2)]&0x80) ) {
      }
      else {FAIL(2,err79,err80,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==146)
 ) {
      zzmatch(146); consume();
      zzmatch(Key); consume();
      zzmatch(155); consume();
      zzmatch(Number);
      KN = (ANTLRTokenPtr)LT(1);

      AssignQuestionKey (*QHObj, KN);
 consume();
    }
    else {
      if ( (LA(1)==151) ) {
      }
      else {FAIL(1,err81,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(151);
  if (R1Obj != NULL) {delete R1Obj;} if (R2Obj != NULL) {delete R2Obj;} if (R3Obj != NULL) {delete R3Obj;} if (R4Obj != NULL) {delete R4Obj;}
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd16, 0x1);
}

void
EfiVfrParser::vfrGotoFlags(CIfrQuestionHeader * QHObj,UINT32 LineNum)
{
  zzRULE;
  UINT8 HFlags = 0;
  gotoFlagsField( HFlags );
  {
    while ( (LA(1)==157) ) {
      zzmatch(157); consume();
      gotoFlagsField( HFlags );
    }
  }
  _PCATCH(QHObj->SetFlags (HFlags), LineNum);
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd16, 0x2);
}

void
EfiVfrParser::gotoFlagsField(UINT8 & HFlags)
{
  zzRULE;
  ANTLRTokenPtr N=NULL;
  if ( (LA(1)==Number) ) {
    zzmatch(Number);
    N = (ANTLRTokenPtr)LT(1);

    _PCATCH(_STOU8(N->getText()) == 0 ? VFR_RETURN_SUCCESS : VFR_RETURN_UNSUPPORTED, N->getLine());
 consume();
  }
  else {
    if ( (setwd16[LA(1)]&0x4) ) {
      questionheaderFlagsField( HFlags );
    }
    else {FAIL(1,err82,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd16, 0x8);
}

void
EfiVfrParser::getStringId(void)
{
  zzRULE;
  ANTLRTokenPtr IdVal=NULL;
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  IdVal = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd16, 0x10);
}

void
EfiVfrParser::vfrStatementResetButton(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, N=NULL, E=NULL;
  
  CIfrResetButton RBObj;
  UINT16          DefaultId;
  zzmatch(ResetButton);
  L = (ANTLRTokenPtr)LT(1);

  RBObj.SetLineNo(L->getLine());
 consume();
  zzmatch(DefaultStore); consume();
  zzmatch(155); consume();
  zzmatch(StringIdentifier);
  N = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146);
  
  _PCATCH(mCVfrDefaultStore.GetDefaultId (N->getText(), &DefaultId), N->getLine());
  RBObj.SetDefaultId (DefaultId);
 consume();
  vfrStatementHeader( &RBObj );
  zzmatch(146); consume();
  {
    if ( (setwd16[LA(1)]&0x20)
 ) {
      vfrStatementStatTagList();
      zzmatch(146); consume();
    }
    else {
      if ( (LA(1)==EndResetButton) ) {
      }
      else {FAIL(1,err83,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(EndResetButton);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd16, 0x40);
}

void
EfiVfrParser::vfrStatementBooleanType(void)
{
  zzRULE;
  if ( (LA(1)==CheckBox) ) {
    vfrStatementCheckBox();
  }
  else {
    if ( (LA(1)==Action) ) {
      vfrStatementAction();
    }
    else {FAIL(1,err84,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd16, 0x80);
}

void
EfiVfrParser::vfrStatementCheckBox(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, F=NULL, KN=NULL, E=NULL;
  
  CIfrCheckBox       CBObj;
  EFI_IFR_TYPE_VALUE Val = gZeroEfiIfrTypeValue;
  CHAR8              *VarStoreName = NULL;
  UINT32             DataTypeSize;
  zzmatch(CheckBox);
  L = (ANTLRTokenPtr)LT(1);

  CBObj.SetLineNo(L->getLine());
 consume();
  vfrQuestionHeader( CBObj );
  zzmatch(146);
  //check data type
  _PCATCH (gCVfrVarDataTypeDB.GetDataTypeSize (_GET_CURRQEST_DATATYPE(), &DataTypeSize), L->getLine(), "CheckBox varid is not the valid data type");
  if (DataTypeSize != 0 && DataTypeSize != _GET_CURRQEST_VARSIZE()) {
    _PCATCH (VFR_RETURN_INVALID_PARAMETER, L->getLine(), "CheckBox varid doesn't support array");
  } else if ((mCVfrDataStorage.GetVarStoreType (_GET_CURRQEST_VARTINFO().mVarStoreId) == EFI_VFR_VARSTORE_BUFFER) &&
  (_GET_CURRQEST_VARSIZE() != sizeof (BOOLEAN))) {
    _PCATCH (VFR_RETURN_INVALID_PARAMETER, L->getLine(), "CheckBox varid only support BOOLEAN data type");
  }
 consume();
  {
    if ( (LA(1)==FLAGS) ) {
      zzmatch(FLAGS);
      F = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(155); consume();
      vfrCheckBoxFlags( CBObj, F->getLine() );
      zzmatch(146);
      
      _PCATCH(mCVfrDataStorage.GetVarStoreName (_GET_CURRQEST_VARTINFO().mVarStoreId, &VarStoreName), VFR_RETURN_SUCCESS, L, "Failed to retrieve varstore name");
      Val.b = TRUE;
      if (CBObj.GetFlags () & 0x01) {
        _PCATCH(
        mCVfrDefaultStore.BufferVarStoreAltConfigAdd (
        EFI_HII_DEFAULT_CLASS_STANDARD,
        _GET_CURRQEST_VARTINFO(),
        VarStoreName,
        _GET_CURRQEST_DATATYPE (),
        Val
        ),
        VFR_RETURN_SUCCESS,
        L,
        "No standard default storage found"
        );
      }
      if (CBObj.GetFlags () & 0x02) {
      _PCATCH(
      mCVfrDefaultStore.BufferVarStoreAltConfigAdd (
      EFI_HII_DEFAULT_CLASS_MANUFACTURING,
      _GET_CURRQEST_VARTINFO(),
      VarStoreName,
      _GET_CURRQEST_DATATYPE (),
      Val
      ),
      VFR_RETURN_SUCCESS,
      L,
      "No manufacturing default storage found"
      );
    }
 consume();
    }
    else {
      if ( (setwd17[LA(1)]&0x1)
 ) {
      }
      else {FAIL(1,err85,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==Key) ) {
      zzmatch(Key); consume();
      zzmatch(155); consume();
      zzmatch(Number);
      KN = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(146);
      AssignQuestionKey (CBObj, KN);
 consume();
    }
    else {
      if ( (setwd17[LA(1)]&0x2) ) {
      }
      else {FAIL(1,err86,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  vfrStatementQuestionOptionList();
  zzmatch(EndCheckBox);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd17, 0x4);
}

void
EfiVfrParser::vfrCheckBoxFlags(CIfrCheckBox & CBObj,UINT32 LineNum)
{
  zzRULE;
  
  UINT8 LFlags = 0;
  UINT8 HFlags = 0;
  checkboxFlagsField( LFlags, HFlags );
  {
    while ( (LA(1)==157) ) {
      zzmatch(157); consume();
      checkboxFlagsField( LFlags, HFlags );
    }
  }
  _PCATCH(CBObj.SetFlags (HFlags, LFlags), LineNum);
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd17, 0x8);
}

void
EfiVfrParser::checkboxFlagsField(UINT8 & LFlags,UINT8 & HFlags)
{
  zzRULE;
  ANTLRTokenPtr N=NULL, D=NULL, M=NULL;
  if ( (LA(1)==Number) ) {
    zzmatch(Number);
    N = (ANTLRTokenPtr)LT(1);

    
    if (mCompatibleMode) {
      //
      // set question flag
      //
      LFlags |= _STOU8(N->getText());
    } else {
      _PCATCH(_STOU8(N->getText()) == 0 ? VFR_RETURN_SUCCESS : VFR_RETURN_UNSUPPORTED, N->getLine());
    }
 consume();
  }
  else {
    if ( (LA(1)==DefaultFlag)
 ) {
      zzmatch(DefaultFlag);
      D = (ANTLRTokenPtr)LT(1);

      
      if (mCompatibleMode) {
        //
        // set question Default flag
        //
        LFlags |= 0x01;
      } else {
        _PCATCH (VFR_RETURN_UNSUPPORTED, D);
      }
 consume();
    }
    else {
      if ( (LA(1)==ManufacturingFlag) ) {
        zzmatch(ManufacturingFlag);
        M = (ANTLRTokenPtr)LT(1);

        
        if (mCompatibleMode) {
          //
          // set question MFG flag
          //
          LFlags |= 0x02;
        } else {
          _PCATCH (VFR_RETURN_UNSUPPORTED, M);
        }
 consume();
      }
      else {
        if ( (LA(1)==167) ) {
          zzmatch(167);
          LFlags |= 0x01;
 consume();
        }
        else {
          if ( (LA(1)==168) ) {
            zzmatch(168);
            LFlags |= 0x02;
 consume();
          }
          else {
            if ( (setwd17[LA(1)]&0x10) ) {
              questionheaderFlagsField( HFlags );
            }
            else {FAIL(1,err87,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd17, 0x20);
}

void
EfiVfrParser::vfrStatementAction(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, F=NULL, S=NULL, E=NULL;
  CIfrAction AObj;
  zzmatch(Action);
  L = (ANTLRTokenPtr)LT(1);

  AObj.SetLineNo(L->getLine());
 consume();
  vfrQuestionHeaderWithNoStorage( &AObj );
  zzmatch(146); consume();
  {
    if ( (LA(1)==FLAGS)
 ) {
      zzmatch(FLAGS);
      F = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(155); consume();
      vfrActionFlags( AObj, F->getLine() );
      zzmatch(146); consume();
    }
    else {
      if ( (LA(1)==Config) ) {
      }
      else {FAIL(1,err88,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(Config); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  S = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen); consume();
  zzmatch(146);
  AObj.SetQuestionConfig (_STOSID(S->getText()));
 consume();
  vfrStatementQuestionTagList();
  zzmatch(EndAction);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd17, 0x40);
}

void
EfiVfrParser::vfrActionFlags(CIfrAction & AObj,UINT32 LineNum)
{
  zzRULE;
  UINT8 HFlags = 0;
  actionFlagsField( HFlags );
  {
    while ( (LA(1)==157) ) {
      zzmatch(157); consume();
      actionFlagsField( HFlags );
    }
  }
  _PCATCH(AObj.SetFlags (HFlags), LineNum);
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd17, 0x80);
}

void
EfiVfrParser::actionFlagsField(UINT8 & HFlags)
{
  zzRULE;
  ANTLRTokenPtr N=NULL;
  if ( (LA(1)==Number) ) {
    zzmatch(Number);
    N = (ANTLRTokenPtr)LT(1);

    _PCATCH(_STOU8(N->getText()) == 0 ? VFR_RETURN_SUCCESS : VFR_RETURN_UNSUPPORTED, N->getLine());
 consume();
  }
  else {
    if ( (setwd18[LA(1)]&0x1) ) {
      questionheaderFlagsField( HFlags );
    }
    else {FAIL(1,err89,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd18, 0x2);
}

void
EfiVfrParser::vfrStatementDate(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, F=NULL, D1=NULL, D1Y=NULL, YP=NULL, YH=NULL, D2=NULL, D2M=NULL, MP=NULL, MH=NULL, D3=NULL, D3D=NULL, DP=NULL, DH=NULL, E=NULL;
  
  EFI_QUESTION_ID    QId          = EFI_QUESTION_ID_INVALID;
  CHAR8              *VarIdStr[3] = {NULL, };
  CIfrDate           DObj;
  EFI_IFR_TYPE_VALUE Val = gZeroEfiIfrTypeValue;
  zzmatch(Date);
  L = (ANTLRTokenPtr)LT(1);

  DObj.SetLineNo(L->getLine());
 consume();
  {
    if ( (setwd18[LA(1)]&0x4)
 ) {
      {
        vfrQuestionHeader( DObj, QUESTION_DATE );
        zzmatch(146); consume();
        {
          if ( (LA(1)==FLAGS) ) {
            zzmatch(FLAGS);
            F = (ANTLRTokenPtr)LT(1);
 consume();
            zzmatch(155); consume();
            vfrDateFlags( DObj, F->getLine() );
            zzmatch(146); consume();
          }
          else {
            if ( (setwd18[LA(1)]&0x8) ) {
            }
            else {FAIL(1,err90,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
          }
        }
        vfrStatementQuestionOptionList();
      }
    }
    else {
      if ( (LA(1)==Year) ) {
        {
          zzmatch(Year); consume();
          zzmatch(VarId); consume();
          zzmatch(155); consume();
          zzmatch(StringIdentifier);
          D1 = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(158); consume();
          zzmatch(StringIdentifier);
          D1Y = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(146);
          _STRCAT(&VarIdStr[0], D1->getText()); _STRCAT(&VarIdStr[0], "."); _STRCAT(&VarIdStr[0], D1Y->getText());
 consume();
          zzmatch(Prompt); consume();
          zzmatch(155); consume();
          zzmatch(156); consume();
          zzmatch(OpenParen); consume();
          zzmatch(Number);
          YP = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(CloseParen); consume();
          zzmatch(146); consume();
          zzmatch(Help); consume();
          zzmatch(155); consume();
          zzmatch(156); consume();
          zzmatch(OpenParen); consume();
          zzmatch(Number);
          YH = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(CloseParen); consume();
          zzmatch(146); consume();
          minMaxDateStepDefault( Val.date, 0 );
          zzmatch(Month); consume();
          zzmatch(VarId); consume();
          zzmatch(155); consume();
          zzmatch(StringIdentifier);
          D2 = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(158); consume();
          zzmatch(StringIdentifier);
          D2M = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(146);
          _STRCAT(&VarIdStr[1], D2->getText()); _STRCAT(&VarIdStr[1], "."); _STRCAT(&VarIdStr[1], D2M->getText());
 consume();
          zzmatch(Prompt); consume();
          zzmatch(155); consume();
          zzmatch(156); consume();
          zzmatch(OpenParen); consume();
          zzmatch(Number);
          MP = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(CloseParen); consume();
          zzmatch(146); consume();
          zzmatch(Help); consume();
          zzmatch(155); consume();
          zzmatch(156); consume();
          zzmatch(OpenParen); consume();
          zzmatch(Number);
          MH = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(CloseParen); consume();
          zzmatch(146); consume();
          minMaxDateStepDefault( Val.date, 1 );
          zzmatch(Day); consume();
          zzmatch(VarId); consume();
          zzmatch(155); consume();
          zzmatch(StringIdentifier);
          D3 = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(158); consume();
          zzmatch(StringIdentifier);
          D3D = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(146);
          _STRCAT(&VarIdStr[2], D3->getText()); _STRCAT(&VarIdStr[2], "."); _STRCAT(&VarIdStr[2], D3D->getText());
 consume();
          zzmatch(Prompt); consume();
          zzmatch(155); consume();
          zzmatch(156); consume();
          zzmatch(OpenParen); consume();
          zzmatch(Number);
          DP = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(CloseParen); consume();
          zzmatch(146); consume();
          zzmatch(Help); consume();
          zzmatch(155); consume();
          zzmatch(156); consume();
          zzmatch(OpenParen); consume();
          zzmatch(Number);
          DH = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(CloseParen); consume();
          zzmatch(146); consume();
          minMaxDateStepDefault( Val.date, 2 );
          
          mCVfrQuestionDB.RegisterOldDateQuestion (VarIdStr[0], VarIdStr[1], VarIdStr[2], QId);
          DObj.SetQuestionId (QId);
          DObj.SetFlags (EFI_IFR_QUESTION_FLAG_DEFAULT, QF_DATE_STORAGE_TIME);
          DObj.SetPrompt (_STOSID(YP->getText()));
          DObj.SetHelp (_STOSID(YH->getText()));
          if (VarIdStr[0] != NULL) { delete VarIdStr[0]; } if (VarIdStr[1] != NULL) { delete VarIdStr[1]; } if (VarIdStr[2] != NULL) { delete VarIdStr[2]; }
          {CIfrDefault DefaultObj(EFI_HII_DEFAULT_CLASS_STANDARD, EFI_IFR_TYPE_DATE, Val); DefaultObj.SetLineNo(L->getLine());}
        }
        {
          while ( (LA(1)==InconsistentIf) ) {
            vfrStatementInconsistentIf();
          }
        }
      }
      else {FAIL(1,err91,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(EndDate);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd18, 0x10);
}

void
EfiVfrParser::minMaxDateStepDefault(EFI_HII_DATE & D,UINT8 KeyValue)
{
  zzRULE;
  ANTLRTokenPtr MinN=NULL, MaxN=NULL, N=NULL;
  zzmatch(Minimum); consume();
  zzmatch(155); consume();
  zzmatch(Number);
  MinN = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146); consume();
  zzmatch(Maximum); consume();
  zzmatch(155); consume();
  zzmatch(Number);
  MaxN = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146); consume();
  {
    if ( (LA(1)==STEP)
 ) {
      zzmatch(STEP); consume();
      zzmatch(155); consume();
      zzmatch(Number); consume();
      zzmatch(146); consume();
    }
    else {
      if ( (setwd18[LA(1)]&0x20) ) {
      }
      else {FAIL(1,err92,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==Default) ) {
      zzmatch(Default); consume();
      zzmatch(155); consume();
      zzmatch(Number);
      N = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(146);
      
      switch (KeyValue) {
        case 0: 
        D.Year  = _STOU16(N->getText());
        if (D.Year < _STOU16 (MinN->getText()) || D.Year > _STOU16 (MaxN->getText())) {
          _PCATCH (VFR_RETURN_INVALID_PARAMETER, N->getLine(), "Year default value must be between Min year and Max year.");
        }
        break;
        case 1: 
        D.Month = _STOU8(N->getText()); 
        if (D.Month < 1 || D.Month > 12) {
          _PCATCH (VFR_RETURN_INVALID_PARAMETER, N->getLine(), "Month default value must be between 1 and 12.");
        }
        break;
        case 2: 
        D.Day = _STOU8(N->getText()); 
        if (D.Day < 1 || D.Day > 31) {
          _PCATCH (VFR_RETURN_INVALID_PARAMETER, N->getLine(), "Day default value must be between 1 and 31.");
        }
        break;
      }
 consume();
    }
    else {
      if ( (setwd18[LA(1)]&0x40) ) {
      }
      else {FAIL(1,err93,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd18, 0x80);
}

void
EfiVfrParser::vfrDateFlags(CIfrDate & DObj,UINT32 LineNum)
{
  zzRULE;
  UINT8 LFlags = 0;
  dateFlagsField( LFlags );
  {
    while ( (LA(1)==157) ) {
      zzmatch(157); consume();
      dateFlagsField( LFlags );
    }
  }
  _PCATCH(DObj.SetFlags (EFI_IFR_QUESTION_FLAG_DEFAULT, LFlags), LineNum);
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd19, 0x1);
}

void
EfiVfrParser::dateFlagsField(UINT8 & Flags)
{
  zzRULE;
  ANTLRTokenPtr N=NULL;
  if ( (LA(1)==Number)
 ) {
    zzmatch(Number);
    N = (ANTLRTokenPtr)LT(1);

    Flags |= _STOU8(N->getText());
 consume();
  }
  else {
    if ( (LA(1)==169) ) {
      zzmatch(169);
      Flags |= 0x01;
 consume();
    }
    else {
      if ( (LA(1)==170) ) {
        zzmatch(170);
        Flags |= 0x02;
 consume();
      }
      else {
        if ( (LA(1)==171) ) {
          zzmatch(171);
          Flags |= 0x04;
 consume();
        }
        else {
          if ( (LA(1)==172) ) {
            zzmatch(172);
            Flags |= 0x00;
 consume();
          }
          else {
            if ( (LA(1)==173)
 ) {
              zzmatch(173);
              Flags |= 0x10;
 consume();
            }
            else {
              if ( (LA(1)==174) ) {
                zzmatch(174);
                Flags |= 0x20;
 consume();
              }
              else {FAIL(1,err94,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
            }
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd19, 0x2);
}

void
EfiVfrParser::vfrStatementNumericType(void)
{
  zzRULE;
  if ( (LA(1)==Numeric) ) {
    vfrStatementNumeric();
  }
  else {
    if ( (LA(1)==OneOf) ) {
      vfrStatementOneOf();
    }
    else {FAIL(1,err95,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd19, 0x4);
}

void
EfiVfrParser::vfrSetMinMaxStep(CIfrMinMaxStepData & MMSDObj)
{
  zzRULE;
  ANTLRTokenPtr I=NULL, A=NULL, S=NULL;
  
  UINT64 MaxU8 = 0, MinU8 = 0, StepU8 = 0;
  UINT32 MaxU4 = 0, MinU4 = 0, StepU4 = 0;
  UINT16 MaxU2 = 0, MinU2 = 0, StepU2 = 0;
  UINT8  MaxU1 = 0, MinU1 = 0, StepU1 = 0;
  zzmatch(Minimum); consume();
  zzmatch(155); consume();
  zzmatch(Number);
  I = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146);
  
  switch (_GET_CURRQEST_DATATYPE()) {
    case EFI_IFR_TYPE_NUM_SIZE_64 : MinU8 = _STOU64(I->getText()); break;
    case EFI_IFR_TYPE_NUM_SIZE_32 : MinU4 = _STOU32(I->getText()); break;
    case EFI_IFR_TYPE_NUM_SIZE_16 : MinU2 = _STOU16(I->getText()); break;
    case EFI_IFR_TYPE_NUM_SIZE_8 :  MinU1 = _STOU8(I->getText());  break;
  }
 consume();
  zzmatch(Maximum); consume();
  zzmatch(155); consume();
  zzmatch(Number);
  A = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146);
  
  switch (_GET_CURRQEST_DATATYPE()) {
    case EFI_IFR_TYPE_NUM_SIZE_64 : 
    MaxU8 = _STOU64(A->getText()); 
    if (MaxU8 < MinU8) {
      _PCATCH (VFR_RETURN_INVALID_PARAMETER, A->getLine(), "Maximum can't be less than Minimum");
    }
    break;
    case EFI_IFR_TYPE_NUM_SIZE_32 : 
    MaxU4 = _STOU32(A->getText()); 
    if (MaxU4 < MinU4) {
      _PCATCH (VFR_RETURN_INVALID_PARAMETER, A->getLine(), "Maximum can't be less than Minimum");
    }
    break;
    case EFI_IFR_TYPE_NUM_SIZE_16 : 
    MaxU2 = _STOU16(A->getText()); 
    if (MaxU2 < MinU2) {
      _PCATCH (VFR_RETURN_INVALID_PARAMETER, A->getLine(), "Maximum can't be less than Minimum");
    }
    break;
    case EFI_IFR_TYPE_NUM_SIZE_8 :  
    MaxU1 = _STOU8(A->getText());  
    if (MaxU1 < MinU1) {
      _PCATCH (VFR_RETURN_INVALID_PARAMETER, A->getLine(), "Maximum can't be less than Minimum");
    }
    break;
  }
 consume();
  {
    if ( (LA(1)==STEP) ) {
      zzmatch(STEP); consume();
      zzmatch(155); consume();
      zzmatch(Number);
      S = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(146);
      
      switch (_GET_CURRQEST_DATATYPE()) {
        case EFI_IFR_TYPE_NUM_SIZE_64 : StepU8 = _STOU64(S->getText()); break;
        case EFI_IFR_TYPE_NUM_SIZE_32 : StepU4 = _STOU32(S->getText()); break;
        case EFI_IFR_TYPE_NUM_SIZE_16 : StepU2 = _STOU16(S->getText()); break;
        case EFI_IFR_TYPE_NUM_SIZE_8 :  StepU1 = _STOU8(S->getText());  break;
      }
 consume();
    }
    else {
      if ( (setwd19[LA(1)]&0x8)
 ) {
      }
      else {FAIL(1,err96,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  
  switch (_GET_CURRQEST_DATATYPE()) {
    case EFI_IFR_TYPE_NUM_SIZE_64 :  MMSDObj.SetMinMaxStepData (MinU8, MaxU8, StepU8); break;
    case EFI_IFR_TYPE_NUM_SIZE_32 :  MMSDObj.SetMinMaxStepData (MinU4, MaxU4, StepU4); break;
    case EFI_IFR_TYPE_NUM_SIZE_16 :  MMSDObj.SetMinMaxStepData (MinU2, MaxU2, StepU2); break;
    case EFI_IFR_TYPE_NUM_SIZE_8 :   MMSDObj.SetMinMaxStepData (MinU1, MaxU1, StepU1);  break;
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd19, 0x10);
}

void
EfiVfrParser::vfrStatementNumeric(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, F=NULL, KN=NULL, E=NULL;
  
  CIfrNumeric NObj;
  UINT32 DataTypeSize;
  zzmatch(Numeric);
  L = (ANTLRTokenPtr)LT(1);

  NObj.SetLineNo(L->getLine());
 consume();
  vfrQuestionHeader( NObj );
  zzmatch(146);
  // check data type
  _PCATCH (gCVfrVarDataTypeDB.GetDataTypeSize (_GET_CURRQEST_DATATYPE(), &DataTypeSize), L->getLine(), "Numeric varid is not the valid data type");
  if (DataTypeSize != 0 && DataTypeSize != _GET_CURRQEST_VARSIZE()) {
    _PCATCH (VFR_RETURN_INVALID_PARAMETER, L->getLine(), "Numeric varid doesn't support array");
  }
  _PCATCH(NObj.SetFlags (NObj.FLAGS(), _GET_CURRQEST_DATATYPE()), L->getLine());
 consume();
  {
    if ( (LA(1)==FLAGS) ) {
      zzmatch(FLAGS);
      F = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(155); consume();
      vfrNumericFlags( NObj, F->getLine() );
      zzmatch(146); consume();
    }
    else {
      if ( (setwd19[LA(1)]&0x20) ) {
      }
      else {FAIL(1,err97,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==Key) ) {
      zzmatch(Key); consume();
      zzmatch(155); consume();
      zzmatch(Number);
      KN = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(146);
      AssignQuestionKey (NObj, KN);
 consume();
    }
    else {
      if ( (LA(1)==Minimum) ) {
      }
      else {FAIL(1,err98,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  vfrSetMinMaxStep( NObj );
  vfrStatementQuestionOptionList();
  zzmatch(EndNumeric);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd19, 0x40);
}

void
EfiVfrParser::vfrNumericFlags(CIfrNumeric & NObj,UINT32 LineNum)
{
  zzRULE;
  
  UINT8 LFlags = _GET_CURRQEST_DATATYPE() & EFI_IFR_NUMERIC_SIZE;
  UINT8 HFlags = 0;
  EFI_VFR_VARSTORE_TYPE VarStoreType = EFI_VFR_VARSTORE_INVALID;
  numericFlagsField( HFlags, LFlags );
  {
    while ( (LA(1)==157)
 ) {
      zzmatch(157); consume();
      numericFlagsField( HFlags, LFlags );
    }
  }
  
  //check data type flag
  VarStoreType = mCVfrDataStorage.GetVarStoreType (_GET_CURRQEST_VARTINFO().mVarStoreId);
  if (VarStoreType == EFI_VFR_VARSTORE_BUFFER || VarStoreType == EFI_VFR_VARSTORE_EFI) {
    if (_GET_CURRQEST_DATATYPE() != (LFlags & EFI_IFR_NUMERIC_SIZE)) {
      _PCATCH(VFR_RETURN_INVALID_PARAMETER, LineNum, "Numeric Flag is not same to Numeric VarData type");
    }
  } else {
    // update data type for name/value store
    UINT32 DataTypeSize;
    _GET_CURRQEST_VARTINFO().mVarType = LFlags & EFI_IFR_NUMERIC_SIZE;
    gCVfrVarDataTypeDB.GetDataTypeSize (_GET_CURRQEST_DATATYPE(), &DataTypeSize);
    _GET_CURRQEST_VARTINFO().mVarTotalSize = DataTypeSize;
  }
  _PCATCH(NObj.SetFlags (HFlags, LFlags), LineNum);
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd19, 0x80);
}

void
EfiVfrParser::numericFlagsField(UINT8 & HFlags,UINT8 & LFlags)
{
  zzRULE;
  ANTLRTokenPtr N=NULL;
  if ( (LA(1)==Number) ) {
    zzmatch(Number);
    N = (ANTLRTokenPtr)LT(1);

    _PCATCH(_STOU8(N->getText()) == 0 ? VFR_RETURN_SUCCESS : VFR_RETURN_UNSUPPORTED, N->getLine());
 consume();
  }
  else {
    if ( (LA(1)==175) ) {
      zzmatch(175);
      LFlags = ( LFlags & ~EFI_IFR_NUMERIC_SIZE) | EFI_IFR_NUMERIC_SIZE_1;
 consume();
    }
    else {
      if ( (LA(1)==176) ) {
        zzmatch(176);
        LFlags = ( LFlags & ~EFI_IFR_NUMERIC_SIZE) | EFI_IFR_NUMERIC_SIZE_2;
 consume();
      }
      else {
        if ( (LA(1)==177) ) {
          zzmatch(177);
          LFlags = ( LFlags & ~EFI_IFR_NUMERIC_SIZE) | EFI_IFR_NUMERIC_SIZE_4;
 consume();
        }
        else {
          if ( (LA(1)==178)
 ) {
            zzmatch(178);
            LFlags = ( LFlags & ~EFI_IFR_NUMERIC_SIZE) | EFI_IFR_NUMERIC_SIZE_8;
 consume();
          }
          else {
            if ( (LA(1)==179) ) {
              zzmatch(179);
              LFlags = ( LFlags & ~EFI_IFR_DISPLAY) | EFI_IFR_DISPLAY_INT_DEC;
 consume();
            }
            else {
              if ( (LA(1)==180) ) {
                zzmatch(180);
                LFlags = ( LFlags & ~EFI_IFR_DISPLAY) | EFI_IFR_DISPLAY_UINT_DEC;
 consume();
              }
              else {
                if ( (LA(1)==181) ) {
                  zzmatch(181);
                  LFlags = ( LFlags & ~EFI_IFR_DISPLAY) | EFI_IFR_DISPLAY_UINT_HEX;
 consume();
                }
                else {
                  if ( (setwd20[LA(1)]&0x1) ) {
                    questionheaderFlagsField( HFlags );
                  }
                  else {FAIL(1,err99,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
                }
              }
            }
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd20, 0x2);
}

void
EfiVfrParser::vfrStatementOneOf(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, F=NULL, E=NULL;
  
  CIfrOneOf OObj;
  UINT32    DataTypeSize;
  zzmatch(OneOf);
  L = (ANTLRTokenPtr)LT(1);

  OObj.SetLineNo(L->getLine());
 consume();
  vfrQuestionHeader( OObj );
  zzmatch(146);
  //check data type
  _PCATCH (gCVfrVarDataTypeDB.GetDataTypeSize (_GET_CURRQEST_DATATYPE(), &DataTypeSize), L->getLine(), "OneOf varid is not the valid data type");
  if (DataTypeSize != 0 && DataTypeSize != _GET_CURRQEST_VARSIZE()) {
    _PCATCH (VFR_RETURN_INVALID_PARAMETER, L->getLine(), "OneOf varid doesn't support array");
  }
  _PCATCH(OObj.SetFlags (OObj.FLAGS(), _GET_CURRQEST_DATATYPE()), L->getLine());
 consume();
  {
    if ( (LA(1)==FLAGS)
 ) {
      zzmatch(FLAGS);
      F = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(155); consume();
      vfrOneofFlagsField( OObj, F->getLine() );
      zzmatch(146); consume();
    }
    else {
      if ( (setwd20[LA(1)]&0x4) ) {
      }
      else {FAIL(1,err100,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==Minimum) ) {
      vfrSetMinMaxStep( OObj );
    }
    else {
      if ( (setwd20[LA(1)]&0x8) ) {
      }
      else {FAIL(1,err101,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  vfrStatementQuestionOptionList();
  zzmatch(EndOneOf);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd20, 0x10);
}

void
EfiVfrParser::vfrOneofFlagsField(CIfrOneOf & OObj,UINT32 LineNum)
{
  zzRULE;
  
  UINT8 LFlags = _GET_CURRQEST_DATATYPE() & EFI_IFR_NUMERIC_SIZE;
  UINT8 HFlags = 0;
  EFI_VFR_VARSTORE_TYPE VarStoreType = EFI_VFR_VARSTORE_INVALID;
  numericFlagsField( HFlags, LFlags );
  {
    while ( (LA(1)==157) ) {
      zzmatch(157); consume();
      numericFlagsField( HFlags, LFlags );
    }
  }
  
  //check data type flag
  VarStoreType = mCVfrDataStorage.GetVarStoreType (_GET_CURRQEST_VARTINFO().mVarStoreId);
  if (VarStoreType == EFI_VFR_VARSTORE_BUFFER || VarStoreType == EFI_VFR_VARSTORE_EFI) {
    if (_GET_CURRQEST_DATATYPE() != (LFlags & EFI_IFR_NUMERIC_SIZE)) {
      _PCATCH(VFR_RETURN_INVALID_PARAMETER, LineNum, "Numeric Flag is not same to Numeric VarData type");
    }
  } else {
    // update data type for Name/Value store
    UINT32 DataTypeSize;
    _GET_CURRQEST_VARTINFO().mVarType = LFlags & EFI_IFR_NUMERIC_SIZE;
    gCVfrVarDataTypeDB.GetDataTypeSize (_GET_CURRQEST_DATATYPE(), &DataTypeSize);
    _GET_CURRQEST_VARTINFO().mVarTotalSize = DataTypeSize;
  }
  _PCATCH(OObj.SetFlags (HFlags, LFlags), LineNum);
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd20, 0x20);
}

void
EfiVfrParser::vfrStatementStringType(void)
{
  zzRULE;
  if ( (LA(1)==String)
 ) {
    vfrStatementString();
  }
  else {
    if ( (LA(1)==Password) ) {
      vfrStatementPassword();
    }
    else {FAIL(1,err102,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd20, 0x40);
}

void
EfiVfrParser::vfrStatementString(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, F=NULL, KN=NULL, MIN=NULL, MAX=NULL, E=NULL;
  
  CIfrString SObj;
  UINT32 VarArraySize;
  UINT8 StringMinSize;
  UINT8 StringMaxSize;
  zzmatch(String);
  L = (ANTLRTokenPtr)LT(1);

  SObj.SetLineNo(L->getLine());
 consume();
  vfrQuestionHeader( SObj );
  zzmatch(146); consume();
  {
    if ( (LA(1)==FLAGS) ) {
      zzmatch(FLAGS);
      F = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(155); consume();
      vfrStringFlagsField( SObj, F->getLine() );
      zzmatch(146); consume();
    }
    else {
      if ( (setwd20[LA(1)]&0x80) ) {
      }
      else {FAIL(1,err103,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==Key) ) {
      zzmatch(Key); consume();
      zzmatch(155); consume();
      zzmatch(Number);
      KN = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(146);
      AssignQuestionKey (SObj, KN);
 consume();
    }
    else {
      if ( (LA(1)==MinSize)
 ) {
      }
      else {FAIL(1,err104,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(MinSize); consume();
  zzmatch(155); consume();
  zzmatch(Number);
  MIN = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146);
  
  VarArraySize = _GET_CURRQEST_ARRAY_SIZE();
  StringMinSize = _STOU8(MIN->getText());
  if (_STOU64(MIN->getText()) > StringMinSize) {
    _PCATCH (VFR_RETURN_INVALID_PARAMETER, MIN->getLine(), "String MinSize takes only one byte, which can't be larger than 0xFF.");
  } else if (VarArraySize != 0 && StringMinSize > VarArraySize) {
    _PCATCH (VFR_RETURN_INVALID_PARAMETER, MIN->getLine(), "String MinSize can't be larger than the max number of elements in string array.");
  }
  SObj.SetMinSize (StringMinSize);
 consume();
  zzmatch(MaxSize); consume();
  zzmatch(155); consume();
  zzmatch(Number);
  MAX = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146);
  
  StringMaxSize = _STOU8(MAX->getText());
  if (_STOU64(MAX->getText()) > StringMaxSize) {
    _PCATCH (VFR_RETURN_INVALID_PARAMETER, MAX->getLine(), "String MaxSize takes only one byte, which can't be larger than 0xFF.");
  } else if (VarArraySize != 0 && StringMaxSize > VarArraySize) {
    _PCATCH (VFR_RETURN_INVALID_PARAMETER, MAX->getLine(), "String MaxSize can't be larger than the max number of elements in string array.");
  } else if (StringMaxSize < StringMinSize) {
    _PCATCH (VFR_RETURN_INVALID_PARAMETER, MAX->getLine(), "String MaxSize can't be less than String MinSize.");
  }
  SObj.SetMaxSize (StringMaxSize);
 consume();
  vfrStatementQuestionOptionList();
  zzmatch(EndString);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd21, 0x1);
}

void
EfiVfrParser::vfrStringFlagsField(CIfrString & SObj,UINT32 LineNum)
{
  zzRULE;
  
  UINT8 LFlags = 0;
  UINT8 HFlags = 0;
  stringFlagsField( HFlags, LFlags );
  {
    while ( (LA(1)==157) ) {
      zzmatch(157); consume();
      stringFlagsField( HFlags, LFlags );
    }
  }
  _PCATCH(SObj.SetFlags (HFlags, LFlags), LineNum);
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd21, 0x2);
}

void
EfiVfrParser::stringFlagsField(UINT8 & HFlags,UINT8 & LFlags)
{
  zzRULE;
  ANTLRTokenPtr N=NULL;
  if ( (LA(1)==Number) ) {
    zzmatch(Number);
    N = (ANTLRTokenPtr)LT(1);

    _PCATCH(_STOU8(N->getText()) == 0 ? VFR_RETURN_SUCCESS : VFR_RETURN_UNSUPPORTED, N->getLine());
 consume();
  }
  else {
    if ( (LA(1)==182) ) {
      zzmatch(182);
      LFlags = 0x01;
 consume();
    }
    else {
      if ( (setwd21[LA(1)]&0x4) ) {
        questionheaderFlagsField( HFlags );
      }
      else {FAIL(1,err105,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd21, 0x8);
}

void
EfiVfrParser::vfrStatementPassword(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, F=NULL, KN=NULL, MIN=NULL, MAX=NULL, E=NULL;
  
  CIfrPassword PObj;
  UINT32 VarArraySize;
  UINT16 PasswordMinSize;
  UINT16 PasswordMaxSize;
  zzmatch(Password);
  L = (ANTLRTokenPtr)LT(1);

  PObj.SetLineNo(L->getLine());
 consume();
  vfrQuestionHeader( PObj );
  zzmatch(146); consume();
  {
    if ( (LA(1)==FLAGS)
 ) {
      zzmatch(FLAGS);
      F = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(155); consume();
      vfrPasswordFlagsField( PObj, F->getLine() );
      zzmatch(146); consume();
    }
    else {
      if ( (setwd21[LA(1)]&0x10) ) {
      }
      else {FAIL(1,err106,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==Key) ) {
      zzmatch(Key); consume();
      zzmatch(155); consume();
      zzmatch(Number);
      KN = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(146);
      AssignQuestionKey (PObj, KN);
 consume();
    }
    else {
      if ( (LA(1)==MinSize) ) {
      }
      else {FAIL(1,err107,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(MinSize); consume();
  zzmatch(155); consume();
  zzmatch(Number);
  MIN = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146);
  
  VarArraySize = _GET_CURRQEST_ARRAY_SIZE();
  PasswordMinSize = _STOU16(MIN->getText());
  if (_STOU64(MIN->getText()) > PasswordMinSize) {
    _PCATCH (VFR_RETURN_INVALID_PARAMETER, MIN->getLine(), "Password MinSize takes only two byte, which can't be larger than 0xFFFF.");
  } else if (VarArraySize != 0 && PasswordMinSize > VarArraySize) {
    _PCATCH (VFR_RETURN_INVALID_PARAMETER, MIN->getLine(), "Password MinSize can't be larger than the max number of elements in password array.");
  }
  PObj.SetMinSize (PasswordMinSize);
 consume();
  zzmatch(MaxSize); consume();
  zzmatch(155); consume();
  zzmatch(Number);
  MAX = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(146);
  
  PasswordMaxSize = _STOU16(MAX->getText());
  if (_STOU64(MAX->getText()) > PasswordMaxSize) {
    _PCATCH (VFR_RETURN_INVALID_PARAMETER, MAX->getLine(), "Password MaxSize takes only two byte, which can't be larger than 0xFFFF.");
  } else if (VarArraySize != 0 && PasswordMaxSize > VarArraySize) {
    _PCATCH (VFR_RETURN_INVALID_PARAMETER, MAX->getLine(), "Password MaxSize can't be larger than the max number of elements in password array.");
  } else if (PasswordMaxSize < PasswordMinSize) {
    _PCATCH (VFR_RETURN_INVALID_PARAMETER, MAX->getLine(), "Password MaxSize can't be less than Password MinSize.");
  }
  PObj.SetMaxSize (PasswordMaxSize);
 consume();
  {
    if ( (LA(1)==Encoding) ) {
      zzmatch(Encoding); consume();
      zzmatch(155); consume();
      zzmatch(Number); consume();
      zzmatch(146); consume();
    }
    else {
      if ( (setwd21[LA(1)]&0x20)
 ) {
      }
      else {FAIL(1,err108,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  vfrStatementQuestionOptionList();
  zzmatch(EndPassword);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd21, 0x40);
}

void
EfiVfrParser::vfrPasswordFlagsField(CIfrPassword & PObj,UINT32 LineNum)
{
  zzRULE;
  UINT8 HFlags = 0;
  passwordFlagsField( HFlags );
  {
    while ( (LA(1)==157) ) {
      zzmatch(157); consume();
      passwordFlagsField( HFlags );
    }
  }
  _PCATCH(PObj.SetFlags(HFlags), LineNum);
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd21, 0x80);
}

void
EfiVfrParser::passwordFlagsField(UINT8 & HFlags)
{
  zzRULE;
  ANTLRTokenPtr N=NULL;
  if ( (LA(1)==Number) ) {
    zzmatch(Number);
    N = (ANTLRTokenPtr)LT(1);

    _PCATCH(_STOU8(N->getText()) == 0 ? VFR_RETURN_SUCCESS : VFR_RETURN_UNSUPPORTED, N->getLine());
 consume();
  }
  else {
    if ( (setwd22[LA(1)]&0x1) ) {
      questionheaderFlagsField( HFlags );
    }
    else {FAIL(1,err109,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd22, 0x2);
}

void
EfiVfrParser::vfrStatementOrderedList(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, M=NULL, F=NULL, E=NULL;
  
  CIfrOrderedList OLObj;
  UINT32 VarArraySize;
  zzmatch(OrderedList);
  L = (ANTLRTokenPtr)LT(1);

  OLObj.SetLineNo(L->getLine());
 consume();
  vfrQuestionHeader( OLObj );
  zzmatch(146);
  
  VarArraySize = _GET_CURRQEST_ARRAY_SIZE();
  OLObj.SetMaxContainers ((UINT8) (VarArraySize > 0xFF ? 0xFF : VarArraySize));
 consume();
  {
    if ( (LA(1)==MaxContainers) ) {
      zzmatch(MaxContainers); consume();
      zzmatch(155); consume();
      zzmatch(Number);
      M = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(146);
      
      if (_STOU64(M->getText()) > _STOU8(M->getText())) {
        _PCATCH (VFR_RETURN_INVALID_PARAMETER, M->getLine(), "OrderedList MaxContainers takes only one byte, which can't be larger than 0xFF.");
      } else if (VarArraySize != 0 && _STOU8(M->getText()) > VarArraySize) {
        _PCATCH (VFR_RETURN_INVALID_PARAMETER, M->getLine(), "OrderedList MaxContainers can't be larger than the max number of elements in array.");
      }
      OLObj.SetMaxContainers (_STOU8(M->getText()));
 consume();
    }
    else {
      if ( (setwd22[LA(1)]&0x4)
 ) {
      }
      else {FAIL(1,err110,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==FLAGS) ) {
      zzmatch(FLAGS);
      F = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(155); consume();
      vfrOrderedListFlags( OLObj, F->getLine() );
    }
    else {
      if ( (setwd22[LA(1)]&0x8) ) {
      }
      else {FAIL(1,err111,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  vfrStatementQuestionOptionList();
  zzmatch(EndList);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd22, 0x10);
}

void
EfiVfrParser::vfrOrderedListFlags(CIfrOrderedList & OLObj,UINT32 LineNum)
{
  zzRULE;
  
  UINT8 HFlags = 0;
  UINT8 LFlags = 0;
  orderedlistFlagsField( HFlags, LFlags );
  {
    while ( (LA(1)==157) ) {
      zzmatch(157); consume();
      orderedlistFlagsField( HFlags, LFlags );
    }
  }
  _PCATCH(OLObj.SetFlags (HFlags, LFlags), LineNum);
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd22, 0x20);
}

void
EfiVfrParser::orderedlistFlagsField(UINT8 & HFlags,UINT8 & LFlags)
{
  zzRULE;
  ANTLRTokenPtr N=NULL;
  if ( (LA(1)==Number) ) {
    zzmatch(Number);
    N = (ANTLRTokenPtr)LT(1);

    _PCATCH(_STOU8(N->getText()) == 0 ? VFR_RETURN_SUCCESS : VFR_RETURN_UNSUPPORTED, N->getLine());
 consume();
  }
  else {
    if ( (LA(1)==183)
 ) {
      zzmatch(183);
      LFlags |= 0x01;
 consume();
    }
    else {
      if ( (LA(1)==184) ) {
        zzmatch(184);
        LFlags |= 0x02;
 consume();
      }
      else {
        if ( (setwd22[LA(1)]&0x40) ) {
          questionheaderFlagsField( HFlags );
        }
        else {FAIL(1,err112,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd22, 0x80);
}

void
EfiVfrParser::vfrStatementTime(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, F=NULL, T1=NULL, T1H=NULL, HP=NULL, HH=NULL, T2=NULL, T2M=NULL, MP=NULL, MH=NULL, T3=NULL, T3S=NULL, SP=NULL, SH=NULL, E=NULL;
  
  EFI_QUESTION_ID    QId          = EFI_QUESTION_ID_INVALID;
  CHAR8              *VarIdStr[3] = {NULL, };
  CIfrTime           TObj;
  EFI_IFR_TYPE_VALUE Val = gZeroEfiIfrTypeValue;
  zzmatch(Time);
  L = (ANTLRTokenPtr)LT(1);

  TObj.SetLineNo(L->getLine());
 consume();
  {
    if ( (setwd23[LA(1)]&0x1) ) {
      {
        vfrQuestionHeader( TObj, QUESTION_TIME );
        zzmatch(146); consume();
        {
          if ( (LA(1)==FLAGS) ) {
            zzmatch(FLAGS);
            F = (ANTLRTokenPtr)LT(1);
 consume();
            zzmatch(155); consume();
            vfrTimeFlags( TObj, F->getLine() );
            zzmatch(146); consume();
          }
          else {
            if ( (setwd23[LA(1)]&0x2)
 ) {
            }
            else {FAIL(1,err113,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
          }
        }
        vfrStatementQuestionOptionList();
      }
    }
    else {
      if ( (LA(1)==Hour) ) {
        {
          zzmatch(Hour); consume();
          zzmatch(VarId); consume();
          zzmatch(155); consume();
          zzmatch(StringIdentifier);
          T1 = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(158); consume();
          zzmatch(StringIdentifier);
          T1H = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(146);
          _STRCAT(&VarIdStr[0], T1->getText()); _STRCAT(&VarIdStr[0], "."); _STRCAT(&VarIdStr[0], T1H->getText());
 consume();
          zzmatch(Prompt); consume();
          zzmatch(155); consume();
          zzmatch(156); consume();
          zzmatch(OpenParen); consume();
          zzmatch(Number);
          HP = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(CloseParen); consume();
          zzmatch(146); consume();
          zzmatch(Help); consume();
          zzmatch(155); consume();
          zzmatch(156); consume();
          zzmatch(OpenParen); consume();
          zzmatch(Number);
          HH = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(CloseParen); consume();
          zzmatch(146); consume();
          minMaxTimeStepDefault( Val.time, 0 );
          zzmatch(Minute); consume();
          zzmatch(VarId); consume();
          zzmatch(155); consume();
          zzmatch(StringIdentifier);
          T2 = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(158); consume();
          zzmatch(StringIdentifier);
          T2M = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(146);
          _STRCAT(&VarIdStr[1], T2->getText()); _STRCAT(&VarIdStr[1], "."); _STRCAT(&VarIdStr[1], T2M->getText());
 consume();
          zzmatch(Prompt); consume();
          zzmatch(155); consume();
          zzmatch(156); consume();
          zzmatch(OpenParen); consume();
          zzmatch(Number);
          MP = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(CloseParen); consume();
          zzmatch(146); consume();
          zzmatch(Help); consume();
          zzmatch(155); consume();
          zzmatch(156); consume();
          zzmatch(OpenParen); consume();
          zzmatch(Number);
          MH = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(CloseParen); consume();
          zzmatch(146); consume();
          minMaxTimeStepDefault( Val.time, 1 );
          zzmatch(Second); consume();
          zzmatch(VarId); consume();
          zzmatch(155); consume();
          zzmatch(StringIdentifier);
          T3 = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(158); consume();
          zzmatch(StringIdentifier);
          T3S = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(146);
          _STRCAT(&VarIdStr[2], T3->getText()); _STRCAT(&VarIdStr[2], "."); _STRCAT(&VarIdStr[2], T3S->getText());
 consume();
          zzmatch(Prompt); consume();
          zzmatch(155); consume();
          zzmatch(156); consume();
          zzmatch(OpenParen); consume();
          zzmatch(Number);
          SP = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(CloseParen); consume();
          zzmatch(146); consume();
          zzmatch(Help); consume();
          zzmatch(155); consume();
          zzmatch(156); consume();
          zzmatch(OpenParen); consume();
          zzmatch(Number);
          SH = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(CloseParen); consume();
          zzmatch(146); consume();
          minMaxTimeStepDefault( Val.time, 2 );
          
          mCVfrQuestionDB.RegisterOldTimeQuestion (VarIdStr[0], VarIdStr[1], VarIdStr[2], QId);
          TObj.SetQuestionId (QId);
          TObj.SetFlags (EFI_IFR_QUESTION_FLAG_DEFAULT, QF_TIME_STORAGE_TIME);
          TObj.SetPrompt (_STOSID(HP->getText()));
          TObj.SetHelp (_STOSID(HH->getText()));
          if (VarIdStr[0] != NULL) { delete VarIdStr[0]; } if (VarIdStr[1] != NULL) { delete VarIdStr[1]; } if (VarIdStr[2] != NULL) { delete VarIdStr[2]; }
          {CIfrDefault DefaultObj(EFI_HII_DEFAULT_CLASS_STANDARD, EFI_IFR_TYPE_TIME, Val); DefaultObj.SetLineNo(L->getLine());}
        }
        {
          while ( (LA(1)==InconsistentIf) ) {
            vfrStatementInconsistentIf();
          }
        }
      }
      else {FAIL(1,err114,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(EndTime);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd23, 0x4);
}

void
EfiVfrParser::minMaxTimeStepDefault(EFI_HII_TIME & T,UINT8 KeyValue)
{
  zzRULE;
  ANTLRTokenPtr N=NULL;
  zzmatch(Minimum); consume();
  zzmatch(155); consume();
  zzmatch(Number); consume();
  zzmatch(146); consume();
  zzmatch(Maximum); consume();
  zzmatch(155); consume();
  zzmatch(Number); consume();
  zzmatch(146); consume();
  {
    if ( (LA(1)==STEP) ) {
      zzmatch(STEP); consume();
      zzmatch(155); consume();
      zzmatch(Number); consume();
      zzmatch(146); consume();
    }
    else {
      if ( (setwd23[LA(1)]&0x8) ) {
      }
      else {FAIL(1,err115,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==Default)
 ) {
      zzmatch(Default); consume();
      zzmatch(155); consume();
      zzmatch(Number);
      N = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(146);
      
      switch (KeyValue) {
        case 0: 
        T.Hour   = _STOU8(N->getText()); 
        if (T.Hour > 23) {
          _PCATCH (VFR_RETURN_INVALID_PARAMETER, N->getLine(), "Hour default value must be between 0 and 23.");
        }
        break;
        case 1: 
        T.Minute = _STOU8(N->getText()); 
        if (T.Minute > 59) {
          _PCATCH (VFR_RETURN_INVALID_PARAMETER, N->getLine(), "Minute default value must be between 0 and 59.");
        }
        break;
        case 2: 
        T.Second = _STOU8(N->getText());
        if (T.Second > 59) {
          _PCATCH (VFR_RETURN_INVALID_PARAMETER, N->getLine(), "Second default value must be between 0 and 59.");
        }
        break;
      }
 consume();
    }
    else {
      if ( (setwd23[LA(1)]&0x10) ) {
      }
      else {FAIL(1,err116,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd23, 0x20);
}

void
EfiVfrParser::vfrTimeFlags(CIfrTime & TObj,UINT32 LineNum)
{
  zzRULE;
  UINT8 LFlags = 0;
  timeFlagsField( LFlags );
  {
    while ( (LA(1)==157) ) {
      zzmatch(157); consume();
      timeFlagsField( LFlags );
    }
  }
  _PCATCH(TObj.SetFlags(EFI_IFR_QUESTION_FLAG_DEFAULT, LFlags), LineNum);
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd23, 0x40);
}

void
EfiVfrParser::timeFlagsField(UINT8 & Flags)
{
  zzRULE;
  ANTLRTokenPtr N=NULL;
  if ( (LA(1)==Number) ) {
    zzmatch(Number);
    N = (ANTLRTokenPtr)LT(1);

    Flags |= _STOU8(N->getText());
 consume();
  }
  else {
    if ( (LA(1)==185) ) {
      zzmatch(185);
      Flags |= 0x01;
 consume();
    }
    else {
      if ( (LA(1)==186)
 ) {
        zzmatch(186);
        Flags |= 0x02;
 consume();
      }
      else {
        if ( (LA(1)==187) ) {
          zzmatch(187);
          Flags |= 0x04;
 consume();
        }
        else {
          if ( (LA(1)==172) ) {
            zzmatch(172);
            Flags |= 0x00;
 consume();
          }
          else {
            if ( (LA(1)==173) ) {
              zzmatch(173);
              Flags |= 0x10;
 consume();
            }
            else {
              if ( (LA(1)==174) ) {
                zzmatch(174);
                Flags |= 0x20;
 consume();
              }
              else {FAIL(1,err117,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
            }
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd23, 0x80);
}

void
EfiVfrParser::vfrStatementQuestionTag(void)
{
  zzRULE;
  if ( (setwd24[LA(1)]&0x1)
 ) {
    vfrStatementStatTag();
    zzmatch(146); consume();
  }
  else {
    if ( (LA(1)==InconsistentIf) ) {
      vfrStatementInconsistentIf();
    }
    else {
      if ( (LA(1)==NoSubmitIf) ) {
        vfrStatementNoSubmitIf();
      }
      else {
        if ( (LA(1)==DisableIf) ) {
          vfrStatementDisableIfQuest();
        }
        else {
          if ( (LA(1)==Refresh) ) {
            vfrStatementRefresh();
          }
          else {
            if ( (LA(1)==VarstoreDevice)
 ) {
              vfrStatementVarstoreDevice();
            }
            else {FAIL(1,err118,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd24, 0x2);
}

void
EfiVfrParser::vfrStatementQuestionTagList(void)
{
  zzRULE;
  {
    while ( (setwd24[LA(1)]&0x4) ) {
      vfrStatementQuestionTag();
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd24, 0x8);
}

void
EfiVfrParser::vfrStatementQuestionOptionTag(void)
{
  zzRULE;
  if ( (LA(1)==SuppressIf) ) {
    vfrStatementSuppressIfQuest();
  }
  else {
    if ( (LA(1)==GrayOutIf) ) {
      vfrStatementGrayOutIfQuest();
    }
    else {
      if ( (LA(1)==Value) ) {
        vfrStatementValue();
      }
      else {
        if ( (LA(1)==Default)
 ) {
          vfrStatementDefault();
        }
        else {
          if ( (LA(1)==Read) ) {
            vfrStatementRead();
          }
          else {
            if ( (LA(1)==Write) ) {
              vfrStatementWrite();
            }
            else {
              if ( (LA(1)==Option) ) {
                vfrStatementOptions();
              }
              else {FAIL(1,err119,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
            }
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd24, 0x10);
}

void
EfiVfrParser::vfrStatementQuestionOptionList(void)
{
  zzRULE;
  {
    for (;;) {
      if ( !((setwd24[LA(1)]&0x20))) break;
      if ( (setwd24[LA(1)]&0x40)
 ) {
        vfrStatementQuestionTag();
      }
      else {
        if ( (setwd24[LA(1)]&0x80) ) {
          vfrStatementQuestionOptionTag();
        }
        else break; /* MR6 code for exiting loop "for sure" */
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd25, 0x1);
}

void
EfiVfrParser::vfrStatementStatList(void)
{
  zzRULE;
  if ( (setwd25[LA(1)]&0x2) ) {
    vfrStatementStat();
  }
  else {
    if ( (setwd25[LA(1)]&0x4) ) {
      vfrStatementQuestions();
    }
    else {
      if ( (setwd25[LA(1)]&0x8) ) {
        vfrStatementConditionalNew();
      }
      else {
        if ( (LA(1)==Label)
 ) {
          vfrStatementLabel();
        }
        else {
          if ( (setwd25[LA(1)]&0x10) ) {
            vfrStatementInvalid();
          }
          else {FAIL(1,err120,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd25, 0x20);
}

void
EfiVfrParser::vfrStatementStatListOld(void)
{
  zzRULE;
  if ( (setwd25[LA(1)]&0x40) ) {
    vfrStatementStat();
  }
  else {
    if ( (setwd25[LA(1)]&0x80) ) {
      vfrStatementQuestions();
    }
    else {
      if ( (LA(1)==Label) ) {
        vfrStatementLabel();
      }
      else {
        if ( (setwd26[LA(1)]&0x1)
 ) {
          vfrStatementInvalid();
        }
        else {FAIL(1,err121,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd26, 0x2);
}

void
EfiVfrParser::vfrStatementDisableIfStat(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, E=NULL;
  
  CIfrDisableIf DIObj;
  zzmatch(DisableIf);
  L = (ANTLRTokenPtr)LT(1);

  DIObj.SetLineNo(L->getLine());
 consume();
  vfrStatementExpression( 0 );
  zzmatch(151); consume();
  {
    while ( (setwd26[LA(1)]&0x4) ) {
      vfrStatementStatList();
    }
  }
  zzmatch(EndIf);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd26, 0x8);
}

void
EfiVfrParser::vfrStatementInconsistentIfStat(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, S=NULL, E=NULL;
  CIfrInconsistentIf IIObj;
  zzmatch(InconsistentIf);
  L = (ANTLRTokenPtr)LT(1);

  
  if (!mCompatibleMode) {
    _PCATCH (VFR_RETURN_UNSUPPORTED, L);
  }
  IIObj.SetLineNo(L->getLine());
 consume();
  zzmatch(Prompt); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  S = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen); consume();
  zzmatch(146);
  IIObj.SetError (_STOSID(S->getText()));
 consume();
  {
    if ( (LA(1)==FLAGS) ) {
      zzmatch(FLAGS); consume();
      zzmatch(155); consume();
      flagsField();
      {
        while ( (LA(1)==157) ) {
          zzmatch(157); consume();
          flagsField();
        }
      }
      zzmatch(146); consume();
    }
    else {
      if ( (setwd26[LA(1)]&0x10) ) {
      }
      else {FAIL(1,err122,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  vfrStatementExpression( 0 );
  zzmatch(EndIf);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd26, 0x20);
}

void
EfiVfrParser::vfrStatementgrayoutIfSuppressIf(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  CIfrSuppressIf SIObj;
  zzmatch(SuppressIf);
  L = (ANTLRTokenPtr)LT(1);

  SIObj.SetLineNo(L->getLine());
 consume();
  {
    if ( (LA(1)==FLAGS)
 ) {
      zzmatch(FLAGS); consume();
      zzmatch(155); consume();
      flagsField();
      {
        while ( (LA(1)==157) ) {
          zzmatch(157); consume();
          flagsField();
        }
      }
      zzmatch(146); consume();
    }
    else {
      if ( (setwd26[LA(1)]&0x40) ) {
      }
      else {FAIL(1,err123,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  vfrStatementExpression( 0 );
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd26, 0x80);
}

void
EfiVfrParser::vfrStatementsuppressIfGrayOutIf(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  CIfrGrayOutIf GOIObj;
  zzmatch(GrayOutIf);
  L = (ANTLRTokenPtr)LT(1);

  GOIObj.SetLineNo(L->getLine());
 consume();
  {
    if ( (LA(1)==FLAGS) ) {
      zzmatch(FLAGS); consume();
      zzmatch(155); consume();
      flagsField();
      {
        while ( (LA(1)==157) ) {
          zzmatch(157); consume();
          flagsField();
        }
      }
      zzmatch(146); consume();
    }
    else {
      if ( (setwd27[LA(1)]&0x1)
 ) {
      }
      else {FAIL(1,err124,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  vfrStatementExpression( 0 );
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd27, 0x2);
}

void
EfiVfrParser::vfrStatementSuppressIfStatNew(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, E=NULL;
  CIfrSuppressIf SIObj;
  zzmatch(SuppressIf);
  L = (ANTLRTokenPtr)LT(1);

  SIObj.SetLineNo(L->getLine());
 consume();
  {
    if ( (LA(1)==FLAGS) ) {
      zzmatch(FLAGS); consume();
      zzmatch(155); consume();
      flagsField();
      {
        while ( (LA(1)==157) ) {
          zzmatch(157); consume();
          flagsField();
        }
      }
      zzmatch(146); consume();
    }
    else {
      if ( (setwd27[LA(1)]&0x4) ) {
      }
      else {FAIL(1,err125,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  vfrStatementExpression( 0 );
  zzmatch(151); consume();
  {
    while ( (setwd27[LA(1)]&0x8) ) {
      vfrStatementStatList();
    }
  }
  zzmatch(EndIf);
  E = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(151);
  CRT_END_OP (E);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd27, 0x10);
}

void
EfiVfrParser::vfrStatementGrayOutIfStatNew(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, E=NULL;
  CIfrGrayOutIf GOIObj;
  zzmatch(GrayOutIf);
  L = (ANTLRTokenPtr)LT(1);

  GOIObj.SetLineNo(L->getLine());
 consume();
  {
    if ( (LA(1)==FLAGS)
 ) {
      zzmatch(FLAGS); consume();
      zzmatch(155); consume();
      flagsField();
      {
        while ( (LA(1)==157) ) {
          zzmatch(157); consume();
          flagsField();
        }
      }
      zzmatch(146); consume();
    }
    else {
      if ( (setwd27[LA(1)]&0x20) ) {
      }
      else {FAIL(1,err126,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  vfrStatementExpression( 0 );
  zzmatch(151); consume();
  {
    while ( (setwd27[LA(1)]&0x40) ) {
      vfrStatementStatList();
    }
  }
  zzmatch(EndIf);
  E = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(151);
  CRT_END_OP (E);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd27, 0x80);
}

void
EfiVfrParser::vfrStatementSuppressIfStatOld(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, E=NULL;
  
  CIfrSuppressIf SIObj;
  BOOLEAN        GrayOutExist = FALSE;
  zzmatch(SuppressIf);
  L = (ANTLRTokenPtr)LT(1);

  SIObj.SetLineNo(L->getLine());
 consume();
  {
    if ( (LA(1)==FLAGS) ) {
      zzmatch(FLAGS); consume();
      zzmatch(155); consume();
      flagsField();
      {
        while ( (LA(1)==157)
 ) {
          zzmatch(157); consume();
          flagsField();
        }
      }
      zzmatch(146); consume();
    }
    else {
      if ( (setwd28[LA(1)]&0x1) ) {
      }
      else {FAIL(1,err127,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  vfrStatementExpression( 0 );
  zzmatch(151); consume();
  {
    if ( (LA(1)==GrayOutIf) ) {
      vfrStatementsuppressIfGrayOutIf();
      GrayOutExist = TRUE;
    }
    else {
      if ( (setwd28[LA(1)]&0x2) ) {
      }
      else {FAIL(1,err128,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    while ( (setwd28[LA(1)]&0x4) ) {
      vfrStatementStatListOld();
    }
  }
  zzmatch(EndIf);
  E = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(151);
  if (GrayOutExist) CRT_END_OP (E); CRT_END_OP (E);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd28, 0x8);
}

void
EfiVfrParser::vfrStatementGrayOutIfStatOld(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, E=NULL;
  
  CIfrGrayOutIf  GOIObj;
  BOOLEAN        SuppressExist = FALSE;
  zzmatch(GrayOutIf);
  L = (ANTLRTokenPtr)LT(1);

  GOIObj.SetLineNo(L->getLine());
 consume();
  {
    if ( (LA(1)==FLAGS)
 ) {
      zzmatch(FLAGS); consume();
      zzmatch(155); consume();
      flagsField();
      {
        while ( (LA(1)==157) ) {
          zzmatch(157); consume();
          flagsField();
        }
      }
      zzmatch(146); consume();
    }
    else {
      if ( (setwd28[LA(1)]&0x10) ) {
      }
      else {FAIL(1,err129,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  vfrStatementExpression( 0 );
  zzmatch(151); consume();
  {
    if ( (LA(1)==SuppressIf) ) {
      vfrStatementgrayoutIfSuppressIf();
      SuppressExist = TRUE;
    }
    else {
      if ( (setwd28[LA(1)]&0x20) ) {
      }
      else {FAIL(1,err130,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    while ( (setwd28[LA(1)]&0x40)
 ) {
      vfrStatementStatListOld();
    }
  }
  zzmatch(EndIf);
  E = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(151);
  if (SuppressExist) CRT_END_OP (E); CRT_END_OP (E);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd28, 0x80);
}

void
EfiVfrParser::vfrImageTag(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, S1=NULL;
  CIfrImage IObj;
  zzmatch(Image);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(155); consume();
  zzmatch(188); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  S1 = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen);
  IObj.SetImageId (_STOSID(S1->getText())); IObj.SetLineNo(L->getLine());
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd29, 0x1);
}

void
EfiVfrParser::vfrLockedTag(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  CIfrLocked LObj;
  zzmatch(Locked);
  L = (ANTLRTokenPtr)LT(1);

  LObj.SetLineNo(L->getLine());
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd29, 0x2);
}

void
EfiVfrParser::vfrStatementStatTag(void)
{
  zzRULE;
  if ( (LA(1)==Image) ) {
    vfrImageTag();
  }
  else {
    if ( (LA(1)==Locked) ) {
      vfrLockedTag();
    }
    else {FAIL(1,err131,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd29, 0x4);
}

void
EfiVfrParser::vfrStatementStatTagList(void)
{
  zzRULE;
  vfrStatementStatTag();
  {
    while ( (LA(1)==146) && (setwd29[LA(2)]&0x8) && (setwd29[LA(3)]&0x10) ) {
      zzmatch(146); consume();
      vfrStatementStatTag();
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd29, 0x20);
}

void
EfiVfrParser::vfrStatementImage(void)
{
  zzRULE;
  vfrImageTag();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd29, 0x40);
}

void
EfiVfrParser::vfrStatementLocked(void)
{
  zzRULE;
  vfrLockedTag();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd29, 0x80);
}

void
EfiVfrParser::vfrStatementInconsistentIf(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, S=NULL, E=NULL;
  CIfrInconsistentIf IIObj;
  zzmatch(InconsistentIf);
  L = (ANTLRTokenPtr)LT(1);

  IIObj.SetLineNo(L->getLine());
 consume();
  zzmatch(Prompt); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  S = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen); consume();
  zzmatch(146);
  IIObj.SetError (_STOSID(S->getText()));
 consume();
  {
    if ( (LA(1)==FLAGS)
 ) {
      zzmatch(FLAGS); consume();
      zzmatch(155); consume();
      flagsField();
      {
        while ( (LA(1)==157) ) {
          zzmatch(157); consume();
          flagsField();
        }
      }
      zzmatch(146); consume();
    }
    else {
      if ( (setwd30[LA(1)]&0x1) ) {
      }
      else {FAIL(1,err132,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  vfrStatementExpression( 0 );
  zzmatch(EndIf);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd30, 0x2);
}

void
EfiVfrParser::vfrStatementNoSubmitIf(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, S=NULL, E=NULL;
  CIfrNoSubmitIf NSIObj;
  zzmatch(NoSubmitIf);
  L = (ANTLRTokenPtr)LT(1);

  NSIObj.SetLineNo(L->getLine());
 consume();
  zzmatch(Prompt); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  S = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen); consume();
  zzmatch(146);
  NSIObj.SetError (_STOSID(S->getText()));
 consume();
  {
    if ( (LA(1)==FLAGS) ) {
      zzmatch(FLAGS); consume();
      zzmatch(155); consume();
      flagsField();
      {
        while ( (LA(1)==157) ) {
          zzmatch(157); consume();
          flagsField();
        }
      }
      zzmatch(146); consume();
    }
    else {
      if ( (setwd30[LA(1)]&0x4)
 ) {
      }
      else {FAIL(1,err133,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  vfrStatementExpression( 0 );
  zzmatch(EndIf);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd30, 0x8);
}

void
EfiVfrParser::vfrStatementDisableIfQuest(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, E=NULL;
  
  CIfrDisableIf DIObj;
  zzmatch(DisableIf);
  L = (ANTLRTokenPtr)LT(1);

  DIObj.SetLineNo(L->getLine());
 consume();
  vfrStatementExpression( 0 );
  zzmatch(151); consume();
  vfrStatementQuestionOptionList();
  zzmatch(EndIf);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd30, 0x10);
}

void
EfiVfrParser::vfrStatementRefresh(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, I=NULL;
  CIfrRefresh RObj;
  zzmatch(Refresh);
  L = (ANTLRTokenPtr)LT(1);

  RObj.SetLineNo(L->getLine());
 consume();
  zzmatch(Interval); consume();
  zzmatch(155); consume();
  zzmatch(Number);
  I = (ANTLRTokenPtr)LT(1);

  RObj.SetRefreshInterval (_STOU8(I->getText()));
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd30, 0x20);
}

void
EfiVfrParser::vfrStatementVarstoreDevice(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, S=NULL;
  CIfrVarStoreDevice VDObj;
  zzmatch(VarstoreDevice);
  L = (ANTLRTokenPtr)LT(1);

  VDObj.SetLineNo(L->getLine());
 consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  S = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen); consume();
  zzmatch(146);
  VDObj.SetDevicePath (_STOSID(S->getText()));
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd30, 0x40);
}

void
EfiVfrParser::vfrStatementSuppressIfQuest(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, E=NULL;
  CIfrSuppressIf SIObj;
  zzmatch(SuppressIf);
  L = (ANTLRTokenPtr)LT(1);

  SIObj.SetLineNo(L->getLine());
 consume();
  {
    if ( (LA(1)==FLAGS) ) {
      zzmatch(FLAGS); consume();
      zzmatch(155); consume();
      flagsField();
      {
        while ( (LA(1)==157) ) {
          zzmatch(157); consume();
          flagsField();
        }
      }
      zzmatch(146); consume();
    }
    else {
      if ( (setwd30[LA(1)]&0x80) ) {
      }
      else {FAIL(1,err134,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  vfrStatementExpression( 0 );
  zzmatch(151); consume();
  vfrStatementQuestionOptionList();
  zzmatch(EndIf);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd31, 0x1);
}

void
EfiVfrParser::vfrStatementGrayOutIfQuest(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, E=NULL;
  CIfrGrayOutIf GOIObj;
  zzmatch(GrayOutIf);
  L = (ANTLRTokenPtr)LT(1);

  GOIObj.SetLineNo(L->getLine());
 consume();
  {
    if ( (LA(1)==FLAGS) ) {
      zzmatch(FLAGS); consume();
      zzmatch(155); consume();
      flagsField();
      {
        while ( (LA(1)==157)
 ) {
          zzmatch(157); consume();
          flagsField();
        }
      }
      zzmatch(146); consume();
    }
    else {
      if ( (setwd31[LA(1)]&0x2) ) {
      }
      else {FAIL(1,err135,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  vfrStatementExpression( 0 );
  zzmatch(151); consume();
  vfrStatementQuestionOptionList();
  zzmatch(EndIf);
  E = (ANTLRTokenPtr)LT(1);

  CRT_END_OP (E);
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd31, 0x4);
}

void
EfiVfrParser::vfrStatementOptions(void)
{
  zzRULE;
  vfrStatementOneOfOption();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd31, 0x8);
}

void
EfiVfrParser::vfrStatementOneOfOption(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, S=NULL, F=NULL, KN=NULL, T=NULL;
  
  EFI_IFR_TYPE_VALUE Val = gZeroEfiIfrTypeValue;
  CIfrOneOfOption    OOOObj;
  CHAR8              *VarStoreName = NULL;
  zzmatch(Option);
  L = (ANTLRTokenPtr)LT(1);

  OOOObj.SetLineNo(L->getLine());
 consume();
  zzmatch(Text); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  S = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen); consume();
  zzmatch(146);
  OOOObj.SetOption (_STOSID(S->getText()));
 consume();
  zzmatch(Value); consume();
  zzmatch(155); consume();
   Val  = vfrConstantValueField( _GET_CURRQEST_DATATYPE() );

  zzmatch(146);
  
  if (gCurrentMinMaxData != NULL) {
    //set min/max value for oneof opcode
    UINT64 Step = gCurrentMinMaxData->GetStepData(_GET_CURRQEST_DATATYPE());
    switch (_GET_CURRQEST_DATATYPE()) {
      case EFI_IFR_TYPE_NUM_SIZE_64:
      gCurrentMinMaxData->SetMinMaxStepData(Val.u64, Val.u64, Step);
      break;
      case EFI_IFR_TYPE_NUM_SIZE_32:
      gCurrentMinMaxData->SetMinMaxStepData(Val.u32, Val.u32, (UINT32) Step);
      break;
      case EFI_IFR_TYPE_NUM_SIZE_16:
      gCurrentMinMaxData->SetMinMaxStepData(Val.u16, Val.u16, (UINT16) Step);
      break;
      case EFI_IFR_TYPE_NUM_SIZE_8:
      gCurrentMinMaxData->SetMinMaxStepData(Val.u8, Val.u8, (UINT8) Step);
      break;
      default:
      break;
    }
  }
  OOOObj.SetType (_GET_CURRQEST_DATATYPE()); 
  OOOObj.SetValue (Val);
 consume();
  zzmatch(FLAGS);
  F = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(155); consume();
  vfrOneOfOptionFlags( OOOObj, F->getLine() );
  
  _PCATCH(mCVfrDataStorage.GetVarStoreName (_GET_CURRQEST_VARTINFO().mVarStoreId, &VarStoreName), L->getLine());
  if (OOOObj.GetFlags () & 0x10) {
    _PCATCH(mCVfrDefaultStore.BufferVarStoreAltConfigAdd (
    EFI_HII_DEFAULT_CLASS_STANDARD,
    _GET_CURRQEST_VARTINFO(),
    VarStoreName,
    _GET_CURRQEST_DATATYPE (),
    Val
    ), L->getLine());
  }
  if (OOOObj.GetFlags () & 0x20) {
    _PCATCH(mCVfrDefaultStore.BufferVarStoreAltConfigAdd (
    EFI_HII_DEFAULT_CLASS_MANUFACTURING,
    _GET_CURRQEST_VARTINFO(),
    VarStoreName,
    _GET_CURRQEST_DATATYPE (),
    Val
    ), L->getLine());
  }
  {
    if ( (LA(1)==146) && (LA(2)==Key) ) {
      zzmatch(146); consume();
      zzmatch(Key); consume();
      zzmatch(155); consume();
      zzmatch(Number);
      KN = (ANTLRTokenPtr)LT(1);

      
      if (!mCompatibleMode) {
        _PCATCH (VFR_RETURN_UNSUPPORTED, KN);
      }
      //
      // Guid Option Key
      //
      CIfrOptionKey IfrOptionKey (
      gCurrentQuestion->QUESTION_ID(),
      Val,
      _STOQID(KN->getText())
      );
      SET_LINE_INFO (IfrOptionKey, KN);
 consume();
    }
    else {
      if ( (setwd31[LA(1)]&0x10) && (setwd31[LA(2)]&0x20)
 ) {
      }
      else {FAIL(2,err136,err137,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    while ( (LA(1)==146) ) {
      zzmatch(146);
      T = (ANTLRTokenPtr)LT(1);
 consume();
      vfrImageTag();
      OOOObj.SetScope (1); CRT_END_OP (T);
    }
  }
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd31, 0x40);
}

void
EfiVfrParser::vfrOneOfOptionFlags(CIfrOneOfOption & OOOObj,UINT32 LineNum)
{
  zzRULE;
  
  UINT8 LFlags = _GET_CURRQEST_DATATYPE();
  UINT8 HFlags = 0;
  oneofoptionFlagsField( HFlags, LFlags );
  {
    while ( (LA(1)==157) ) {
      zzmatch(157); consume();
      oneofoptionFlagsField( HFlags, LFlags );
    }
  }
  _PCATCH(gCurrentQuestion->SetFlags(HFlags), LineNum);
  _PCATCH(OOOObj.SetFlags(LFlags), LineNum);
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd31, 0x80);
}

void
EfiVfrParser::oneofoptionFlagsField(UINT8 & HFlags,UINT8 & LFlags)
{
  zzRULE;
  ANTLRTokenPtr N=NULL;
  if ( (LA(1)==Number) ) {
    zzmatch(Number);
    N = (ANTLRTokenPtr)LT(1);

    LFlags |= _STOU8(N->getText());
 consume();
  }
  else {
    if ( (LA(1)==189) ) {
      zzmatch(189);
      LFlags |= 0x10;
 consume();
    }
    else {
      if ( (LA(1)==190)
 ) {
        zzmatch(190);
        LFlags |= 0x20;
 consume();
      }
      else {
        if ( (LA(1)==InteractiveFlag) ) {
          zzmatch(InteractiveFlag);
          HFlags |= 0x04;
 consume();
        }
        else {
          if ( (LA(1)==NVAccessFlag) ) {
            zzmatch(NVAccessFlag);
            HFlags |= 0x08;
 consume();
          }
          else {
            if ( (LA(1)==ResetRequiredFlag) ) {
              zzmatch(ResetRequiredFlag);
              HFlags |= 0x10;
 consume();
            }
            else {
              if ( (LA(1)==LateCheckFlag) ) {
                zzmatch(LateCheckFlag);
                HFlags |= 0x20;
 consume();
              }
              else {
                if ( (LA(1)==ManufacturingFlag)
 ) {
                  zzmatch(ManufacturingFlag);
                  LFlags |= 0x20;
 consume();
                }
                else {
                  if ( (LA(1)==DefaultFlag) ) {
                    zzmatch(DefaultFlag);
                    LFlags |= 0x10;
 consume();
                  }
                  else {FAIL(1,err138,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
                }
              }
            }
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd32, 0x1);
}

void
EfiVfrParser::vfrStatementLabel(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, N=NULL;
  zzmatch(Label);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(Number);
  N = (ANTLRTokenPtr)LT(1);

  
  if (mCompatibleMode) {
    //
    // Add end Label for Framework Vfr
    //
    CIfrLabel LObj1;
    LObj1.SetLineNo(L->getLine());
    LObj1.SetNumber (0xffff);  //add end label for UEFI, label number hardcode 0xffff
  }
  
  {
    CIfrLabel LObj2;
    LObj2.SetLineNo(L->getLine());
    LObj2.SetNumber (_STOU16(N->getText()));
  }
 consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd32, 0x2);
}

void
EfiVfrParser::vfrStatementBanner(void)
{
  zzRULE;
  ANTLRTokenPtr B=NULL, S=NULL, L=NULL, T=NULL;
  CIfrBanner BObj;
  zzmatch(Banner);
  B = (ANTLRTokenPtr)LT(1);
 consume();
  {
    if ( (LA(1)==146) ) {
      zzmatch(146); consume();
    }
    else {
      if ( (LA(1)==Title) ) {
      }
      else {FAIL(1,err139,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  BObj.SetLineNo(B->getLine());
  zzmatch(Title); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  S = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen); consume();
  zzmatch(146);
  BObj.SetTitle (_STOSID(S->getText()));
 consume();
  {
    if ( (LA(1)==Line) ) {
      {
        zzmatch(Line); consume();
        zzmatch(Number);
        L = (ANTLRTokenPtr)LT(1);
 consume();
        zzmatch(146);
        BObj.SetLine (_STOU16(L->getText()));
 consume();
        zzmatch(Align); consume();
        {
          if ( (LA(1)==Left)
 ) {
            zzmatch(Left);
            BObj.SetAlign (0);
 consume();
          }
          else {
            if ( (LA(1)==Center) ) {
              zzmatch(Center);
              BObj.SetAlign (1);
 consume();
            }
            else {
              if ( (LA(1)==Right) ) {
                zzmatch(Right);
                BObj.SetAlign (2);
 consume();
              }
              else {FAIL(1,err140,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
            }
          }
        }
        zzmatch(151); consume();
      }
    }
    else {
      if ( (LA(1)==Timeout) ) {
        {
          zzmatch(Timeout); consume();
          zzmatch(155); consume();
          zzmatch(Number);
          T = (ANTLRTokenPtr)LT(1);
 consume();
          zzmatch(151);
          {CIfrTimeout TObj(_STOU16(T->getText()));}
 consume();
        }
      }
      else {FAIL(1,err141,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd32, 0x4);
}

void
EfiVfrParser::vfrStatementInvalidHidden(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  zzmatch(Hidden);
  L = (ANTLRTokenPtr)LT(1);

  
  if (!mCompatibleMode) {
    _PCATCH (VFR_RETURN_UNSUPPORTED, L);
  }
 consume();
  zzmatch(Value); consume();
  zzmatch(155); consume();
  zzmatch(Number); consume();
  zzmatch(146); consume();
  zzmatch(Key); consume();
  zzmatch(155); consume();
  zzmatch(Number); consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd32, 0x8);
}

void
EfiVfrParser::vfrStatementInvalidInconsistentIf(void)
{
  zzRULE;
  ANTLRTokenPtr S=NULL;
  zzmatch(InconsistentIf); consume();
  zzmatch(Prompt); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  S = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen); consume();
  zzmatch(146); consume();
  {
    if ( (LA(1)==FLAGS) ) {
      zzmatch(FLAGS); consume();
      zzmatch(155); consume();
      flagsField();
      {
        while ( (LA(1)==157)
 ) {
          zzmatch(157); consume();
          flagsField();
        }
      }
      zzmatch(146); consume();
    }
    else {
      if ( (setwd32[LA(1)]&0x10) ) {
      }
      else {FAIL(1,err142,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  vfrStatementExpression( 0 );
  zzmatch(EndIf); consume();
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd32, 0x20);
}

void
EfiVfrParser::vfrStatementInvalidInventory(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  zzmatch(Inventory);
  L = (ANTLRTokenPtr)LT(1);

  
  if (!mCompatibleMode) {
    _PCATCH (VFR_RETURN_UNSUPPORTED, L);
  }
 consume();
  zzmatch(Help); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number); consume();
  zzmatch(CloseParen); consume();
  zzmatch(146); consume();
  zzmatch(Text); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number); consume();
  zzmatch(CloseParen); consume();
  zzmatch(146); consume();
  {
    if ( (LA(1)==Text) ) {
      zzmatch(Text); consume();
      zzmatch(155); consume();
      zzmatch(156); consume();
      zzmatch(OpenParen); consume();
      zzmatch(Number); consume();
      zzmatch(CloseParen); consume();
    }
    else {
      if ( (LA(1)==151) ) {
      }
      else {FAIL(1,err143,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd32, 0x40);
}

void
EfiVfrParser::vfrStatementInvalidSaveRestoreDefaults(void)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, K=NULL;
  {
    if ( (LA(1)==Save) ) {
      zzmatch(Save);
      L = (ANTLRTokenPtr)LT(1);

      
      if (!mCompatibleMode) {
        _PCATCH (VFR_RETURN_UNSUPPORTED, L);
      }
 consume();
    }
    else {
      if ( (LA(1)==Restore)
 ) {
        zzmatch(Restore);
        K = (ANTLRTokenPtr)LT(1);

        
        if (!mCompatibleMode) {
          _PCATCH (VFR_RETURN_UNSUPPORTED, K);
        }
 consume();
      }
      else {FAIL(1,err144,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(Defaults); consume();
  zzmatch(146); consume();
  zzmatch(FormId); consume();
  zzmatch(155); consume();
  zzmatch(Number); consume();
  zzmatch(146); consume();
  zzmatch(Prompt); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number); consume();
  zzmatch(CloseParen); consume();
  zzmatch(146); consume();
  zzmatch(Help); consume();
  zzmatch(155); consume();
  zzmatch(156); consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number); consume();
  zzmatch(CloseParen); consume();
  {
    if ( (LA(1)==146) && (LA(2)==FLAGS) ) {
      zzmatch(146); consume();
      zzmatch(FLAGS); consume();
      zzmatch(155); consume();
      flagsField();
      {
        while ( (LA(1)==157) ) {
          zzmatch(157); consume();
          flagsField();
        }
      }
    }
    else {
      if ( (setwd32[LA(1)]&0x80) && (setwd33[LA(2)]&0x1)
 ) {
      }
      else {FAIL(2,err145,err146,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  {
    if ( (LA(1)==146) ) {
      zzmatch(146); consume();
      zzmatch(Key); consume();
      zzmatch(155); consume();
      zzmatch(Number); consume();
    }
    else {
      if ( (LA(1)==151) ) {
      }
      else {FAIL(1,err147,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(151); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd33, 0x2);
}

void
EfiVfrParser::vfrStatementExpression(UINT32 RootLevel,UINT32 ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  if ( RootLevel == 0) {mCIfrOpHdrIndex ++; if (mCIfrOpHdrIndex >= MAX_IFR_EXPRESSION_DEPTH) _PCATCH (VFR_RETURN_INVALID_PARAMETER, 0, "The depth of expression exceeds the max supported level 8!"); _CLEAR_SAVED_OPHDR ();}
  andTerm(  RootLevel,  ExpOpCount );
  {
    while ( (LA(1)==OR) ) {
      zzmatch(OR);
      L = (ANTLRTokenPtr)LT(1);
 consume();
      andTerm(  RootLevel,  ExpOpCount );
      ExpOpCount++; CIfrOr OObj(L->getLine());
    }
  }
  
  //
  // Extend OpCode Scope only for the root expression.
  //
  if ( ExpOpCount > 1 &&  RootLevel == 0) {
    if (_SET_SAVED_OPHDR_SCOPE()) {
      CIfrEnd EObj;
      if (mCIfrOpHdrLineNo[mCIfrOpHdrIndex] != 0) {
        EObj.SetLineNo (mCIfrOpHdrLineNo[mCIfrOpHdrIndex]);
      }
    }
  }
  
  if ( RootLevel == 0) {
    mCIfrOpHdrIndex --;
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd33, 0x4);
}

void
EfiVfrParser::vfrStatementExpressionSub(UINT32 RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  andTerm(  RootLevel,  ExpOpCount );
  {
    while ( (LA(1)==OR) ) {
      zzmatch(OR);
      L = (ANTLRTokenPtr)LT(1);
 consume();
      andTerm(  RootLevel,  ExpOpCount );
      ExpOpCount++; CIfrOr OObj(L->getLine());
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd33, 0x8);
}

void
EfiVfrParser::andTerm(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  bitwiseorTerm(  RootLevel,  ExpOpCount );
  {
    while ( (LA(1)==AND)
 ) {
      zzmatch(AND);
      L = (ANTLRTokenPtr)LT(1);
 consume();
      bitwiseorTerm(  RootLevel,  ExpOpCount );
      ExpOpCount++; CIfrAnd AObj(L->getLine());
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd33, 0x10);
}

void
EfiVfrParser::bitwiseorTerm(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  bitwiseandTerm(  RootLevel,  ExpOpCount );
  {
    while ( (LA(1)==157) ) {
      zzmatch(157);
      L = (ANTLRTokenPtr)LT(1);
 consume();
      bitwiseandTerm(  RootLevel,  ExpOpCount );
      ExpOpCount++; CIfrBitWiseOr BWOObj(L->getLine());
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd33, 0x20);
}

void
EfiVfrParser::bitwiseandTerm(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  equalTerm(  RootLevel,  ExpOpCount );
  {
    while ( (LA(1)==221) ) {
      zzmatch(221);
      L = (ANTLRTokenPtr)LT(1);
 consume();
      equalTerm(  RootLevel,  ExpOpCount );
      ExpOpCount++; CIfrBitWiseAnd BWAObj(L->getLine());
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd33, 0x40);
}

void
EfiVfrParser::equalTerm(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L1=NULL, L2=NULL;
  compareTerm(  RootLevel,  ExpOpCount );
  {
    for (;;) {
      if ( !((setwd33[LA(1)]&0x80))) break;
      if ( (LA(1)==222) ) {
        {
          zzmatch(222);
          L1 = (ANTLRTokenPtr)LT(1);
 consume();
          compareTerm(  RootLevel,  ExpOpCount );
          ExpOpCount++; CIfrEqual EObj(L1->getLine());
        }
      }
      else {
        if ( (LA(1)==223)
 ) {
          {
            zzmatch(223);
            L2 = (ANTLRTokenPtr)LT(1);
 consume();
            compareTerm(  RootLevel,  ExpOpCount );
            ExpOpCount++; CIfrNotEqual NEObj(L2->getLine());
          }
        }
        else break; /* MR6 code for exiting loop "for sure" */
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd34, 0x1);
}

void
EfiVfrParser::compareTerm(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L1=NULL, L2=NULL, L3=NULL, L4=NULL;
  shiftTerm(  RootLevel,  ExpOpCount );
  {
    for (;;) {
      if ( !((setwd34[LA(1)]&0x2))) break;
      if ( (LA(1)==224) ) {
        {
          zzmatch(224);
          L1 = (ANTLRTokenPtr)LT(1);
 consume();
          shiftTerm(  RootLevel,  ExpOpCount );
          ExpOpCount++; CIfrLessThan LTObj(L1->getLine());
        }
      }
      else {
        if ( (LA(1)==225) ) {
          {
            zzmatch(225);
            L2 = (ANTLRTokenPtr)LT(1);
 consume();
            shiftTerm(  RootLevel,  ExpOpCount );
            ExpOpCount++; CIfrLessEqual LEObj(L2->getLine());
          }
        }
        else {
          if ( (LA(1)==226) ) {
            {
              zzmatch(226);
              L3 = (ANTLRTokenPtr)LT(1);
 consume();
              shiftTerm(  RootLevel,  ExpOpCount );
              ExpOpCount++; CIfrGreaterThan GTObj(L3->getLine());
            }
          }
          else {
            if ( (LA(1)==227)
 ) {
              {
                zzmatch(227);
                L4 = (ANTLRTokenPtr)LT(1);
 consume();
                shiftTerm(  RootLevel,  ExpOpCount );
                ExpOpCount++; CIfrGreaterEqual GEObj(L4->getLine());
              }
            }
            else break; /* MR6 code for exiting loop "for sure" */
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd34, 0x4);
}

void
EfiVfrParser::shiftTerm(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L1=NULL, L2=NULL;
  addMinusTerm(  RootLevel,  ExpOpCount );
  {
    for (;;) {
      if ( !((setwd34[LA(1)]&0x8))) break;
      if ( (LA(1)==228) ) {
        {
          zzmatch(228);
          L1 = (ANTLRTokenPtr)LT(1);
 consume();
          addMinusTerm(  RootLevel,  ExpOpCount );
          ExpOpCount++; CIfrShiftLeft SLObj(L1->getLine());
        }
      }
      else {
        if ( (LA(1)==229) ) {
          {
            zzmatch(229);
            L2 = (ANTLRTokenPtr)LT(1);
 consume();
            addMinusTerm(  RootLevel,  ExpOpCount );
            ExpOpCount++; CIfrShiftRight SRObj(L2->getLine());
          }
        }
        else break; /* MR6 code for exiting loop "for sure" */
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd34, 0x10);
}

void
EfiVfrParser::addMinusTerm(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L1=NULL, L2=NULL;
  multdivmodTerm(  RootLevel,  ExpOpCount );
  {
    for (;;) {
      if ( !((setwd34[LA(1)]&0x20))) break;
      if ( (LA(1)==230)
 ) {
        {
          zzmatch(230);
          L1 = (ANTLRTokenPtr)LT(1);
 consume();
          multdivmodTerm(  RootLevel,  ExpOpCount );
          ExpOpCount++; CIfrAdd AObj(L1->getLine());
        }
      }
      else {
        if ( (LA(1)==231) ) {
          {
            zzmatch(231);
            L2 = (ANTLRTokenPtr)LT(1);
 consume();
            multdivmodTerm(  RootLevel,  ExpOpCount );
            ExpOpCount++; CIfrSubtract SObj(L2->getLine());
          }
        }
        else break; /* MR6 code for exiting loop "for sure" */
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd34, 0x40);
}

void
EfiVfrParser::multdivmodTerm(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L1=NULL, L2=NULL, L3=NULL;
  castTerm(  RootLevel,  ExpOpCount );
  {
    for (;;) {
      if ( !((setwd34[LA(1)]&0x80))) break;
      if ( (LA(1)==232) ) {
        {
          zzmatch(232);
          L1 = (ANTLRTokenPtr)LT(1);
 consume();
          castTerm(  RootLevel,  ExpOpCount );
          ExpOpCount++; CIfrMultiply MObj(L1->getLine());
        }
      }
      else {
        if ( (LA(1)==165) ) {
          {
            zzmatch(165);
            L2 = (ANTLRTokenPtr)LT(1);
 consume();
            castTerm(  RootLevel,  ExpOpCount );
            ExpOpCount++; CIfrDivide DObj(L2->getLine());
          }
        }
        else {
          if ( (LA(1)==233)
 ) {
            {
              zzmatch(233);
              L3 = (ANTLRTokenPtr)LT(1);
 consume();
              castTerm(  RootLevel,  ExpOpCount );
              ExpOpCount++; CIfrModulo MObj(L3->getLine());
            }
          }
          else break; /* MR6 code for exiting loop "for sure" */
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd35, 0x1);
}

void
EfiVfrParser::castTerm(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  UINT8 CastType = 0xFF;
  {
    while ( (LA(1)==OpenParen) && (setwd35[LA(2)]&0x2) ) {
      zzmatch(OpenParen);
      L = (ANTLRTokenPtr)LT(1);
 consume();
      {
        if ( (LA(1)==Boolean) ) {
          zzmatch(Boolean);
          CastType = 0;
 consume();
        }
        else {
          if ( (LA(1)==Uint64) ) {
            zzmatch(Uint64);
            CastType = 1;
 consume();
          }
          else {
            if ( (LA(1)==Uint32)
 ) {
              zzmatch(Uint32);
              CastType = 1;
 consume();
            }
            else {
              if ( (LA(1)==Uint16) ) {
                zzmatch(Uint16);
                CastType = 1;
 consume();
              }
              else {
                if ( (LA(1)==Uint8) ) {
                  zzmatch(Uint8);
                  CastType = 1;
 consume();
                }
                else {FAIL(1,err148,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
              }
            }
          }
        }
      }
      zzmatch(CloseParen); consume();
    }
  }
  atomTerm(  RootLevel,  ExpOpCount );
  
  switch (CastType) {
    case 0: { CIfrToBoolean TBObj(L->getLine());  ExpOpCount++; } break;
    case 1: { CIfrToUint TUObj(L->getLine());  ExpOpCount++; } break;
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd35, 0x4);
}

void
EfiVfrParser::atomTerm(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  if ( (LA(1)==Catenate) ) {
    vfrExpressionCatenate(  RootLevel,  ExpOpCount );
  }
  else {
    if ( (LA(1)==Match) ) {
      vfrExpressionMatch(  RootLevel,  ExpOpCount );
    }
    else {
      if ( (LA(1)==OpenParen)
 ) {
        vfrExpressionParen(  RootLevel,  ExpOpCount );
      }
      else {
        if ( (setwd35[LA(1)]&0x8) ) {
          vfrExpressionBuildInFunction(  RootLevel,  ExpOpCount );
        }
        else {
          if ( (setwd35[LA(1)]&0x10) ) {
            vfrExpressionConstant(  RootLevel,  ExpOpCount );
          }
          else {
            if ( (setwd35[LA(1)]&0x20) ) {
              vfrExpressionUnaryOp(  RootLevel,  ExpOpCount );
            }
            else {
              if ( (setwd35[LA(1)]&0x40) ) {
                vfrExpressionTernaryOp(  RootLevel,  ExpOpCount );
              }
              else {
                if ( (LA(1)==Map)
 ) {
                  vfrExpressionMap(  RootLevel,  ExpOpCount );
                }
                else {
                  if ( (LA(1)==NOT) ) {
                    {
                      zzmatch(NOT);
                      L = (ANTLRTokenPtr)LT(1);
 consume();
                      atomTerm(  RootLevel,  ExpOpCount );
                      { CIfrNot NObj(L->getLine());  ExpOpCount++; }
                    }
                  }
                  else {FAIL(1,err149,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
                }
              }
            }
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd35, 0x80);
}

void
EfiVfrParser::vfrExpressionCatenate(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  zzmatch(Catenate);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(146); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(CloseParen);
  { CIfrCatenate CObj(L->getLine());  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd36, 0x1);
}

void
EfiVfrParser::vfrExpressionMatch(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  zzmatch(Match);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(146); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(CloseParen);
  { CIfrMatch MObj(L->getLine());  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd36, 0x2);
}

void
EfiVfrParser::vfrExpressionParen(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  zzmatch(OpenParen); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(CloseParen); consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd36, 0x4);
}

void
EfiVfrParser::vfrExpressionBuildInFunction(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  if ( (LA(1)==Dup) ) {
    dupExp(  RootLevel,  ExpOpCount );
  }
  else {
    if ( (LA(1)==VarEqVal) ) {
      vareqvalExp(  RootLevel,  ExpOpCount );
    }
    else {
      if ( (LA(1)==IdEqVal) ) {
        ideqvalExp(  RootLevel,  ExpOpCount );
      }
      else {
        if ( (LA(1)==IdEqId)
 ) {
          ideqidExp(  RootLevel,  ExpOpCount );
        }
        else {
          if ( (LA(1)==IdEqValList) ) {
            ideqvallistExp(  RootLevel,  ExpOpCount );
          }
          else {
            if ( (LA(1)==QuestionRef) ) {
              questionref13Exp(  RootLevel,  ExpOpCount );
            }
            else {
              if ( (LA(1)==RuleRef) ) {
                rulerefExp(  RootLevel,  ExpOpCount );
              }
              else {
                if ( (LA(1)==StringRef) ) {
                  stringref1Exp(  RootLevel,  ExpOpCount );
                }
                else {
                  if ( (LA(1)==PushThis)
 ) {
                    pushthisExp(  RootLevel,  ExpOpCount );
                  }
                  else {
                    if ( (LA(1)==Security) ) {
                      securityExp(  RootLevel,  ExpOpCount );
                    }
                    else {
                      if ( (LA(1)==Get) ) {
                        getExp(  RootLevel,  ExpOpCount );
                      }
                      else {FAIL(1,err150,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd36, 0x8);
}

void
EfiVfrParser::dupExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  zzmatch(Dup);
  L = (ANTLRTokenPtr)LT(1);

  { CIfrDup DObj(L->getLine()); _SAVE_OPHDR_COND(DObj, ( ExpOpCount == 0), L->getLine());  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd36, 0x10);
}

void
EfiVfrParser::vareqvalExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, VK=NULL, VN=NULL, V1=NULL, V2=NULL, V3=NULL, V4=NULL, V5=NULL;
  
  EFI_QUESTION_ID QId;
  UINT32          Mask;
  UINT16          ConstVal;
  CHAR8           *VarIdStr;
  UINT32          LineNo;
  EFI_VFR_VARSTORE_TYPE VarStoreType = EFI_VFR_VARSTORE_INVALID;
  EFI_VFR_RETURN_CODE   VfrReturnCode = VFR_RETURN_SUCCESS;
  zzmatch(VarEqVal);
  L = (ANTLRTokenPtr)LT(1);

  
  if (!mCompatibleMode) {
    _PCATCH (VFR_RETURN_UNSUPPORTED, L);
  }
 consume();
  zzmatch(Var);
  VK = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  zzmatch(Number);
  VN = (ANTLRTokenPtr)LT(1);

  
  VarIdStr = NULL; _STRCAT(&VarIdStr, VK->getText()); _STRCAT(&VarIdStr, VN->getText());
  VfrReturnCode = mCVfrDataStorage.GetVarStoreType (VarIdStr, VarStoreType);
  if (VfrReturnCode == VFR_RETURN_UNDEFINED) {
    _PCATCH (mCVfrDataStorage.DeclareEfiVarStore (
    VarIdStr,
    &mFormsetGuid,
    _STOSID(VN->getText()),
    0x2,   //default type is UINT16
    FALSE
    ), VN);
  } else {
    _PCATCH (VfrReturnCode, VN);
  }
  mCVfrQuestionDB.GetQuestionId (NULL, VarIdStr, QId, Mask);
  LineNo = GET_LINENO(VN);
 consume();
  zzmatch(CloseParen); consume();
  {
    if ( (LA(1)==222) ) {
      {
        zzmatch(222); consume();
        zzmatch(Number);
        V1 = (ANTLRTokenPtr)LT(1);

        ConstVal = _STOU16(V1->getText());
 consume();
        
        if (Mask == 0) {
          CIfrEqIdVal EIVObj (L->getLine());
          _SAVE_OPHDR_COND (EIVObj, ( ExpOpCount == 0), L->getLine());
          EIVObj.SetQuestionId (QId, VarIdStr, LineNo);
          EIVObj.SetValue (ConstVal);
          ExpOpCount++;
        } else {
          IdEqValDoSpecial ( ExpOpCount, L->getLine(), QId, VarIdStr, Mask, ConstVal, EQUAL);
        }
      }
    }
    else {
      if ( (LA(1)==225) ) {
        {
          zzmatch(225); consume();
          zzmatch(Number);
          V2 = (ANTLRTokenPtr)LT(1);

          ConstVal = _STOU16(V2->getText());
 consume();
          IdEqValDoSpecial ( ExpOpCount, L->getLine(), QId, VarIdStr, Mask, ConstVal, LESS_EQUAL);
        }
      }
      else {
        if ( (LA(1)==224)
 ) {
          {
            zzmatch(224); consume();
            zzmatch(Number);
            V3 = (ANTLRTokenPtr)LT(1);

            ConstVal = _STOU16(V3->getText());
 consume();
            IdEqValDoSpecial ( ExpOpCount, L->getLine(), QId, VarIdStr, Mask, ConstVal, LESS_THAN);
          }
        }
        else {
          if ( (LA(1)==227) ) {
            {
              zzmatch(227); consume();
              zzmatch(Number);
              V4 = (ANTLRTokenPtr)LT(1);

              ConstVal = _STOU16(V4->getText());
 consume();
              IdEqValDoSpecial ( ExpOpCount, L->getLine(), QId, VarIdStr, Mask, ConstVal, GREATER_EQUAL);
            }
          }
          else {
            if ( (LA(1)==226) ) {
              {
                zzmatch(226); consume();
                zzmatch(Number);
                V5 = (ANTLRTokenPtr)LT(1);

                ConstVal = _STOU16(V5->getText());
 consume();
                IdEqValDoSpecial ( ExpOpCount, L->getLine(), QId, VarIdStr, Mask, ConstVal, GREATER_THAN);
              }
            }
            else {FAIL(1,err151,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd36, 0x20);
}

void
EfiVfrParser::ideqvalExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, V1=NULL, V2=NULL, V3=NULL, V4=NULL, V5=NULL;
  
  EFI_QUESTION_ID QId;
  UINT32          Mask;
  UINT16          ConstVal;
  CHAR8           *VarIdStr;
  UINT32          LineNo;
  zzmatch(IdEqVal);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  vfrQuestionDataFieldName( QId, Mask, VarIdStr, LineNo );
  {
    if ( (LA(1)==222) ) {
      {
        zzmatch(222); consume();
        zzmatch(Number);
        V1 = (ANTLRTokenPtr)LT(1);

        ConstVal = _STOU16(V1->getText());
 consume();
        
        if (Mask == 0) {
          CIfrEqIdVal EIVObj (L->getLine());
          _SAVE_OPHDR_COND (EIVObj, ( ExpOpCount == 0), L->getLine());
          EIVObj.SetQuestionId (QId, VarIdStr, LineNo);
          EIVObj.SetValue (ConstVal);
          ExpOpCount++;
        } else {
          IdEqValDoSpecial ( ExpOpCount, L->getLine(), QId, VarIdStr, Mask, ConstVal, EQUAL);
        }
      }
    }
    else {
      if ( (LA(1)==225) ) {
        {
          zzmatch(225); consume();
          zzmatch(Number);
          V2 = (ANTLRTokenPtr)LT(1);

          ConstVal = _STOU16(V2->getText());
 consume();
          IdEqValDoSpecial ( ExpOpCount, L->getLine(), QId, VarIdStr, Mask, ConstVal, LESS_EQUAL);
        }
      }
      else {
        if ( (LA(1)==224)
 ) {
          {
            zzmatch(224); consume();
            zzmatch(Number);
            V3 = (ANTLRTokenPtr)LT(1);

            ConstVal = _STOU16(V3->getText());
 consume();
            IdEqValDoSpecial ( ExpOpCount, L->getLine(), QId, VarIdStr, Mask, ConstVal, LESS_THAN);
          }
        }
        else {
          if ( (LA(1)==227) ) {
            {
              zzmatch(227); consume();
              zzmatch(Number);
              V4 = (ANTLRTokenPtr)LT(1);

              ConstVal = _STOU16(V4->getText());
 consume();
              IdEqValDoSpecial ( ExpOpCount, L->getLine(), QId, VarIdStr, Mask, ConstVal, GREATER_EQUAL);
            }
          }
          else {
            if ( (LA(1)==226) ) {
              {
                zzmatch(226); consume();
                zzmatch(Number);
                V5 = (ANTLRTokenPtr)LT(1);

                ConstVal = _STOU16(V5->getText());
 consume();
                IdEqValDoSpecial ( ExpOpCount, L->getLine(), QId, VarIdStr, Mask, ConstVal, GREATER_THAN);
              }
            }
            else {FAIL(1,err152,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd36, 0x40);
}

void
EfiVfrParser::ideqidExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  
  EFI_QUESTION_ID QId[2];
  UINT32          Mask[2];
  CHAR8           *VarIdStr[2];
  UINT32          LineNo[2];
  zzmatch(IdEqId);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  vfrQuestionDataFieldName( QId[0], Mask[0], VarIdStr[0], LineNo[0] );
  {
    if ( (LA(1)==222) ) {
      {
        zzmatch(222); consume();
        vfrQuestionDataFieldName( QId[1], Mask[1], VarIdStr[1], LineNo[1] );
        
        if (Mask[0] & Mask[1]) {
          IdEqIdDoSpecial ( ExpOpCount, L->getLine(), QId[0], VarIdStr[0], Mask[0], QId[1], VarIdStr[1], Mask[1], EQUAL);
        } else {
          CIfrEqIdId      EIIObj(L->getLine());
          _SAVE_OPHDR_COND (EIIObj, ( ExpOpCount == 0), L->getLine());
          EIIObj.SetQuestionId1 (QId[0], VarIdStr[0], LineNo[0]);
          EIIObj.SetQuestionId2 (QId[1], VarIdStr[1], LineNo[1]);
          ExpOpCount++;
        }
      }
    }
    else {
      if ( (LA(1)==225) ) {
        {
          zzmatch(225); consume();
          vfrQuestionDataFieldName( QId[1], Mask[1], VarIdStr[1], LineNo[1] );
          IdEqIdDoSpecial ( ExpOpCount, L->getLine(), QId[0], VarIdStr[0], Mask[0], QId[1], VarIdStr[1], Mask[1], LESS_EQUAL);
        }
      }
      else {
        if ( (LA(1)==224)
 ) {
          {
            zzmatch(224); consume();
            vfrQuestionDataFieldName( QId[1], Mask[1], VarIdStr[1], LineNo[1] );
            IdEqIdDoSpecial ( ExpOpCount, L->getLine(), QId[0], VarIdStr[0], Mask[0], QId[1], VarIdStr[1], Mask[1], LESS_THAN);
          }
        }
        else {
          if ( (LA(1)==227) ) {
            {
              zzmatch(227); consume();
              vfrQuestionDataFieldName( QId[1], Mask[1], VarIdStr[1], LineNo[1] );
              IdEqIdDoSpecial ( ExpOpCount, L->getLine(), QId[0], VarIdStr[0], Mask[0], QId[1], VarIdStr[1], Mask[1], GREATER_EQUAL);
            }
          }
          else {
            if ( (LA(1)==226) ) {
              {
                zzmatch(226); consume();
                vfrQuestionDataFieldName( QId[1], Mask[1], VarIdStr[1], LineNo[1] );
                IdEqIdDoSpecial ( ExpOpCount, L->getLine(), QId[0], VarIdStr[0], Mask[0], QId[1], VarIdStr[1], Mask[1], GREATER_THAN);
              }
            }
            else {FAIL(1,err153,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd36, 0x80);
}

void
EfiVfrParser::ideqvallistExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, V=NULL;
  
  UINT16          ListLen = 0;
  EFI_QUESTION_ID QId;
  UINT32          Mask;
  UINT16          ValueList[EFI_IFR_MAX_LENGTH] = {0,};
  CHAR8           *VarIdStr;
  UINT32          LineNo;
  zzmatch(IdEqValList);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  vfrQuestionDataFieldName( QId, Mask, VarIdStr, LineNo );
  zzmatch(222); consume();
  {
    int zzcnt=1;
    do {
      zzmatch(Number);
      V = (ANTLRTokenPtr)LT(1);

      ValueList[ListLen] = _STOU16(V->getText()); ListLen++;
 consume();
    } while ( (LA(1)==Number) );
  }
  
  if (Mask != 0) {
    IdEqListDoSpecial ( ExpOpCount, LineNo, QId, VarIdStr, Mask, ListLen, ValueList);
  } else {
    UINT16       Index;
    CIfrEqIdList EILObj(L->getLine());
    if (QId != EFI_QUESTION_ID_INVALID) {
      EILObj.SetQuestionId (QId, VarIdStr, LineNo);
    }
    EILObj.SetListLength (ListLen);
    for (Index = 0; Index < ListLen; Index++) {
      EILObj.SetValueList (Index, ValueList[Index]);
    }
    
    EILObj.UpdateIfrBuffer();
    _SAVE_OPHDR_COND (EILObj, ( ExpOpCount == 0), L->getLine());                                                            
    
    if (QId == EFI_QUESTION_ID_INVALID) {
      EILObj.SetQuestionId (QId, VarIdStr, LineNo);
    }
    ExpOpCount++;
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd37, 0x1);
}

void
EfiVfrParser::questionref13Exp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, S=NULL, QN=NULL, ID=NULL;
  
  UINT8           Type = 0x1;
  EFI_STRING_ID   DevPath = EFI_STRING_ID_INVALID;
  EFI_GUID        Guid = {0,};
  EFI_QUESTION_ID QId = EFI_QUESTION_ID_INVALID;
  UINT32          BitMask;
  CHAR8           *QName = NULL;
  UINT32          LineNo = 0;
  zzmatch(QuestionRef);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  {
    if ( (setwd37[LA(1)]&0x2) ) {
      {
        Type = 0x3;
        {
          if ( (LA(1)==Path)
 ) {
            zzmatch(Path); consume();
            zzmatch(155); consume();
            zzmatch(156); consume();
            zzmatch(OpenParen); consume();
            zzmatch(Number);
            S = (ANTLRTokenPtr)LT(1);
 consume();
            zzmatch(CloseParen);
            Type = 0x4; DevPath = _STOSID(S->getText());
 consume();
          }
          else {
            if ( (setwd37[LA(1)]&0x4) ) {
            }
            else {FAIL(1,err154,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
          }
        }
        {
          if ( (LA(1)==Uuid) ) {
            zzmatch(Uuid); consume();
            zzmatch(155); consume();
            guidDefinition( Guid );
            Type = 0x5;
          }
          else {
            if ( (setwd37[LA(1)]&0x8) ) {
            }
            else {FAIL(1,err155,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
          }
        }
      }
    }
    else {
      if ( (LA(1)==OpenParen) ) {
        {
          zzmatch(OpenParen); consume();
          {
            if ( (LA(1)==StringIdentifier)
 ) {
              zzmatch(StringIdentifier);
              QN = (ANTLRTokenPtr)LT(1);

              
              QName  = QN->getText();
              LineNo = QN->getLine();
              mCVfrQuestionDB.GetQuestionId (QN->getText(), NULL, QId, BitMask);
 consume();
            }
            else {
              if ( (LA(1)==Number) ) {
                zzmatch(Number);
                ID = (ANTLRTokenPtr)LT(1);

                QId = _STOQID(ID->getText());
 consume();
              }
              else {FAIL(1,err156,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
            }
          }
          zzmatch(CloseParen); consume();
        }
      }
      else {FAIL(1,err157,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  
  switch (Type) {
    case 0x1: {CIfrQuestionRef1 QR1Obj(L->getLine()); _SAVE_OPHDR_COND (QR1Obj, ( ExpOpCount == 0), L->getLine()); QR1Obj.SetQuestionId (QId, QName, LineNo); break;}
    case 0x3: {CIfrQuestionRef3 QR3Obj(L->getLine()); _SAVE_OPHDR_COND (QR3Obj, ( ExpOpCount == 0), L->getLine()); break;}
    case 0x4: {CIfrQuestionRef3_2 QR3_2Obj(L->getLine()); _SAVE_OPHDR_COND (QR3_2Obj, ( ExpOpCount == 0), L->getLine()); QR3_2Obj.SetDevicePath (DevPath); break;}
    case 0x5: {CIfrQuestionRef3_3 QR3_3Obj(L->getLine()); _SAVE_OPHDR_COND (QR3_3Obj, ( ExpOpCount == 0), L->getLine()); QR3_3Obj.SetDevicePath (DevPath); QR3_3Obj.SetGuid (&Guid); break;}
  }
  ExpOpCount++;
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd37, 0x10);
}

void
EfiVfrParser::rulerefExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, RN=NULL;
  zzmatch(RuleRef);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  zzmatch(StringIdentifier);
  RN = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(CloseParen);
  { CIfrRuleRef RRObj(L->getLine()); _SAVE_OPHDR_COND (RRObj, ( ExpOpCount == 0), L->getLine()); RRObj.SetRuleId (mCVfrRulesDB.GetRuleId (RN->getText())); }  ExpOpCount++;
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd37, 0x20);
}

void
EfiVfrParser::stringref1Exp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, S=NULL, I=NULL;
  
  EFI_STRING_ID RefStringId = EFI_STRING_ID_INVALID;
  zzmatch(StringRef);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  {
    if ( (LA(1)==156) ) {
      zzmatch(156); consume();
      zzmatch(OpenParen); consume();
      zzmatch(Number);
      S = (ANTLRTokenPtr)LT(1);

      RefStringId = _STOSID(S->getText());
 consume();
      zzmatch(CloseParen); consume();
    }
    else {
      if ( (LA(1)==Number) ) {
        zzmatch(Number);
        I = (ANTLRTokenPtr)LT(1);

        RefStringId = _STOSID(I->getText());
 consume();
      }
      else {FAIL(1,err158,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(CloseParen);
  { CIfrStringRef1 SR1Obj(L->getLine()); _SAVE_OPHDR_COND (SR1Obj, ( ExpOpCount == 0), L->getLine()); SR1Obj.SetStringId (RefStringId);  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd37, 0x40);
}

void
EfiVfrParser::pushthisExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  zzmatch(PushThis);
  L = (ANTLRTokenPtr)LT(1);

  { CIfrThis TObj(L->getLine()); _SAVE_OPHDR_COND (TObj, ( ExpOpCount == 0), L->getLine());  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd37, 0x80);
}

void
EfiVfrParser::securityExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  
  EFI_GUID Guid;
  zzmatch(Security);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  guidDefinition( Guid );
  zzmatch(CloseParen);
  { CIfrSecurity SObj(L->getLine()); _SAVE_OPHDR_COND (SObj, ( ExpOpCount == 0), L->getLine()); SObj.SetPermissions (&Guid); }  ExpOpCount++;
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd38, 0x1);
}

void
EfiVfrParser::numericVarStoreType(UINT8 & VarType)
{
  zzRULE;
  if ( (LA(1)==175) ) {
    zzmatch(175);
    VarType = EFI_IFR_NUMERIC_SIZE_1;
 consume();
  }
  else {
    if ( (LA(1)==176)
 ) {
      zzmatch(176);
      VarType = EFI_IFR_NUMERIC_SIZE_2;
 consume();
    }
    else {
      if ( (LA(1)==177) ) {
        zzmatch(177);
        VarType = EFI_IFR_NUMERIC_SIZE_4;
 consume();
      }
      else {
        if ( (LA(1)==178) ) {
          zzmatch(178);
          VarType = EFI_IFR_NUMERIC_SIZE_8;
 consume();
        }
        else {FAIL(1,err159,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd38, 0x2);
}

void
EfiVfrParser::getExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  
  EFI_VARSTORE_INFO Info;
  CHAR8             *VarIdStr = NULL;
  EFI_QUESTION_ID   QId = EFI_QUESTION_ID_INVALID;
  UINT32            Mask = 0;
  EFI_QUESION_TYPE  QType = QUESTION_NORMAL;
  UINT8             VarType = EFI_IFR_TYPE_UNDEFINED;
  UINT32            VarSize = 0;
  Info.mVarStoreId = 0;
  zzmatch(Get);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  vfrStorageVarId( Info, VarIdStr, FALSE );
  {
    if ( (LA(1)==157) ) {
      zzmatch(157); consume();
      zzmatch(FLAGS); consume();
      zzmatch(155); consume();
      numericVarStoreType( VarType );
    }
    else {
      if ( (LA(1)==CloseParen) ) {
      }
      else {FAIL(1,err160,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(CloseParen);
  
  {
    if (Info.mVarStoreId == 0) {
      // support Date/Time question
      mCVfrQuestionDB.GetQuestionId (NULL, VarIdStr, QId, Mask, &QType);
      if (QId == EFI_QUESTION_ID_INVALID || Mask == 0 || QType == QUESTION_NORMAL) {
        _PCATCH(VFR_RETURN_UNSUPPORTED, L->getLine(), "Get/Set opcode can't get the enough varstore information");
      }
      if (QType == QUESTION_DATE) {
        Info.mVarType = EFI_IFR_TYPE_DATE;
      } else if (QType == QUESTION_TIME) {
        Info.mVarType = EFI_IFR_TYPE_TIME;
      }
      switch (Mask) {
        case DATE_YEAR_BITMASK:
        Info.mInfo.mVarOffset = 0;
        break;
        case DATE_DAY_BITMASK:
        Info.mInfo.mVarOffset = 3;
        break;
        case TIME_HOUR_BITMASK:
        Info.mInfo.mVarOffset = 0;
        break;
        case TIME_MINUTE_BITMASK:
        Info.mInfo.mVarOffset = 1;
        break;
        case TIME_SECOND_BITMASK:
        Info.mInfo.mVarOffset = 2;
        break;
        default:
        _PCATCH(VFR_RETURN_UNSUPPORTED, L->getLine(), "Get/Set opcode can't get the enough varstore information");
        break;
      }
    } else {
      if ((mCVfrDataStorage.GetVarStoreType(Info.mVarStoreId) == EFI_VFR_VARSTORE_NAME) && (VarType == EFI_IFR_TYPE_UNDEFINED)) {
        _PCATCH(VFR_RETURN_UNSUPPORTED, L->getLine(), "Get/Set opcode don't support name string");
      }
      if (VarType != EFI_IFR_TYPE_UNDEFINED) {
        Info.mVarType = VarType;
        _PCATCH(gCVfrVarDataTypeDB.GetDataTypeSize (Info.mVarType, &VarSize), L->getLine(), "Get/Set opcode can't get var type size");
        Info.mVarTotalSize = VarSize;
      }
      _PCATCH(gCVfrVarDataTypeDB.GetDataTypeSize (Info.mVarType, &VarSize), L->getLine(), "Get/Set opcode can't get var type size");
      if (VarSize != Info.mVarTotalSize) {
        _PCATCH(VFR_RETURN_UNSUPPORTED, L->getLine(), "Get/Set opcode don't support data array");
      }
    }
    CIfrGet GObj(L->getLine()); 
    _SAVE_OPHDR_COND (GObj, ( ExpOpCount == 0), L->getLine()); 
    GObj.SetVarInfo (&Info); 
    delete VarIdStr; 
    ExpOpCount++;
  }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd38, 0x4);
}

void
EfiVfrParser::vfrExpressionConstant(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L1=NULL, L2=NULL, L3=NULL, L4=NULL, L5=NULL, L6=NULL, L7=NULL, V=NULL;
  if ( (LA(1)==True)
 ) {
    zzmatch(True);
    L1 = (ANTLRTokenPtr)LT(1);

    CIfrTrue TObj(L1->getLine()); _SAVE_OPHDR_COND (TObj, ( ExpOpCount == 0), L1->getLine());  ExpOpCount++;
 consume();
  }
  else {
    if ( (LA(1)==False) ) {
      zzmatch(False);
      L2 = (ANTLRTokenPtr)LT(1);

      CIfrFalse FObj(L2->getLine()); _SAVE_OPHDR_COND (FObj, ( ExpOpCount == 0), L2->getLine());  ExpOpCount++;
 consume();
    }
    else {
      if ( (LA(1)==One) ) {
        zzmatch(One);
        L3 = (ANTLRTokenPtr)LT(1);

        CIfrOne OObj(L3->getLine()); _SAVE_OPHDR_COND (OObj, ( ExpOpCount == 0), L3->getLine());  ExpOpCount++;
 consume();
      }
      else {
        if ( (LA(1)==Ones) ) {
          zzmatch(Ones);
          L4 = (ANTLRTokenPtr)LT(1);

          CIfrOnes OObj(L4->getLine()); _SAVE_OPHDR_COND (OObj, ( ExpOpCount == 0), L4->getLine());  ExpOpCount++;
 consume();
        }
        else {
          if ( (LA(1)==Zero) ) {
            zzmatch(Zero);
            L5 = (ANTLRTokenPtr)LT(1);

            CIfrZero ZObj(L5->getLine()); _SAVE_OPHDR_COND (ZObj, ( ExpOpCount == 0), L5->getLine());  ExpOpCount++;
 consume();
          }
          else {
            if ( (LA(1)==Undefined)
 ) {
              zzmatch(Undefined);
              L6 = (ANTLRTokenPtr)LT(1);

              CIfrUndefined UObj(L6->getLine()); _SAVE_OPHDR_COND (UObj, ( ExpOpCount == 0), L6->getLine());  ExpOpCount++;
 consume();
            }
            else {
              if ( (LA(1)==Version) ) {
                zzmatch(Version);
                L7 = (ANTLRTokenPtr)LT(1);

                CIfrVersion VObj(L7->getLine()); _SAVE_OPHDR_COND (VObj, ( ExpOpCount == 0), L7->getLine());  ExpOpCount++;
 consume();
              }
              else {
                if ( (LA(1)==Number) ) {
                  zzmatch(Number);
                  V = (ANTLRTokenPtr)LT(1);

                  CIfrUint64 U64Obj(V->getLine()); U64Obj.SetValue (_STOU64(V->getText())); _SAVE_OPHDR_COND (U64Obj, ( ExpOpCount == 0), V->getLine());  ExpOpCount++;
 consume();
                }
                else {FAIL(1,err161,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
              }
            }
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd38, 0x8);
}

void
EfiVfrParser::vfrExpressionUnaryOp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  if ( (LA(1)==Length) ) {
    lengthExp(  RootLevel,  ExpOpCount );
  }
  else {
    if ( (LA(1)==BitWiseNot) ) {
      bitwisenotExp(  RootLevel,  ExpOpCount );
    }
    else {
      if ( (LA(1)==QuestionRefVal)
 ) {
        question2refExp(  RootLevel,  ExpOpCount );
      }
      else {
        if ( (LA(1)==StringRefVal) ) {
          stringref2Exp(  RootLevel,  ExpOpCount );
        }
        else {
          if ( (LA(1)==BoolVal) ) {
            toboolExp(  RootLevel,  ExpOpCount );
          }
          else {
            if ( (LA(1)==UnIntVal) ) {
              unintExp(  RootLevel,  ExpOpCount );
            }
            else {
              if ( (LA(1)==ToUpper) ) {
                toupperExp(  RootLevel,  ExpOpCount );
              }
              else {
                if ( (LA(1)==ToLower)
 ) {
                  tolwerExp(  RootLevel,  ExpOpCount );
                }
                else {
                  if ( (LA(1)==Set) ) {
                    setExp(  RootLevel,  ExpOpCount );
                  }
                  else {FAIL(1,err162,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
                }
              }
            }
          }
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd38, 0x10);
}

void
EfiVfrParser::lengthExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  zzmatch(Length);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(CloseParen);
  { CIfrLength LObj(L->getLine());  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd38, 0x20);
}

void
EfiVfrParser::bitwisenotExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  zzmatch(BitWiseNot);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(CloseParen);
  { CIfrBitWiseNot BWNObj(L->getLine());  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd38, 0x40);
}

void
EfiVfrParser::question2refExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  zzmatch(QuestionRefVal);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(CloseParen);
  { CIfrQuestionRef2 QR2Obj(L->getLine());  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd38, 0x80);
}

void
EfiVfrParser::stringref2Exp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  zzmatch(StringRefVal);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(CloseParen);
  { CIfrStringRef2 SR2Obj(L->getLine());  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd39, 0x1);
}

void
EfiVfrParser::toboolExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  zzmatch(BoolVal);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(CloseParen);
  { CIfrToBoolean TBObj(L->getLine());  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd39, 0x2);
}

void
EfiVfrParser::tostringExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, F=NULL;
  UINT8 Fmt = 0;
  zzmatch(StringVal);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  {
    if ( (LA(1)==Format) ) {
      zzmatch(Format); consume();
      zzmatch(155); consume();
      zzmatch(Number);
      F = (ANTLRTokenPtr)LT(1);
 consume();
      zzmatch(146);
      Fmt = _STOU8(F->getText());
 consume();
    }
    else {
      if ( (LA(1)==OpenParen) ) {
      }
      else {FAIL(1,err163,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(OpenParen); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(CloseParen);
  { CIfrToString TSObj(L->getLine()); TSObj.SetFormat (Fmt);  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd39, 0x4);
}

void
EfiVfrParser::unintExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  zzmatch(UnIntVal);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(CloseParen);
  { CIfrToUint TUObj(L->getLine());  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd39, 0x8);
}

void
EfiVfrParser::toupperExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  zzmatch(ToUpper);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(CloseParen);
  { CIfrToUpper TUObj(L->getLine());  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd39, 0x10);
}

void
EfiVfrParser::tolwerExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  zzmatch(ToLower);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(CloseParen);
  { CIfrToLower TLObj(L->getLine());  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd39, 0x20);
}

void
EfiVfrParser::setExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  
  EFI_VARSTORE_INFO Info;
  CHAR8             *VarIdStr = NULL;
  EFI_QUESTION_ID   QId = EFI_QUESTION_ID_INVALID;
  UINT32            Mask = 0;
  EFI_QUESION_TYPE  QType = QUESTION_NORMAL;
  UINT8             VarType = EFI_IFR_TYPE_UNDEFINED;
  UINT32            VarSize = 0;
  Info.mVarStoreId = 0;
  zzmatch(Set);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  vfrStorageVarId( Info, VarIdStr, FALSE );
  {
    if ( (LA(1)==157) ) {
      zzmatch(157); consume();
      zzmatch(FLAG); consume();
      zzmatch(155); consume();
      numericVarStoreType( VarType );
    }
    else {
      if ( (LA(1)==146)
 ) {
      }
      else {FAIL(1,err164,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  zzmatch(146); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(CloseParen);
  
  {
    if (Info.mVarStoreId == 0) {
      // support Date/Time question
      mCVfrQuestionDB.GetQuestionId (NULL, VarIdStr, QId, Mask, &QType);
      if (QId == EFI_QUESTION_ID_INVALID || Mask == 0 || QType == QUESTION_NORMAL) {
        _PCATCH(VFR_RETURN_UNSUPPORTED, L->getLine(), "Get/Set opcode can't get the enough varstore information");
      }
      if (QType == QUESTION_DATE) {
        Info.mVarType = EFI_IFR_TYPE_DATE;
      } else if (QType == QUESTION_TIME) {
        Info.mVarType = EFI_IFR_TYPE_TIME;
      }
      switch (Mask) {
        case DATE_YEAR_BITMASK:
        Info.mInfo.mVarOffset = 0;
        break;
        case DATE_DAY_BITMASK:
        Info.mInfo.mVarOffset = 3;
        break;
        case TIME_HOUR_BITMASK:
        Info.mInfo.mVarOffset = 0;
        break;
        case TIME_MINUTE_BITMASK:
        Info.mInfo.mVarOffset = 1;
        break;
        case TIME_SECOND_BITMASK:
        Info.mInfo.mVarOffset = 2;
        break;
        default:
        _PCATCH(VFR_RETURN_UNSUPPORTED, L->getLine(), "Get/Set opcode can't get the enough varstore information");
        break;
      }
    } else {
      if ((mCVfrDataStorage.GetVarStoreType(Info.mVarStoreId) == EFI_VFR_VARSTORE_NAME) && (VarType == EFI_IFR_TYPE_UNDEFINED)) {
        _PCATCH(VFR_RETURN_UNSUPPORTED, L->getLine(), "Get/Set opcode don't support name string");
      }
      if (VarType != EFI_IFR_TYPE_UNDEFINED) {
        Info.mVarType = VarType;
        _PCATCH(gCVfrVarDataTypeDB.GetDataTypeSize (Info.mVarType, &VarSize), L->getLine(), "Get/Set opcode can't get var type size");
        Info.mVarTotalSize = VarSize;
      }
      _PCATCH(gCVfrVarDataTypeDB.GetDataTypeSize (Info.mVarType, &VarSize), L->getLine(), "Get/Set opcode can't get var type size");
      if (VarSize != Info.mVarTotalSize) {
        _PCATCH(VFR_RETURN_UNSUPPORTED, L->getLine(), "Get/Set opcode don't support data array");
      }
    }
    CIfrSet TSObj(L->getLine()); 
    TSObj.SetVarInfo (&Info); 
    delete VarIdStr; 
    ExpOpCount++;
  }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd39, 0x40);
}

void
EfiVfrParser::vfrExpressionTernaryOp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  if ( (LA(1)==Cond) ) {
    conditionalExp(  RootLevel,  ExpOpCount );
  }
  else {
    if ( (LA(1)==Find) ) {
      findExp(  RootLevel,  ExpOpCount );
    }
    else {
      if ( (LA(1)==Mid) ) {
        midExp(  RootLevel,  ExpOpCount );
      }
      else {
        if ( (LA(1)==Tok) ) {
          tokenExp(  RootLevel,  ExpOpCount );
        }
        else {
          if ( (LA(1)==Span)
 ) {
            spanExp(  RootLevel,  ExpOpCount );
          }
          else {FAIL(1,err165,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
        }
      }
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd39, 0x80);
}

void
EfiVfrParser::conditionalExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  zzmatch(Cond);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(242); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(164); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(CloseParen);
  { CIfrConditional CObj(L->getLine());  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd40, 0x1);
}

void
EfiVfrParser::findExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  UINT8 Format;
  zzmatch(Find);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  findFormat( Format );
  {
    while ( (LA(1)==157) ) {
      zzmatch(157); consume();
      findFormat( Format );
    }
  }
  zzmatch(146); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(146); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(146); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(CloseParen);
  { CIfrFind FObj(L->getLine()); FObj.SetFormat (Format);  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd40, 0x2);
}

void
EfiVfrParser::findFormat(UINT8 & Format)
{
  zzRULE;
  if ( (LA(1)==243) ) {
    zzmatch(243);
    Format = 0x00;
 consume();
  }
  else {
    if ( (LA(1)==244) ) {
      zzmatch(244);
      Format = 0x01;
 consume();
    }
    else {FAIL(1,err166,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd40, 0x4);
}

void
EfiVfrParser::midExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  zzmatch(Mid);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(146); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(146); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(CloseParen);
  { CIfrMid MObj(L->getLine());  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd40, 0x8);
}

void
EfiVfrParser::tokenExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL;
  zzmatch(Tok);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(146); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(146); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(CloseParen);
  { CIfrToken TObj(L->getLine());  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd40, 0x10);
}

void
EfiVfrParser::spanExp(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr S=NULL;
  UINT8 Flags = 0;
  zzmatch(Span);
  S = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  zzmatch(FLAGS); consume();
  zzmatch(155); consume();
  spanFlags( Flags );
  {
    while ( (LA(1)==157) ) {
      zzmatch(157); consume();
      spanFlags( Flags );
    }
  }
  zzmatch(146); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(146); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(146); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(CloseParen);
  { CIfrSpan SObj(S->getLine()); SObj.SetFlags(Flags);  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd40, 0x20);
}

void
EfiVfrParser::vfrExpressionMap(UINT32 & RootLevel,UINT32 & ExpOpCount)
{
  zzRULE;
  ANTLRTokenPtr L=NULL, E=NULL;
  zzmatch(Map);
  L = (ANTLRTokenPtr)LT(1);
 consume();
  zzmatch(OpenParen); consume();
  vfrStatementExpressionSub(  RootLevel + 1,  ExpOpCount );
  zzmatch(164);
  { CIfrMap MObj(L->getLine()); }
 consume();
  {
    while ( (setwd40[LA(1)]&0x40)
 ) {
      vfrStatementExpression( 0 );
      zzmatch(146); consume();
      vfrStatementExpression( 0 );
      zzmatch(151); consume();
    }
  }
  zzmatch(CloseParen);
  E = (ANTLRTokenPtr)LT(1);

  { CIfrEnd EObj; EObj.SetLineNo(E->getLine());  ExpOpCount++; }
 consume();
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd40, 0x80);
}

void
EfiVfrParser::spanFlags(UINT8 & Flags)
{
  zzRULE;
  ANTLRTokenPtr N=NULL;
  if ( (LA(1)==Number) ) {
    zzmatch(Number);
    N = (ANTLRTokenPtr)LT(1);

    Flags |= _STOU8(N->getText());
 consume();
  }
  else {
    if ( (LA(1)==245) ) {
      zzmatch(245);
      Flags |= 0x00;
 consume();
    }
    else {
      if ( (LA(1)==246) ) {
        zzmatch(246);
        Flags |= 0x01;
 consume();
      }
      else {FAIL(1,err167,&zzMissSet,&zzMissText,&zzBadTok,&zzBadText,&zzErrk); goto fail;}
    }
  }
  return;
fail:
  syn(zzBadTok, (ANTLRChar *)"", zzMissSet, zzMissTok, zzErrk);
  resynch(setwd41, 0x1);
}

VOID
EfiVfrParser::_SAVE_OPHDR_COND (
IN CIfrOpHeader &OpHdr,
IN BOOLEAN      Cond,
IN UINT32       LineNo
)
{
  if (Cond == TRUE) {
    if (mCIfrOpHdr[mCIfrOpHdrIndex] != NULL) {
      return ;
    }
    mCIfrOpHdr[mCIfrOpHdrIndex]       = new CIfrOpHeader(OpHdr);
    mCIfrOpHdrLineNo[mCIfrOpHdrIndex] = LineNo;
  }
}

VOID
EfiVfrParser::_CLEAR_SAVED_OPHDR (
VOID
)
{
  mCIfrOpHdr[mCIfrOpHdrIndex]       = NULL;
  mCIfrOpHdrLineNo[mCIfrOpHdrIndex] = 0;
}

BOOLEAN
EfiVfrParser::_SET_SAVED_OPHDR_SCOPE (
VOID
)
{
  if (mCIfrOpHdr[mCIfrOpHdrIndex] != NULL) {
    mCIfrOpHdr[mCIfrOpHdrIndex]->SetScope (1);
    return TRUE;
  }
  
  //
  // IfrOpHdr is not set, FALSE is return.
  //
  return FALSE;
}

VOID
EfiVfrParser::_CRT_OP (
IN BOOLEAN Crt
)
{
  gCreateOp = Crt;
}

VOID
EfiVfrParser::_SAVE_CURRQEST_VARINFO (
IN EFI_VARSTORE_INFO &Info
)
{
  mCurrQestVarInfo = Info;
}

EFI_VARSTORE_INFO &
EfiVfrParser::_GET_CURRQEST_VARTINFO (
VOID
)
{
  return mCurrQestVarInfo;
}

UINT32
EfiVfrParser::_GET_CURRQEST_ARRAY_SIZE (
VOID
)
{
  UINT8 Size = 1;
  
  switch (mCurrQestVarInfo.mVarType) {
    case EFI_IFR_TYPE_NUM_SIZE_8:
    Size = 1;
    break;
    
    case EFI_IFR_TYPE_NUM_SIZE_16:
    Size = 2;
    break;
    
    case EFI_IFR_TYPE_NUM_SIZE_32:
    Size = 4;
    break;
    
    case EFI_IFR_TYPE_NUM_SIZE_64:
    Size = 8;
    break;
    
    default:
    break;
  }
  
  return (mCurrQestVarInfo.mVarTotalSize / Size);
}

UINT8
EfiVfrParser::_GET_CURRQEST_DATATYPE (
VOID
)
{
  return mCurrQestVarInfo.mVarType;
}

UINT32
EfiVfrParser::_GET_CURRQEST_VARSIZE (
VOID
)
{
  return mCurrQestVarInfo.mVarTotalSize;
}

VOID
EfiVfrParser::_PCATCH (
IN INTN                ReturnCode,
IN INTN                ExpectCode,
IN ANTLRTokenPtr       Tok,
IN CONST CHAR8         *ErrorMsg
)
{
  if (ReturnCode != ExpectCode) {
    mParserStatus++;
    gCVfrErrorHandle.PrintMsg (Tok->getLine(), Tok->getText(), "Error", ErrorMsg);
  }
}

VOID
EfiVfrParser::_PCATCH (
IN EFI_VFR_RETURN_CODE ReturnCode
)
{
  mParserStatus = mParserStatus + gCVfrErrorHandle.HandleError (ReturnCode);
}

VOID
EfiVfrParser::_PCATCH (
IN EFI_VFR_RETURN_CODE ReturnCode,
IN ANTLRTokenPtr       Tok
)
{
  mParserStatus = mParserStatus + gCVfrErrorHandle.HandleError (ReturnCode, Tok->getLine(), Tok->getText());
}

VOID
EfiVfrParser::_PCATCH (
IN EFI_VFR_RETURN_CODE ReturnCode,
IN UINT32              LineNum
)
{
  mParserStatus = mParserStatus + gCVfrErrorHandle.HandleError (ReturnCode, LineNum);
}

VOID
EfiVfrParser::_PCATCH (
IN EFI_VFR_RETURN_CODE ReturnCode,
IN UINT32              LineNum,
IN CONST CHAR8         *ErrorMsg
)
{
  mParserStatus = mParserStatus + gCVfrErrorHandle.HandleError (ReturnCode, LineNum, (CHAR8 *) ErrorMsg);
}

VOID
EfiVfrParser::syn (
ANTLRAbstractToken  *Tok,
ANTLRChar           *Egroup,
SetWordType         *Eset,
ANTLRTokenType      ETok,
INT32               Huh
)
{
  gCVfrErrorHandle.HandleError (VFR_RETURN_MISMATCHED, Tok->getLine(), Tok->getText());
  
  mParserStatus += 1;
}

CHAR8 *
EfiVfrParser::TrimHex (
IN  CHAR8   *Str,
OUT BOOLEAN *IsHex
)
{
  *IsHex = FALSE;
  
  while (*Str && *Str == ' ') {
    Str++;
  }
  while (*Str && *Str == '0') {
    Str++;
  }
  if (*Str && (*Str == 'x' || *Str == 'X')) {
    Str++;
    *IsHex = TRUE;
  }
  
  return Str;
}

CHAR8 *
EfiVfrParser::_U32TOS (
IN UINT32 Value
)
{
  CHAR8 *Str;
  Str = new CHAR8[20];
  sprintf (Str, "%d", Value);
  return Str;
}

UINT8
EfiVfrParser::_STOU8 (
IN CHAR8*Str
)
{
  BOOLEAN IsHex;
  UINT8   Value;
  CHAR8   c;
  
  Str = TrimHex (Str, &IsHex);
  for (Value = 0; (c = *Str) != '\0'; Str++) {
    //
    // BUG: does not handle overflow here
    //
    (IsHex == TRUE) ? (Value <<= 4) : (Value *= 10);
    
    if ((IsHex == TRUE) && (c >= 'a') && (c <= 'f')) {
      Value += (c - 'a' + 10);
    }
    if ((IsHex == TRUE) && (c >= 'A') && (c <= 'F')) {
      Value += (c - 'A' + 10);
    }
    if (c >= '0' && c <= '9') {
      Value += (c - '0');
    }
  }
  
  return Value;
}

UINT16
EfiVfrParser::_STOU16 (
IN CHAR8*Str
)
{
  BOOLEAN IsHex;
  UINT16  Value;
  CHAR8   c;
  
  Str = TrimHex (Str, &IsHex);
  for (Value = 0; (c = *Str) != '\0'; Str++) {
    //
    // BUG: does not handle overflow here
    //
    (IsHex == TRUE) ? (Value <<= 4) : (Value *= 10);
    
    if ((IsHex == TRUE) && (c >= 'a') && (c <= 'f')) {
      Value += (c - 'a' + 10);
    }
    if ((IsHex == TRUE) && (c >= 'A') && (c <= 'F')) {
      Value += (c - 'A' + 10);
    }
    if (c >= '0' && c <= '9') {
      Value += (c - '0');
    }
  }
  
  return Value;
}

UINT32
EfiVfrParser::_STOU32 (
IN CHAR8*Str
)
{
  BOOLEAN IsHex;
  UINT32  Value;
  CHAR8   c;
  
  Str = TrimHex (Str, &IsHex);
  for (Value = 0; (c = *Str) != '\0'; Str++) {
    //
    // BUG: does not handle overflow here
    //
    (IsHex == TRUE) ? (Value <<= 4) : (Value *= 10);
    
    if ((IsHex == TRUE) && (c >= 'a') && (c <= 'f')) {
      Value += (c - 'a' + 10);
    }
    if ((IsHex == TRUE) && (c >= 'A') && (c <= 'F')) {
      Value += (c - 'A' + 10);
    }
    if (c >= '0' && c <= '9') {
      Value += (c - '0');
    }
  }
  
  return Value;
}

UINT64
EfiVfrParser::_STOU64 (
IN CHAR8*Str
)
{
  BOOLEAN IsHex;
  UINT64  Value;
  CHAR8   c;
  
  Str = TrimHex (Str, &IsHex);
  for (Value = 0; (c = *Str) != '\0'; Str++) {
    //
    // BUG: does not handle overflow here
    //
    (IsHex == TRUE) ? (Value <<= 4) : (Value *= 10);
    
    if ((IsHex == TRUE) && (c >= 'a') && (c <= 'f')) {
      Value += (c - 'a' + 10);
    }
    if ((IsHex == TRUE) && (c >= 'A') && (c <= 'F')) {
      Value += (c - 'A' + 10);
    }
    if (c >= '0' && c <= '9') {
      Value += (c - '0');
    }
  }
  
  return Value;
}

EFI_HII_DATE
EfiVfrParser::_STOD (
IN CHAR8 *Year,
IN CHAR8 *Month,
IN CHAR8 *Day
)
{
  EFI_HII_DATE Date;
  
  Date.Year  = _STOU16 (Year);
  Date.Month = _STOU8 (Month);
  Date.Day   = _STOU8 (Day);
  
  return Date;
}

EFI_HII_TIME
EfiVfrParser::_STOT (
IN CHAR8 *Hour,
IN CHAR8 *Minute,
IN CHAR8 *Second
)
{
  EFI_HII_TIME Time;
  
  Time.Hour   = _STOU8 (Hour);
  Time.Minute = _STOU8 (Minute);
  Time.Second = _STOU8 (Second);
  
  return Time;
}

EFI_STRING_ID
EfiVfrParser::_STOSID (
IN CHAR8 *Str
)
{
  return (EFI_STRING_ID)_STOU16(Str);
}

EFI_FORM_ID
EfiVfrParser::_STOFID (
IN CHAR8 *Str
)
{
  return (EFI_FORM_ID)_STOU16(Str);
}

EFI_QUESTION_ID
EfiVfrParser::_STOQID (
IN CHAR8 *Str
)
{
  return (EFI_QUESTION_ID)_STOU16(Str);
}

VOID
EfiVfrParser::_STRCAT (
IN OUT CHAR8 **Dest,
IN CONST CHAR8 *Src
)
{
  CHAR8   *NewStr;
  UINT32 Len;
  
  if ((Dest == NULL) || (Src == NULL)) {
    return;
  }
  
  Len = (*Dest == NULL) ? 0 : strlen (*Dest);
  Len += strlen (Src);
  if ((NewStr = new CHAR8[Len + 1]) == NULL) {
    return;
  }
  NewStr[0] = '\0';
  if (*Dest != NULL) {
    strcpy (NewStr, *Dest);
    delete *Dest;
  }
  strcat (NewStr, Src);
  
  *Dest = NewStr;
}

//
// framework vfr to default declare varstore for each structure
//
VOID
EfiVfrParser::_DeclareDefaultFrameworkVarStore (
IN UINT32 LineNo
)
{
  SVfrVarStorageNode    *pNode;
  UINT32                TypeSize;
  BOOLEAN               FirstNode;
  CONST CHAR8           VarName[] = "Setup";
  
  FirstNode = TRUE;
  pNode = mCVfrDataStorage.GetBufferVarStoreList();
  if (pNode == NULL && gCVfrVarDataTypeDB.mFirstNewDataTypeName != NULL) {
    //
    // Create the default Buffer Var Store when no VarStore is defined.
    // its name should be "Setup"
    //
    gCVfrVarDataTypeDB.GetDataTypeSize (gCVfrVarDataTypeDB.mFirstNewDataTypeName, &TypeSize);
    CIfrVarStore      VSObj;
    VSObj.SetLineNo (LineNo);
    VSObj.SetVarStoreId (0x1); //the first and only one Buffer Var Store
    VSObj.SetSize ((UINT16) TypeSize);
    //VSObj.SetName (gCVfrVarDataTypeDB.mFirstNewDataTypeName);
    VSObj.SetName ((CHAR8 *) VarName);
    VSObj.SetGuid (&mFormsetGuid);
#ifdef VFREXP_DEBUG
    printf ("Create the default VarStoreName is %s\n", gCVfrVarDataTypeDB.mFirstNewDataTypeName);
#endif
  } else {
    for (; pNode != NULL; pNode = pNode->mNext) {
      //
      // create the default varstore opcode for not declared varstore
      // the first varstore name should be "Setup"
      //
      if (!pNode->mAssignedFlag) {
        CIfrVarStore      VSObj;
        VSObj.SetLineNo (LineNo);
        VSObj.SetVarStoreId (pNode->mVarStoreId);
        VSObj.SetSize ((UINT16) pNode->mStorageInfo.mDataType->mTotalSize);
        if (FirstNode) {
          VSObj.SetName ((CHAR8 *) VarName);
          FirstNode = FALSE;
        } else {
          VSObj.SetName (pNode->mVarStoreName);
        }
        VSObj.SetGuid (&pNode->mGuid);
#ifdef VFREXP_DEBUG
        printf ("undefined VarStoreName is %s and Id is 0x%x\n", pNode->mVarStoreName, pNode->mVarStoreId);
#endif
      }
    }
  }
  
  pNode = mCVfrDataStorage.GetEfiVarStoreList();
  for (; pNode != NULL; pNode = pNode->mNext) {
    //
    // create the default efi varstore opcode for not exist varstore
    //
    if (!pNode->mAssignedFlag) {
      CIfrVarStoreEfi VSEObj;
      VSEObj.SetLineNo (LineNo);
      VSEObj.SetAttributes (0x00000002); //hardcode EFI_VARIABLE_BOOTSERVICE_ACCESS attribute
      VSEObj.SetGuid (&pNode->mGuid);
      VSEObj.SetVarStoreId (pNode->mVarStoreId);
#ifdef VFREXP_DEBUG
      printf ("undefined Efi VarStoreName is %s and Id is 0x%x\n", pNode->mVarStoreName, pNode->mVarStoreId);
#endif
    }
  }
  
}

VOID
EfiVfrParser::_DeclareDefaultLinearVarStore (
IN UINT32 LineNo
)
{
  UINT32            Index;
  CHAR8             **TypeNameList;
  UINT32            ListSize;
  CONST CHAR8       DateName[] = "Date";
  CONST CHAR8       TimeName[] = "Time";
  CONST CHAR8       DateType[] = "EFI_HII_DATE";
  CONST CHAR8       TimeType[] = "EFI_HII_TIME";
  
  gCVfrVarDataTypeDB.GetUserDefinedTypeNameList (&TypeNameList, &ListSize);
  
  for (Index = 0; Index < ListSize; Index++) {
    UINT32            Size;
    EFI_VARSTORE_ID   VarStoreId;
    CIfrVarStore      VSObj;
    
    VSObj.SetLineNo (LineNo);
    mCVfrDataStorage.DeclareBufferVarStore (
    TypeNameList[Index],
    &mFormsetGuid,
    &gCVfrVarDataTypeDB,
    TypeNameList[Index],
    EFI_VARSTORE_ID_INVALID
    );
    mCVfrDataStorage.GetVarStoreId(TypeNameList[Index], &VarStoreId);
    VSObj.SetVarStoreId (VarStoreId);
    gCVfrVarDataTypeDB.GetDataTypeSize(TypeNameList[Index], &Size);
    VSObj.SetSize ((UINT16) Size);
    VSObj.SetName (TypeNameList[Index]);
    VSObj.SetGuid (&mFormsetGuid);
  }
  
  //
  // not required to declare Date and Time VarStore,
  // because code to support old format Data and Time
  //
  if (gCVfrVarDataTypeDB.IsTypeNameDefined ((CHAR8 *) DateName) == FALSE) {
    UINT32            Size;
    EFI_VARSTORE_ID   VarStoreId;
    CIfrVarStore      VSObj;
    
    VSObj.SetLineNo (LineNo);
    mCVfrDataStorage.DeclareBufferVarStore (
    (CHAR8 *) DateName,
    &mFormsetGuid,
    &gCVfrVarDataTypeDB,
    (CHAR8 *) DateType,
    EFI_VARSTORE_ID_INVALID
    );
    mCVfrDataStorage.GetVarStoreId((CHAR8 *) DateName, &VarStoreId);
    VSObj.SetVarStoreId (VarStoreId);
    gCVfrVarDataTypeDB.GetDataTypeSize((CHAR8 *) DateType, &Size);
    VSObj.SetSize ((UINT16) Size);
    VSObj.SetName ((CHAR8 *) DateName);
    VSObj.SetGuid (&mFormsetGuid);
  }
  
  if (gCVfrVarDataTypeDB.IsTypeNameDefined ((CHAR8 *) TimeName) == FALSE) {
    UINT32            Size;
    EFI_VARSTORE_ID   VarStoreId;
    CIfrVarStore      VSObj;
    
    VSObj.SetLineNo (LineNo);
    mCVfrDataStorage.DeclareBufferVarStore (
    (CHAR8 *) TimeName,
    &mFormsetGuid,
    &gCVfrVarDataTypeDB,
    (CHAR8 *) TimeType,
    EFI_VARSTORE_ID_INVALID
    );
    mCVfrDataStorage.GetVarStoreId((CHAR8 *) TimeName, &VarStoreId);
    VSObj.SetVarStoreId (VarStoreId);
    gCVfrVarDataTypeDB.GetDataTypeSize((CHAR8 *) TimeType, &Size);
    VSObj.SetSize ((UINT16) Size);
    VSObj.SetName ((CHAR8 *) TimeName);
    VSObj.SetGuid (&mFormsetGuid);
  }
}

VOID
EfiVfrParser::_DeclareStandardDefaultStorage (
IN UINT32 LineNo
)
{
  //
  // Default Store is declared.
  //
  CIfrDefaultStore DSObj;
  
  mCVfrDefaultStore.RegisterDefaultStore (DSObj.GetObjBinAddr(), (CHAR8 *) "Standard Defaults", EFI_STRING_ID_INVALID, EFI_HII_DEFAULT_CLASS_STANDARD);
  DSObj.SetLineNo (LineNo);
  DSObj.SetDefaultName (EFI_STRING_ID_INVALID);
  DSObj.SetDefaultId (EFI_HII_DEFAULT_CLASS_STANDARD);
  
  //
  // Default MANUFACTURING Store is declared.
  //
  CIfrDefaultStore DSObjMF;
  
  mCVfrDefaultStore.RegisterDefaultStore (DSObjMF.GetObjBinAddr(), (CHAR8 *) "Standard ManuFacturing", EFI_STRING_ID_INVALID, EFI_HII_DEFAULT_CLASS_MANUFACTURING);
  DSObjMF.SetLineNo (LineNo);
  DSObjMF.SetDefaultName (EFI_STRING_ID_INVALID);
  DSObjMF.SetDefaultId (EFI_HII_DEFAULT_CLASS_MANUFACTURING);
}

VOID
EfiVfrParser::AssignQuestionKey (
IN CIfrQuestionHeader   &QHObj,
IN ANTLRTokenPtr        KeyTok
)
{
  UINT16 KeyValue;
  
  if (KeyTok == NULL) {
    return;
  }
  
  KeyValue = _STOU16 (KeyTok->getText());
  
  if (QHObj.FLAGS () & EFI_IFR_FLAG_CALLBACK) {
    /*
    * if the question is not CALLBACK ignore the key.
    */
    _PCATCH(mCVfrQuestionDB.UpdateQuestionId (QHObj.QUESTION_ID(), KeyValue), KeyTok);
    QHObj.SetQuestionId (KeyValue);
  }
}

VOID
EfiVfrParser::ConvertIdExpr (
IN UINT32          &ExpOpCount,
IN UINT32          LineNo,
IN EFI_QUESTION_ID QId,
IN CHAR8           *VarIdStr,
IN UINT32          BitMask
)
{
  CIfrQuestionRef1 QR1Obj(LineNo);
  QR1Obj.SetQuestionId (QId, VarIdStr, LineNo);
  _SAVE_OPHDR_COND (QR1Obj, (ExpOpCount == 0));
  
  if (BitMask != 0) {
    CIfrUint32       U32Obj(LineNo);
    U32Obj.SetValue (BitMask);
    
    CIfrBitWiseAnd   BWAObj(LineNo);
    
    CIfrUint8        U8Obj(LineNo);
    switch (BitMask) {
      case DATE_YEAR_BITMASK   : U8Obj.SetValue (0); break;
      case TIME_SECOND_BITMASK : U8Obj.SetValue (0x10); break;
      case DATE_DAY_BITMASK    : U8Obj.SetValue (0x18); break;
      case TIME_HOUR_BITMASK   : U8Obj.SetValue (0); break;
      case TIME_MINUTE_BITMASK : U8Obj.SetValue (0x8); break;
    }
    
    CIfrShiftRight   SRObj(LineNo);
  }
  
  ExpOpCount += 4;
}

VOID
EfiVfrParser::IdEqValDoSpecial (
IN UINT32           &ExpOpCount,
IN UINT32           LineNo,
IN EFI_QUESTION_ID  QId,
IN CHAR8            *VarIdStr,
IN UINT32           BitMask,
IN UINT16           ConstVal,
IN EFI_COMPARE_TYPE CompareType
)
{
  ConvertIdExpr (ExpOpCount, LineNo, QId, VarIdStr, BitMask);
  
  if (ConstVal > 0xFF) {
    CIfrUint16       U16Obj(LineNo);
    U16Obj.SetValue (ConstVal);
  } else {
    CIfrUint8        U8Obj(LineNo);
    U8Obj.SetValue ((UINT8)ConstVal);
  }
  
  switch (CompareType) {
    case EQUAL :
    {
      CIfrEqual EObj(LineNo);
      break;
    }
    case LESS_EQUAL :
    {
      CIfrLessEqual LEObj(LineNo);
      break;
    }
    case LESS_THAN :
    {
      CIfrLessThan LTObj(LineNo);
      break;
    }
    case GREATER_EQUAL :
    {
      CIfrGreaterEqual GEObj(LineNo);
      break;
    }
    case GREATER_THAN :
    {
      CIfrGreaterThan GTObj(LineNo);
      break;
    }
  }
  
  ExpOpCount += 2;
}

VOID
EfiVfrParser::IdEqIdDoSpecial (
IN UINT32           &ExpOpCount,
IN UINT32           LineNo,
IN EFI_QUESTION_ID  QId1,
IN CHAR8            *VarId1Str,
IN UINT32           BitMask1,
IN EFI_QUESTION_ID  QId2,
IN CHAR8            *VarId2Str,
IN UINT32           BitMask2,
IN EFI_COMPARE_TYPE CompareType
)
{
  ConvertIdExpr (ExpOpCount, LineNo, QId1, VarId1Str, BitMask1);
  ConvertIdExpr (ExpOpCount, LineNo, QId2, VarId2Str, BitMask2);
  
  switch (CompareType) {
    case EQUAL :
    {
      CIfrEqual EObj(LineNo);
      break;
    }
    case LESS_EQUAL :
    {
      CIfrLessEqual LEObj(LineNo);
      break;
    }
    case LESS_THAN :
    {
      CIfrLessThan LTObj(LineNo);
      break;
    }
    case GREATER_EQUAL :
    {
      CIfrGreaterEqual GEObj(LineNo);
      break;
    }
    case GREATER_THAN :
    {
      CIfrGreaterThan GTObj(LineNo);
      break;
    }
  }
  
  ExpOpCount++;
}

VOID
EfiVfrParser::IdEqListDoSpecial (
IN UINT32          &ExpOpCount,
IN UINT32          LineNo,
IN EFI_QUESTION_ID QId,
IN CHAR8           *VarIdStr,
IN UINT32          BitMask,
IN UINT16          ListLen,
IN UINT16          *ValueList
)
{
  UINT16 Index;
  
  if (ListLen == 0) {
    return;
  }
  
  IdEqValDoSpecial (ExpOpCount, LineNo, QId, VarIdStr, BitMask, ValueList[0], EQUAL);
  for (Index = 1; Index < ListLen; Index++) {
    IdEqValDoSpecial (ExpOpCount, LineNo, QId, VarIdStr, BitMask, ValueList[Index], EQUAL);
    CIfrOr OObj (LineNo);
    ExpOpCount++;
  }
}

//
// For framework vfr compatibility
//
VOID
EfiVfrParser::SetCompatibleMode (IN BOOLEAN Mode)
{
  mCompatibleMode = Mode;
  mCVfrQuestionDB.SetCompatibleMode (Mode);
}
