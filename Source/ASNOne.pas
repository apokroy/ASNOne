//
// ASN1 Parser for Delphi 7 and above
// 2015 Alexey Pokroy (apokroy@gmail.com)
//
// TODO:
//    Parse stream sequentially (like XML SAX parsers)
//    Support Indefinite length tags
//    Support Real tag
//    Pass test by Yury Strozhevsky http://www.strozhevsky.com/free_docs/free_asn1_testsuite_descr.pdf
//
// Initial development inspired by XAdES Starter Kit for Microsoft .NET 3.5 2010 Microsoft France
// http://www.microsoft.com/france/openness/open-source/interoperabilite_xades.aspx
//

unit ASNOne;

interface

uses SysUtils, Classes, MSXml2;

type
  {$IFNDEF UNICODE}
    RawByteString = AnsiString;
    UnicodeString = WideString;
  {$ENDIF}

  TAsn1TagClasses =
  (
    asn1Universal       = 0,
    asn1Application     = 1,
    asn1ContextSpecific = 2,
    asn1Private         = 3
  );

  TAsn1TagConstructed =
  (
    asn1Primitive       = 0,
    asn1Constructed     = 1
  );

  TAsn1UniversalTags =
  (
    asn1Eoc             = $00, //0: End-of-contents octets
    asn1Boolean         = $01, //1: Boolean
    asn1Integer         = $02, //2: Integer
    asn1BitString       = $03, //3: Bit string
    asn1OctetString     = $04, //4: Byte string
    asn1NullTag         = $05, //5: Null
    asn1Oid             = $06, //6: Object Identifier
    asn1ObjDescriptor   = $07, //7: Object Descriptor
    asn1External        = $08, //8: External
    asn1Real            = $09, //9: Real
    asn1Enumerated      = $0A, //10: Enumerated
    asn1Embedded_Pdv    = $0B, //11: Embedded Presentation Data Value
    asn1Utf8String      = $0C, //12: UTF8 string
    asn1Sequence        = $10, //16: Sequence/sequence of
    asn1Set             = $11, //17: Set/set of
    asn1NumericString   = $12, //18: Numeric string
    asn1PrintableString = $13, //19: Printable string (ASCII subset)
    asn1T61String       = $14, //20: T61/Teletex string
    asn1VideotexString  = $15, //21: Videotex string
    asn1IA5String       = $16, //22: IA5/ASCII string
    asn1UtcTime         = $17, //23: UTC time
    asn1GeneralizedTime = $18, //24: Generalized time
    asn1GraphicString   = $19, //25: Graphic string
    asn1VisibleString   = $1A, //26: Visible string (ASCII subset)
    asn1GeneralString   = $1B, //27: General string
    asn1UniversalString = $1C, //28: Universal string
    asn1BmpString       = $1E  //30: Basic Multilingual Plane/Unicode string
  );

const
  ASN1_ERROR_NONE    = $00;
  ASN1_ERROR_WARNING = $01;
  ASN1_ERROR_FATAL   = $0F;

type
  PAsn1Item = ^TAsn1Item;
  TAsn1Item = record
    TagClass: TAsn1TagClasses;
    TagConstructedFlag: TAsn1TagConstructed;
    Tag: TAsn1UniversalTags;
    TagName: string;
    Encapsulates: Boolean;
    Offset: Integer;
    HeaderLength: Integer;
    Length: Integer;
    Bytes: RawByteString;
    ErrorMessage: string;
    ErrorSeverity: Integer;
  end;

  EAsn1Exception = class(Exception)
  private
    FSeverity: Integer;
    FItem: TAsn1Item;
    FHasItem: Boolean;
  public
    constructor Create(const Msg: string; const Item: PAsn1Item; Severity: Integer);
    property  HasItem: Boolean read FHasItem;
    property  Item: TAsn1Item read FItem;
    property  Severity: Integer read FSeverity;
  end;

type
  TAsn1ParserOutputOption = (
    asn1OutputClass,
    asn1OutputEncapsulates,
    asn1OutputOffset,
    asn1OutputLength,
    asn1OutputHeaderLength,
    asn1OutputRaw
  );

  TAsn1ParserOutputOptions = set of TAsn1ParserOutputOption;

const
  Asn1ParserDefaultOutputOptions = [asn1OutputClass, asn1OutputEncapsulates, asn1OutputOffset, asn1OutputLength, asn1OutputHeaderLength, asn1OutputRaw];

type
  TAsn1Parser = class(TPersistent)
    private
    FErrors: TStrings;
    FExceptionSeverity: Integer;
    FIgnoreErrors: Boolean;
    FOutputOptions: TAsn1ParserOutputOptions;
    FRootName: string;
    FTree: IXmlDomElement;
  protected
    function  IsText(S: RawByteString): string;
    function  ParseItem(const Data: RawByteString; var Index: Integer; var Item: TAsn1Item): Boolean;
    function  TryParseItem(const Data: RawByteString; var Item: TAsn1Item): Boolean;
    procedure Error(const Msg: string; Item: PAsn1Item; Severity: Integer);
    procedure ParseAsn1Item(ParentNode: IXmlDomElement; Parent: PAsn1Item; const S: RawByteString);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Parse(const S: RawByteString); overload;
    procedure Parse(Stream: TStream); overload;
    procedure ParseFile(const FileName: string);
    property  Errors: TStrings read FErrors;
    property  ExceptionSeverity: Integer read FExceptionSeverity write FExceptionSeverity default ASN1_ERROR_FATAL;
    property  OutputOptions: TAsn1ParserOutputOptions read FOutputOptions write FOutputOptions default Asn1ParserDefaultOutputOptions;
    property  RootName: string read FRootName write FRootName;
    property  Tree: IXmlDomElement read FTree;
  end;

  Asn1 = class
  public
    class function DecodeUniversalString(const Data: RawByteString): UnicodeString;
    class function DecodeBMPString(const Data: RawByteString): UnicodeString;
    class function DecodeUtcTime(const Data: RawByteString): string;
    class function DecodeTime(const Data: RawByteString): string;

    class function EncodeOID(const OID: string): RawByteString;
  end;

const
  Asn1TagClasses: array[TAsn1TagClasses] of string =
  (    
    'Universal',
    'Application',
    'ContextSpecific',
    'Private'
  );

  Asn1TagConstructed: array[TAsn1TagConstructed] of string =
  (
    'Primitive',
    'Constructed'
  );

  Asn1UniversalTags: array[TAsn1UniversalTags] of string =
  (
		'Eoc',
		'Boolean',
		'Integer',
		'BitString',
		'OctetString',
		'NullTag',
		'Oid',
		'ObjDescriptor',
		'External',
		'Real',
		'Enumerated',
		'Embedded_Pdv',
		'Utf8String',
		'',
		'',
		'',
		'Sequence',
		'Set',
		'NumericString',
		'PrintableString',
		'T61String',
		'VideotexString',
		'IA5String',
		'UtcTime',
		'GeneralizedTime',
		'GraphicString',
		'VisibleString',
		'GeneralString',
		'UniversalString',
		'',
		'BmpString'
  );

implementation

uses Base64, ActiveX;

const
  TagNumberMask          = $1F; //Bits 5 - 1
  TagConstructedFlagMask = $20; //Bit 6
  TagClassMask           = $C0; //Bits 7 - 8
  Bit8Mask               = $80; //Indefinite or long form
  Bits7Mask              = $7F; //Bits 7 - 1

{ Asn1 }

//TODO: Not tested yet
class function Asn1.DecodeUniversalString(const Data: RawByteString): UnicodeString;
var
  Char: Word;
  I: Integer;
begin
  Result := '';
  I := 0;
  while I < Length(Data) do
  begin
    Char := Word(Data[I + 2]) shl 8 + Word(Data[I + 3]);
    Result := Result + WideChar(Char);
    Inc(I, 4);
  end;
end;

class function Asn1.DecodeBMPString(const Data: RawByteString): UnicodeString;
var
  Char: Word;
  I: Integer;
begin
  Result := '';
  I := 1;
  while I < Length(Data) do
  begin
    Char := Word(Data[I]) shl 8 + Word(Data[I + 1]);
    Result := Result + WideChar(Char);
    Inc(I, 2);
  end;
end;

class function Asn1.DecodeUtcTime(const Data: RawByteString): string;
begin
  if Byte(Data[1]) < $35 then
    Result := '20'
  else
    Result := '19';

  Result := Result + Data[1];
  Result := Result + Data[2];
  Result := Result + '-';
  Result := Result + Data[3];
  Result := Result + Data[4];
  Result := Result + '-';
  Result := Result + Data[5];
  Result := Result + Data[6];
  Result := Result + 'T';
  Result := Result + Data[7];
  Result := Result + Data[8];
  Result := Result + ':';
  Result := Result + Data[9];
  Result := Result + Data[10];
  Result := Result + ':';
  Result := Result + Data[11];
  Result := Result + Data[12];
  Result := Result + 'Z';
end;

class function Asn1.DecodeTime(const Data: RawByteString): string;
var
  I: Integer;
begin
  Result := Result + Data[1];
  Result := Result + Data[2];
  Result := Result + Data[3];
  Result := Result + Data[4];
  Result := Result + '-';
  Result := Result + Data[5];
  Result := Result + Data[6];
  Result := Result + '-';
  Result := Result + Data[7];
  Result := Result + Data[8];
  Result := Result + 'T';
  Result := Result + Data[9];
  Result := Result + Data[10];
  Result := Result + ':';
  Result := Result + Data[11];
  Result := Result + Data[12];
  Result := Result + ':';
  Result := Result + Data[13];
  Result := Result + Data[14];

  for I := 15 to Length(Data) do
  begin
    if Data[I] = 'Z' then
      Break;
    Result := Result + Data[I];
  end;

  Result := Result + 'Z';
end;

class function Asn1.EncodeOID(const OID: string): RawByteString;
var
  S: RawByteString;
  C: Integer;

  procedure MakeBase128(SID: Cardinal; First: Boolean);
  begin
    if SID > 127 then
      MakeBase128( SID div 128, False);

    SID := SID mod 128;
    if First then
      Byte(S[C]) := Byte(SID)
    else
      Byte(S[C]) := Bit8Mask or Byte(SID);
    Inc(C);
  end;

var
  SID: array of Cardinal;
  I, P, N: Integer;
begin
  Result := '';

  if OID = '' then
    Exit;

  N := 0;
  P := 1;
  for I := 1 to Length(OID) do
    if OID[I] = '.' then
    begin
      Inc(N);
      SetLength(SID, N);
      SID[N - 1] := Cardinal(StrToInt(Copy(OID, P, I - P)));
      P := I + 1;
    end;
  SetLength(SID, N + 1);
  SID[N] := Cardinal(StrToInt(Copy(OID, P, MaxInt)));

  SetLength(S, 128);
  C := 1;
  if N = 1 then
    MakeBase128(SID[0] * 40, True)
  else
  begin
    MakeBase128(SID[0] * 40 + SID[1], True);
    for I := 2 to N do
      MakeBase128(SID[I], True);
  end;

  Result := Copy(S, 1, C - 1);
end;

{ EAsn1Exception }

constructor EAsn1Exception.Create(const Msg: string; const Item: PAsn1Item; Severity: Integer);
begin
  FHasItem := Item <> nil;
  if FHasItem then
    FItem := Item^;
  FSeverity := Severity;

  inherited Create(Msg);
end;

{ TAsn1Parser }

constructor TAsn1Parser.Create;
begin
  inherited Create;

  FExceptionSeverity := ASN1_ERROR_FATAL;
  FOutputOptions := Asn1ParserDefaultOutputOptions;
  FRootName := 'Asn1';
  FErrors := TStringList.Create;
end;

destructor TAsn1Parser.Destroy;
begin
  FreeAndNil(FErrors);
  inherited;
end;

procedure TAsn1Parser.ParseFile(const FileName: string);
const
  BufferSize = 256;
var
  Stream: TFileStream;
  S: RawByteString;
  Buffer: array[0..BufferSize - 1] of Char;
  Size: Integer;
begin
  Stream := TFileStream.Create(FileName, fmOpenRead);
  try
    S := '';
    Size := Stream.Read(Buffer, BufferSize);
    while Size > 0 do
    begin
      S := S + Copy(Buffer, 0, Size);
      Size := Stream.Read(Buffer, BufferSize);
    end;
  finally
    Stream.Free;
  end;
  Parse(S);
end;

procedure TAsn1Parser.Parse(Stream: TStream);
var
  Buffer: RawByteString;
begin
  SetLength(Buffer, Stream.Size - Stream.Position);
  Stream.Read(Buffer[1], Length(Buffer));

  Parse(Buffer);
end;

procedure TAsn1Parser.Parse(const S: RawByteString);
var
  Dom: IXmlDomDocument;
begin
  CoInitialize(nil);
  try
    FErrors.Clear;

    Dom := CoDomDocument.Create;
    FTree := Dom.createElement(RootName);
    Dom.appendChild(FTree);

    ParseAsn1Item(FTree, nil, S);
  finally
    CoUninitialize;
  end;
end;

function TAsn1Parser.IsText(S: RawByteString): string;
var
  I: Integer;
begin
  for I := 1 to Length(S) do
    //Alphas, Digits and punctuation
    if not (Byte(S[I]) in [$32..$23, $25..$2A, $2C..$3B, $3F..$5D, $5F..$7B, $7D, $A1, $AB, $AD, $B7, $BB, $BF..$C0]) then
    begin
      Result := '';
      Exit;
    end;

  Result := S;
end;

function TAsn1Parser.TryParseItem(const Data: RawByteString; var Item: TAsn1Item): Boolean;
var
  Dummy: Integer;
begin
  Dummy := 1;
  try
    FIgnoreErrors := True;
    Result := ParseItem(Data, Dummy, Item);
  except
    Result := False;
  end;
  FIgnoreErrors := False;
end;

function TAsn1Parser.ParseItem(const Data: RawByteString; var Index: Integer; var Item: TAsn1Item): Boolean;
var
  Buffer, Buffer2: Integer;
  LengthLength, LengthCounter: Cardinal;
begin
  Result := True;

  LengthLength := 0;

  //Tag info
  Buffer := Byte(Data[Index]);
  Inc(Index);

  Item.TagClass := TAsn1TagClasses((Buffer and TagClassMask) shr 6);
  Item.TagConstructedFlag := TAsn1TagConstructed((Buffer and TagConstructedFlagMask) shr 5);
  Item.Tag := TAsn1UniversalTags(Buffer and TagNumberMask);
  Item.Encapsulates := False;

  if Item.TagClass = asn1Universal then
    Item.TagName := Asn1UniversalTags[Item.Tag]
  else
    Item.TagName := 'Context_' + IntToStr(Integer(Item.Tag));

  //Tag length
  Item.Length := Byte(Data[Index]);
  Inc(Index);

  if (Item.Length and Bit8Mask) <> 0 then
  begin
    //We have a multiple byte length
    LengthLength := Item.Length and Bits7Mask;

    if LengthLength = 0 then
    begin
      Error('Indefinite length not supported', @Item, ASN1_ERROR_FATAL);
      Result := False;
    end;

    if LengthLength > 4 then
    begin
      Error('Bad length (' + IntToStr(LengthLength) + ') encountered', @Item, ASN1_ERROR_FATAL);
      Result := False;
    end;

    Item.Length := 0;
    for LengthCounter := 0 to LengthLength - 1 do
    begin
      Buffer2 := Byte(Data[Index]);
      Inc(Index);
      Item.Length := (Item.Length shl 8) or Buffer2;
    end;
  end;
  Item.HeaderLength := LengthLength + 2;

  Item.Bytes := Copy(Data, Index, Item.Length);

  Inc(Index, Item.Length);
end;

procedure TAsn1Parser.ParseAsn1Item(ParentNode: IXmlDomElement; Parent: PAsn1Item; const S: RawByteString);

  function GetHexString(const Item: TAsn1Item): RawByteString;
  var
    I: Integer;
  begin
    Result := '';
    for I := 1 to Item.Length do
      Result := Result + IntToHex(Byte(Item.Bytes[I]), 2);
  end;

  //TODO: Very ineffective
  function BitStringToBytes(const S: string): RawByteString;
  var
    I, J, C: Integer;
    Bits: RawByteString;
    B: Byte;
  begin
    Result := '';
    C := 0;
    I := Length(S);
    while I > 0 do
    begin
      Inc(C);

      if Length(Result) < C then
        SetLength(Result, C + 15);

      if I >= 8 then
        Bits := Copy(S, I - 7, 8)
      else
        Bits := Copy(S, 1, I);

      B := 0;
      for J := Length(Bits) downto 1 do
      begin
        B := (B shl 1);
        if Bits[J] = '1' then
          B := B or 1;
      end;
      Byte(Result[C]) := B;

      Dec(I, 8);
    end;
    SetLength(Result, C);
  end;

var
  Buffer, Buffer2: Integer;
  I: Integer;
  ChildNode: IXmlDomElement;
  Value: WideString;
  IntegerBuffer: Int64;
  Item, ProbeItem: TAsn1Item;
  Index: Integer;
  Bytes: RawByteString;
  UnusedBits, Bitmask, BitCounter: Byte;
begin
  Index := 1;
    while Index < Length(S) do
    begin
    Value := '';

    if Parent = nil then
      Item.Offset := Index - 1
    else
      Item.Offset := Index + Parent.Offset + Parent.HeaderLength - 1;

    ParseItem(S, Index, Item);

    ChildNode := ParentNode.OwnerDocument.CreateElement(Item.TagName);
    ParentNode.AppendChild(ChildNode);
    try
      if Item.TagConstructedFlag = asn1Constructed then
      begin
        ParseAsn1Item(ChildNode, @Item, Item.Bytes);
      end
      else
      begin
        ProbeItem.Bytes := '';
        Value := GetHexString(Item);

        if Item.TagClass = asn1Universal then
        begin
          case Item.Tag of
            asn1Boolean:
              begin
                if Byte(Item.Bytes[1]) = 0 then
                  Value := 'False'
                else
                  Value := 'True';
              end;
            asn1Oid:
              begin
                if Item.Length > 32 then
                  Error('OID length (' + IntToStr(Item.Length) + ') exceeds 32', @Item, ASN1_ERROR_WARNING);

                Buffer  := Byte(Item.Bytes[1]) div 40;
                Buffer2 := Byte(Item.Bytes[1]) mod 40;
                if Buffer > 2 then
                begin
                  //Some OID magic: shave of any excess (>2) of buffer and add to buffer2
                  Buffer2 := Buffer2 + (Buffer - 2) * 40;
                  Buffer := 2;
                end;
                Value := IntToStr(Buffer) + '.' + IntToStr(Buffer2);

                Buffer := 0;
                for I := 2 to Item.Length do
                begin
                  Buffer := (Buffer shl 7) or (Byte(Item.Bytes[I]) and Bits7Mask);
                  if (Byte(Item.Bytes[I]) and Bit8Mask) = 0 then
                  begin
                    Value := Value + '.' + IntToStr(Buffer);
                    Buffer := 0;
                  end;
                end;
              end;
            asn1Integer, asn1Enumerated:
              begin
                if Item.Length < 19 then
                begin
                  IntegerBuffer := 0;
                  for I := 1 to Item.Length do
                    IntegerBuffer := (IntegerBuffer shl 8) or Byte(Item.Bytes[I]);

                  Value := IntToStr(IntegerBuffer);
                end;
              end;
            asn1OctetString:
              begin
                if TryParseItem(Item.Bytes, ProbeItem) then
                begin
                  if (ProbeItem.Length + probeItem.HeaderLength) = Item.Length then
                  begin
                    Item.Encapsulates := True;
                    ParseAsn1Item(ChildNode, @Item, Item.Bytes);
                  end;
                end;
              end;
            asn1Utf8String:
              Value := Utf8Decode(Copy(Item.Bytes, 1, Item.Length));
            asn1UniversalString:
              Value := Asn1.DecodeUniversalString(Copy(Item.Bytes, 1, Item.Length));
            asn1IA5String:
              Value := Copy(Item.Bytes, 1, Item.Length);
            asn1BmpString:
              Value := Asn1.DecodeBMPString(Copy(Item.Bytes, 1, Item.Length));
            asn1NumericString:
              Value := Item.Bytes;
            asn1VisibleString,
            //TODO: VisibleString is not the same as PrintableString
            asn1PrintableString:
              Value := Copy(Item.Bytes, 1, Item.Length);
            asn1GeneralizedTime:
              begin
                if Item.Length < 15 then
                  Error('Generalized time has to be at least 15 bytes long (' + IntToStr(Item.Length) + ')', @Item, ASN1_ERROR_WARNING)
                else
                  Value := Asn1.DecodeTime(Item.Bytes);
              end;
            asn1UtcTime:
              begin
                if Item.Length <> 13 then
                  Error('UTC time has to be 13 bytes long (' + IntToStr(Item.Length) + ')', @Item, ASN1_ERROR_WARNING)
                else
                  Value := Asn1.DecodeUtcTime(Item.Bytes);
              end;
            asn1BitString:
              begin
                UnusedBits := Byte(Item.Bytes[1]);
                if UnusedBits > 7 then
                  Error('Unused bits of bistring out of range [1-7] (' + IntToStr(UnusedBits) + ')', @Item, ASN1_ERROR_WARNING)
                else
                begin
                  Value := '';
                  Bitmask := Bit8Mask;
                  for I := 2 to Item.Length do
                  begin
                    if I <> Item.Length then
                    begin
                      for BitCounter := 0 to 7 do
                      begin
                        if ((Bitmask shr BitCounter) and Byte(Item.Bytes[I])) = 0 then
                          Value := '0' + Value
                        else
                          Value := '1' + Value;
                      end
                    end
                    else
                    begin
                      for BitCounter := 0 to 7 - UnusedBits do
                      begin
                        if ((Bitmask shr BitCounter) and Byte(Item.Bytes[I])) = 0 then
                          Value := '0' + Value
                        else
                          Value := '1' + Value;
                      end;
                    end;
                  end;

                  Bytes := BitStringToBytes(Value);
                  if TryParseItem(Bytes, ProbeItem) and ((ProbeItem.Length + ProbeItem.HeaderLength + 1) = Item.Length) then
                  begin
                    Value := '';
                    Item.Encapsulates := True;
                    ParseAsn1Item(ChildNode, @Item, Bytes);
                  end;

                  ChildNode.SetAttribute('UnusedBits', UnusedBits);
                end;
              end;
            else if Item.Length > 0 then
              Error('Unsupported tag (' + IntToStr(Integer(Item.Tag)) + ')', @Item, ASN1_ERROR_WARNING);
          end;
        end
        else
        begin
          Value := IsText(Item.Bytes);
          if Value = '' then
            Value := GetHexString(Item);
        end;
      end;
    finally
      if Item.ErrorMessage <> '' then
      begin
        ChildNode.setAttribute('Error', Item.ErrorMessage);
        ChildNode.setAttribute('Severity', Item.ErrorSeverity);
      end;

      if (Item.TagConstructedFlag <> asn1Constructed) and (Value <> '') then
        ChildNode.SetAttribute('Value', Value);

      if asn1OutputClass in OutputOptions then
        ChildNode.setAttribute('Class', Asn1TagClasses[Item.TagClass]);

      if (asn1OutputEncapsulates in OutputOptions) and Item.Encapsulates then
        ChildNode.setAttribute('Encapsulates', 'True');

      if asn1OutputOffset in OutputOptions then
        ChildNode.setAttribute('Offset', Item.Offset);

      if asn1OutputLength in OutputOptions then
        ChildNode.setAttribute('Length', Item.Length);

      if asn1OutputHeaderLength in OutputOptions then
        ChildNode.setAttribute('HeaderLength', Item.HeaderLength);

      if asn1OutputRaw in OutputOptions then
        ChildNode.setAttribute('Raw', EncodeBase64(Item.Bytes));
    end;
  end;
end;

procedure TAsn1Parser.Error(const Msg: string; Item: PAsn1Item; Severity: Integer);
begin
  if FIgnoreErrors then
    Exit;

  if Item <> nil then
  begin
    Item.ErrorMessage := Msg;
    Item.ErrorSeverity := Severity;
  end;

  FErrors.Add(Msg);

  if Severity >= ExceptionSeverity then
    raise EAsn1Exception.Create(Msg, Item, Severity);
end;

end.
