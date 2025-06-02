unit uServerProcs;

interface

uses
  Classes, SysUtils, Winsock, DateUtils, uLoggingUtils, libssh;

type
  TPacketDataList = class(TList)
    public
      procedure Delete(Index: Integer);
  end;

  TReadState = (frs_Init, frs_Reading, frs_Complete);

  TRealPathObject = class //Phasing this class out
    ClientPath: String;
    EntryKind: DWord;
    InternalPath: String;
    NamePart, PathPart: String;
    Status: DWord;
  end;

  TSFTPResourceEntry = class(TPersistent)
    private
      fDateCreated: TDateTime;
      fDateModified: TDateTime;
      fEntryKind: Integer;
      fGroup: String;
      fName: String;
      fOwner: String;
      fPermissions: String;
      fFileSize: Int64;
      fLinkCount: Integer;
    protected
      procedure SetDateCreated(const AValue: TDateTime);
      procedure SetDateModified(const AValue: TDateTime);
      procedure SetGroup(const AValue: String);
      procedure SetOwner(const AValue: String);
      procedure SetPermissions(const AValue: String);
      procedure SetFileSize(const AValue: Int64);
      procedure SetLinkCount(const AValue: Integer);
    public
      constructor Create(aEntryKind: Integer; aName: String);
      procedure Assign(Source: TPersistent); override;
      function  FileSizeAsPrettyString: String;
      property DateCreated: TDateTime read fDateCreated write SetDateCreated;
      property DateModified: TDateTime read fDateModified write SetDateModified;
      property EntryKind: Integer read fEntryKind;
      property Group: String read fGroup write SetGroup;
      property Name: String read fName;
      property Owner: String read fOwner write SetOwner;
      property Permissions: String read fPermissions write SetPermissions;
      property FileSize: Int64 read fFileSize write SetFileSize;
      property LinkCount: Integer read fLinkCount write SetLinkCount;
  end;

  TSFTPResourceEntries = class(TList)
    protected
      procedure FreeAllItems;
      function  GetItem(Index: Integer): TSFTPResourceEntry;
      procedure SetItem(Index: Integer; AItem: TSFTPResourceEntry);
    public
      destructor Destroy; override;
      property  Items[Index: Integer]: TSFTPResourceEntry read GetItem write SetItem; default;
  end;

  { Represents either a single file or a folder (but never both) }
  TSFTPResource = class(TPersistent)
    public
      { Entries is intended for folders to store their contents. *NOTE: Persistent .Entries() has failed miserably due to delete/rename/multi-client and will be removed }
      Entries: TSFTPResourceEntries;
      { Open File handle. Use this to lock file access against other writes for the duration this resource is being acted on. Close it when done and good practice set it to zero }
      FileHandle: THandle;
      { Buffer for reading/writing. Not used by system; repurpose to your need }
      FileReadPtr: Pointer;
      { Size of buffer for reading/writing. Not used by system; repurpose to your need }
      FileReadPtrSize: DWord;
      { You can store your total available bytes here to save round-trip lookups }
      FileReadTotalSize: Int64;
      { An SFTP Handle is an opaque string. Override TConnection.NewResource() to specify your handles }
      Handle: String;
      { Example /root/my-folder/ NAME-PART }
      NamePart: String;
      { Server-private. Not used by system; repurpose to your need }
      ParentFolder: String;
      { This field may leak to client in future versions }
      PathExternal: String;
      { Server-private. Put anything you like in PathInternal if you are virtualizing the file system. }
      PathInternal: String;
      { PathPart is visible to a client. Example /PATH-PART/NAME-PART }
      PathPart: String;
      { eg how many bytes into the file we are (or how many files into the folder). Note that SFTP clients may jump around within a file read; they may not want to read from the start }
      ReadIndex: Integer;
      ReadState: TReadState; //eg: generating content for client
      { SSH_OK or some error-state }
      Status: DWord;
      { Human-readable string for status }
      StatusErrorMessage: String;
      constructor Create;
      destructor Destroy; override;
      procedure Assign(Source: TPersistent); override;
      function  AddEntry(EntryKind: Integer; Name: String): TSFTPResourceEntry;
      { Deprecated. Intended for persistent folder listings, but has failed in practice. }
      procedure ClearEntries; virtual;
      { Override to perform custom constructor-type stuff }
      procedure Initialize; virtual;
      { Internal function to split a path into PathPart / NamePart }
      procedure SetFullPath(APath: String); virtual;
  end;

  TSFTPResourceClass = class of TSFTPResource;

  TSFTPResourceList = class(TList)
    protected
      procedure FreeAllItems;
      function  GetItem(Index: Integer): TSFTPResource;
      procedure SetItem(Index: Integer; AItem: TSFTPResource);
    public
      destructor Destroy; override;
      function  FindByPath(Path: String): TSFTPResource;
      function  FindByResourceID(ResourceID: String): TSFTPResource;
      property  Items[Index: Integer]: TSFTPResource read GetItem write SetItem; default;
  end;

  //A given ServerThread handles one connection at a time.
  //When the client closes the connection (or times out), the server thread is free to scan the list of waiting connections and grab one. Otherwise, it shall sleep
  TBaseConnection = class
    protected
      fAuthorized: Boolean;
      fConnected: Boolean;
      fResources: TSFTPResourceList;
      fSession: PLIBSSHSESSION;
      fPendingData: TPacketDataList;
      InBlockingWriteOperation: Boolean;
      LastPendingPacketCount: Integer;
      LastResourceID: Integer;
      ServerIndex: Integer;
      //ServerCallbacks: TServerCallbacks;
      WorkingHeader: PSFTPPacketHeader;
      WorkingBody: Pointer;
      WorkingBuffers: Pointer;
      WorkingPacketInProgress: Boolean;
      WorkingPacketSize: DWord;
      procedure RenderRealPath(RealPathObject: TRealPathObject); virtual;
    public
      xBuffer: Pointer;
      xBufferLen: Integer;
      xBufferUsed: Integer;
      ActiveChannel: PSSHChannel;
      LastActivity: Int64;
      OffSet: Integer; //Seems like LibSSH is resupplying the entire buffer on each OnChannelData callback. There's probably a call somewhere to clear it out
      ServerCallbacks: TServerCallbacks;
      constructor Create(aSession: PLIBSSHSESSION);
      destructor Destroy; override;
      procedure Disconnect; virtual;
      function  AllowOpenDir(Resource: TSFTPResource; Flags: DWord): Boolean; virtual;
      function  AllowOpenFile(Resource: TSFTPResource; Flags: DWord; IsTest: Boolean = False): Boolean; virtual;
      function  Authorize(Username, Password: String): Integer; virtual;
      procedure Initialize; virtual;
      function  NewResource(Path: String; var ResourceID: String): TSFTPResource; virtual;
      function  OpenFlagsToString(Flags: DWord): String;
      procedure PacketInit(PacketType: Byte; RequestID: DWord);
      procedure PacketPost(Channel: PSSHChannel);
      function  ReadDir(Resource: TSFTPResource): DWord; virtual;
      { On Success, build your own packet and return SSH_OK }
      procedure ReadFileContent(Resource: TSFTPResource; Channel: PSSHCHannel; RequestID: DWord; FileOffset: Int64; ContentLength: DWord); virtual;
      function  ReadInt64(Data: Pointer): Int64;
      function  ReadString(Data: Pointer): String;
      function  RemoveDir(Resource: TSFTPResource): Boolean; virtual;
      function  RemoveFile(Resource: TSFTPResource): Boolean; virtual;
      function  RenameDir(ResourceOld, ResourceNew: TSFTPResource): Boolean; virtual;
      function  RenameFile(ResourceOld, ResourceNew: TSFTPResource): Boolean; virtual;
      procedure SendAsResourceDate(Data: TDateTime);
      procedure SendBytes(Data: Pointer; DataLen: Integer);
      procedure SendBytes(Data: Integer);
      procedure SendBytes(Data: String);
      procedure SendByte(Data: Byte);
      procedure SendInt64(Data: Int64);
      procedure WriteFileContent(Resource: TSFTPResource; Content: PChar; FileOffset: Int64; ContentLength: DWord); virtual;
      property  Authorized: Boolean read fAuthorized;
      property  Connected: Boolean read fConnected;
      property  PendingData: TPacketDataList read fPendingData;
      property  Resources: TSFTPResourceList read fResources;
      property  Session: PLIBSSHSESSION read fSession;
  end;

  TConnections = class(TList)
    protected
      procedure FreeAllItems;
      function  GetItem(Index: Integer): TBaseConnection;
      procedure SetItem(Index: Integer; AItem: TBaseConnection);
    public
      destructor Destroy; override;
      property  Items[Index: Integer]: TBaseConnection read GetItem write SetItem; default;
  end;

var
  Connections: TConnections;
  ResourceClass: TSFTPResourceClass;

implementation

procedure TPacketDataList.Delete(Index: Integer);
var
  DataLen: Integer;
  P: PSFTPPacketHeader;
begin

  P := Items[Index];
  DataLen := htonl(P^.Len) - 1 - SizeOf(DWord);

  FreeMem(P, SizeOf(TSFTPPacketHeader) + DataLen);

  inherited Delete(Index);
end;

constructor TSFTPResourceEntry.Create(aEntryKind: Integer; aName: String);
begin

  inherited Create;

  fDateCreated := Now;
  fDateModified := Now;
  fEntryKind := aEntryKind;
  fGroup := 'users';
  fName := aName;
  fOwner := 'root';
  fPermissions := '';
  fFileSize := 0;
  fLinkCount := 0;

end;

procedure TSFTPResourceEntry.Assign(Source: TPersistent);
begin
  //inherited Assign(Source);

  fDateCreated := TSFTPResourceEntry(Source).DateCreated;
  fDateModified := TSFTPResourceEntry(Source).DateModified;
  fEntryKind := TSFTPResourceEntry(Source).EntryKind;
  fGroup := TSFTPResourceEntry(Source).Group;
  fName := TSFTPResourceEntry(Source).Name;
  fOwner := TSFTPResourceEntry(Source).Owner;
  fPermissions := TSFTPResourceEntry(Source).Permissions;
  fFileSize := TSFTPResourceEntry(Source).FileSize;
  fLinkCount := TSFTPResourceEntry(Source).LinkCount;

end;

function TSFTPResourceEntry.FileSizeAsPrettyString: String;
const
  Kb = 1024;
  Mb = Kb * Kb;
  Gb = Kb * Kb * Kb;
begin
  Result := '';
  if FileSize = 0 then
    Result := '0'
  else if (FileSize < Kb) then
    Result := IntToStr(FileSize)
  else if (FileSize < Mb) then
    Result := Format('%0.2f', [FileSize / Kb]) + 'kB'
  else if (FileSize < Gb) then
    Result := Format('%0.2f', [FileSize / Mb ]) + 'MB'
  else
    Result := Format('%0.2f', [FileSize / Gb]) + 'GB';
end;

procedure TSFTPResourceEntry.SetDateCreated(const AValue: TDateTime);
begin
  fDateCreated := AValue;
end;

procedure TSFTPResourceEntry.SetDateModified(const AValue: TDateTime);
begin
  fDateModified := AValue;
end;

procedure TSFTPResourceEntry.SetGroup(const AValue: String);
begin
  fGroup := AValue;
end;

procedure TSFTPResourceEntry.SetOwner(const AValue: String);
begin
  fOwner := AValue;
end;

procedure TSFTPResourceEntry.SetPermissions(const AValue: String);
begin
  fPermissions := AValue;
end;

procedure TSFTPResourceEntry.SetFileSize(const AValue: Int64);
begin
  fFileSize := AValue;
end;

procedure TSFTPResourceEntry.SetLinkCount(const AValue: Integer);
begin
  fLinkCount := AValue;
end;

destructor TSFTPResourceEntries.Destroy;
begin
  FreeAllItems;
  inherited Destroy;
end;

procedure TSFTPResourceEntries.FreeAllItems;
var
  I: Integer;
begin
  for I := 0 to Count - 1 do
    Items[I].Free;
  Clear;
end;

function TSFTPResourceEntries.GetItem(Index: Integer): TSFTPResourceEntry;
begin
  Result := TSFTPResourceEntry(inherited Items[Index]);
end;

procedure TSFTPResourceEntries.SetItem(Index: Integer; AItem: TSFTPResourceEntry);
begin
  inherited Items[Index] := AItem;
end;

constructor TSFTPResource.Create;
begin
  inherited Create;
  Entries := TSFTPResourceEntries.Create;
  Initialize;
end;

destructor TSFTPResource.Destroy;
begin
  Entries.Free;
  inherited Destroy;
end;

function TSFTPResource.AddEntry(EntryKind: Integer; Name: String): TSFTPResourceEntry;
begin

  Result := TSFTPResourceEntry.Create(EntryKind, Name);
  Entries.Add(Result);

end;

procedure TSFTPResource.Assign(Source: TPersistent);
var
  I: Integer;
  R: TSFTPResourceEntry;
begin

  ClearEntries;
  //Handle := TSFTPResource(Source).Handle; //Don't copy Handle which is unique to the Resource accepting the assignment
  NamePart := TSFTPResource(Source).NamePart;
  PathPart := TSFTPResource(Source).PathPart;
  PathInternal := TSFTPResource(Source).PathInternal;
  PathExternal := TSFTPResource(Source).PathExternal;
  ReadState := frs_Init;

  for I := 0 to TSFTPResource(Source).Entries.Count - 1 do
    begin
      R := AddEntry(TSFTPResource(Source).Entries[I].EntryKind, '');
      R.Assign(TSFTPResource(Source).Entries[I]);
    end;
end;

procedure TSFTPResource.ClearEntries;
begin
  Entries.FreeAllItems;
end;

procedure TSFTPResource.Initialize;
begin

end;

procedure TSFTPResource.SetFullPath(APath: String);
var
  I, J: Integer;
begin

  J := -1;
  for I := Length(APath) downto 1 do
    if APath[I] = '/' then
      begin
        J := I;
        Break;
      end;

  if J = -1 then
    begin
      PathPart := APath;
      NamePart := '';
    end
  else
    begin
      PathPart := Copy(APath, 1, J);
      NamePart := Copy(APath, J + 1, Length(APath));
    end;

  //For the edge case of: /folder-1/folder-2/.
  //  Strip out the . and treat folder2 as the name-part
  if (NamePart = '.') and (J > -1) then
    SetFullPath(Copy(APath, 1, J - 1));


end;

destructor TSFTPResourceList.Destroy;
begin
  FreeAllItems;
  inherited Destroy;
end;

function TSFTPResourceList.FindByPath(Path: String): TSFTPResource;
var
  I: Integer;
begin
  Result := nil;
  for I := 0 to Count - 1 do
    if Items[I].PathPart + Items[I].NamePart = Path then
      begin
        Result := Items[I];
        Break;
      end;
end;

function TSFTPResourceList.FindByResourceID(ResourceID: String): TSFTPResource;
var
  I: Integer;
begin
  Result := nil;
  for I := 0 to Count - 1 do
    if Items[I].Handle = ResourceID then
      begin
        Result := Items[I];
        Break;
      end;
end;

procedure TSFTPResourceList.FreeAllItems;
var
  I: Integer;
begin
  for I := 0 to Count - 1 do
    Items[I].Free;
  Clear;
end;

function TSFTPResourceList.GetItem(Index: Integer): TSFTPResource;
begin
  Result := TSFTPResource(inherited Items[Index]);
end;

procedure TSFTPResourceList.SetItem(Index: Integer; AItem: TSFTPResource);
begin
  inherited Items[Index] := AItem;
end;

constructor TBaseConnection.Create(aSession: PLIBSSHSESSION);
begin
  inherited Create;
  fConnected := True;
  fPendingData := TPacketDataList.Create;
  fSession := aSession;
  LastPendingPacketCount := -1;
  LastResourceID := 123;
  FillChar(ServerCallbacks, Sizeof(TServerCallbacks), 0);
  fResources := TSFTPResourceList.Create;
  ServerIndex := -1;

  GetMem(WorkingBuffers, $FFFF);
end;

destructor TBaseConnection.Destroy;
begin
  if Connected then
    Disconnect;
  fResources.Free;
  PendingData.Free;
  FreeMem(WorkingBuffers, $FFFF);
  inherited Destroy;
end;

function TBaseConnection.AllowOpenDir(Resource: TSFTPResource; Flags: DWord): Boolean;
begin
  Result := True;
end;

function TBaseConnection.AllowOpenFile(Resource: TSFTPResource; Flags: DWord; IsTest: Boolean = False): Boolean;
begin
  Result := False;
end;

function TBaseConnection.Authorize(Username, Password: String): Integer;
begin
  Result := SSH_AUTH_DENIED;
end;

procedure TBaseConnection.Disconnect;
begin
  //ssh_disconnect(Session);
  //ssh_free(Session);
  fConnected := False;
end;

procedure TBaseConnection.Initialize;
begin

end;

function TBaseConnection.NewResource(Path: String; var ResourceID: String): TSFTPResource;
begin
  if Length(ResourceID) = 0 then
    begin
      ResourceID := IntToHex(LastResourceID, 4);
      Inc(LastResourceID);
    end;

  Result := ResourceClass.Create;
  Result.Handle := ResourceID;
  Result.SetFullPath(Path);
  Resources.Add(Result);
end;

function TBaseConnection.OpenFlagsToString(Flags: DWord): String;
var
  SL: TStringList;
begin

  SL := TStringList.Create;
  SL.Delimiter := '|';

  if Flags and SSH_FXF_READ > 0 then SL.Add('READ');
  if Flags and SSH_FXF_WRITE > 0 then SL.Add('WRITE');
  if Flags and SSH_FXF_APPEND > 0 then SL.Add('APPEND');
  if Flags and SSH_FXF_CREAT > 0 then SL.Add('CREAT');
  if Flags and SSH_FXF_TRUNC > 0 then SL.Add('TRUNC');
  if Flags and SSH_FXF_EXCL > 0 then SL.Add('EXCL');

  Result := SL.DelimitedText;
  SL.Free;

end;

procedure TBaseConnection.PacketInit(PacketType: Byte; RequestID: DWord);
begin
  WorkingHeader := WorkingBuffers;
  WorkingHeader^.PacketType := PacketType;
  WorkingHeader^.RequestID := RequestID;
  WorkingBody := Pointer(WorkingHeader) + SizeOf(TSFTPPacketHeader);
  WorkingPacketSize := 0; //eg: body only; header is separate
end;

procedure TBaseConnection.PacketPost(Channel: PSSHChannel);
var
  //B: PByte; A: String;
  C: Integer;
  P: Pointer;
begin

  WorkingHeader^.Len := htonl(1 + SizeOf(DWord) + WorkingPacketSize);  //Len = PacketType + RequestID + DataLen

  //This should not be needed, but if the server seems to randomly time out, this is a good way to "poke" activity
  if (LastPendingPacketCount = 0) and not InBlockingWriteOperation then
    begin
      C := ssh_channel_write(Channel, WorkingHeader, SizeOf(TSFTPPacketHeader) + WorkingPacketSize);
      if C > 0 then
        begin
          InBlockingWriteOperation := True;
          Exit; //Since we successfully poked the data across to the client, we exit here. We do NOT add to Pending
        end;
    end;

  GetMem(P, SizeOf(TSFTPPacketHeader) + WorkingPacketSize);
  Move(WorkingHeader^, P^, SizeOf(TSFTPPacketHeader) + WorkingPacketSize);
  PendingData.Add(P);

end;

function TBaseConnection.ReadDir(Resource: TSFTPResource): DWord;
begin
  Result := SSH_FX_OP_UNSUPPORTED;
end;

procedure  TBaseConnection.ReadFileContent(Resource: TSFTPResource; Channel: PSSHCHannel; RequestID: DWord; FileOffset: Int64; ContentLength: DWord);
begin
  Resource.Status := SSH_FX_OP_UNSUPPORTED;
end;

function TBaseConnection.ReadInt64(Data: Pointer): Int64;
var
  HighPart, LowPart: DWord;

begin
  HighPart := htonl(PDWord(Data)^);
  LowPart := htonl(PDWord(Data + SizeOf(DWord))^);

  Result := Int64(HighPart) shl 32 or LowPart;
end;

function TBaseConnection.ReadString(Data: Pointer): String;
var
  Buffer: array[0..8192] of Char;
  Ln: DWord;
begin
  Ln := htonl(PDWord(Data)^);
  if Ln > 8192 then Ln := 8192;

  Data := Pointer(Data) + SizeOf(DWord);
  StrLCopy(Buffer, Data, Ln);

  Result := Buffer;
end;

function TBaseConnection.RemoveDir(Resource: TSFTPResource): Boolean;
begin
  Result := True;
end;

function TBaseConnection.RemoveFile(Resource: TSFTPResource): Boolean;
begin
  Result := True;
end;

function TBaseConnection.RenameDir(ResourceOld, ResourceNew: TSFTPResource): Boolean;
begin
  Result := True;
end;

function TBaseConnection.RenameFile(ResourceOld, ResourceNew: TSFTPResource): Boolean;
begin
  Result := True;
end;

procedure TBaseConnection.RenderRealPath(RealPathObject: TRealPathObject);
var
  J: Integer;
  SL: TStringList;
begin
  if (RealPathObject.ClientPath = '/') or (RealPathObject.ClientPath = '.') then
    begin
      RealPathObject.ClientPath := '/';
      RealPathObject.EntryKind := SSH_FILEXFER_TYPE_DIRECTORY;
      Exit;
    end;

  SL := TStringList.Create;
  SL.Delimiter := '/';
  SL.StrictDelimiter := True;

  SL.DelimitedText := RealPathObject.ClientPath;

  J := SL.IndexOf('.');
  while J > -1 do
    begin
      SL.Delete(J);
      J := SL.IndexOf('.');
    end;

  J := SL.IndexOf('..');
  while J > -1 do
    begin
      SL.Delete(J);
      if J > 0 then
        SL.Delete(J - 1);
      J := SL.IndexOf('..');
    end;

  RealPathObject.ClientPath := '';
  for J := 0 to SL.Count - 1 do
    begin
      RealPathObject.ClientPath := RealPathObject.ClientPath + SL[J];
      if J < SL.Count - 1 then
        RealPathObject.ClientPath := RealPathObject.ClientPath + '/';
    end;

  SL.Free;
end;

procedure TBaseConnection.SendAsResourceDate(Data: TDateTime);
var
  D: Int64;
begin
  D := SecondsBetween(Data, EncodeDate(1970, 01, 01));
  SendInt64(D);
end;

procedure TBaseConnection.SendBytes(Data: Pointer; DataLen: Integer);
begin
  Move(Data^, WorkingBody^, DataLen);
  WorkingBody := Pointer(WorkingBody) + DataLen;
  WorkingPacketSize := WorkingPacketSize + DataLen;
end;

procedure TBaseConnection.SendByte(Data: Byte);
begin
    SendBytes(@Data, 1);
end;

procedure TBaseConnection.SendBytes(Data: Integer);
begin
  Data := Htonl(Data);
  SendBytes(@Data, SizeOf(DWord));
end;

procedure TBaseConnection.SendBytes(Data: String);
var
  L: DWord;
begin
  L := Htonl(Length(Data));
  SendBytes(@L, SizeOf(DWord));
  SendBytes(PChar(Data), Length(Data));
end;

procedure TBaseConnection.SendInt64(Data: Int64);
var
  H, L: DWord;
begin
  H := Hi(Data);
  L := Lo(Data);
  SendBytes(H);
  SendBytes(L);
end;

procedure TBaseConnection.WriteFileContent(Resource: TSFTPResource; Content: PChar; FileOffset: Int64; ContentLength: DWord);
begin

end;

destructor TConnections.Destroy;
begin
  FreeAllItems;
  inherited Destroy;
end;

procedure TConnections.FreeAllItems;
var
  I: Integer;
begin
  for I := 0 to Count - 1 do
    Items[I].Free;
  Clear;
end;

function TConnections.GetItem(Index: Integer): TBaseConnection;
begin
  Result := TBaseConnection(inherited Items[Index]);
end;

procedure TConnections.SetItem(Index: Integer; AItem: TBaseConnection);
begin
  inherited Items[Index] := AItem;
end;

end.

