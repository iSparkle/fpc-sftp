unit uServerThread;


interface

uses
  Classes, SysUtils, Windows, Winsock, DateUtils, libssh, uLoggingUtils, uServerProcs, uServerConstants;

type
  TConnection = class(TBaseConnection)
    protected
  end;

  TConnectionClass = class of TConnection;

  function ServerThread(Param: Pointer): {$IFDEF Win64}Int64{$ELSE}Integer{$ENDIF};

  function cbAuthUserPassword(Session: PLIBSSHSESSION; Username: PChar; Password: PChar; UserData: Pointer): Integer; cdecl;
  function cbNewChannel(Session: PLIBSSHSESSION; UserData: Pointer): PSSHChannel; cdecl;

var
  ConnectionClass: TConnectionClass;

implementation

threadvar
  ServerName: String;

function GetConnection(UserData: Pointer; Session: PLIBSSHSESSION): TConnection;
var
  I: Integer;
begin

  Result := nil;
  if UserData <> nil then
    begin
      Result := TConnection(UserData);
      Exit;
    end;

  //Hmm.... LibSSH passed a null UserData. Let's find-by-session?
  for I := 0 to Connections.Count - 1 do
    begin
      if Connections[I].Connected and (Connections[I].Session = Session) then
        begin
          Result := TConnection(Connections[I]);
          Break;
        end;
    end;


end;

procedure OnChannelClose(Session: PLIBSSHSESSION; Channel: PSSHChannel; UserData: Pointer); cdecl;
var
  Connection: TConnection;
begin

  Connection := GetConnection(UserData, Session);

  WriteLog(log_Debug, ServerName, 'OnChannelClose');

  if Connection <> nil then
    Connection.Disconnect;
end;

function OnChannelData(Session: PLIBSSHSESSION; Channel: PSSHChannel; Data: Pointer; Len: DWord; is_stderr: Integer; UserData: Pointer): DWord; cdecl;
var
  A: String;
  Connection: TConnection;
  Content: PChar;
  ContentLengthPtr: PDWord;
  ContentLength: DWord;
  FileOffset: PInt64;
  FileOffsetA: Int64;
  Flags: PDWord;
  I, J: Integer;
  FlagsAsInteger: DWord;
  P: PSFTPPacketHeader;
  PacketsRead: Integer;
  Path, Res: String;
  RealPathObject: TRealPathObject;
  Resource: TSFTPResource;
  ResourceB: TSFTPResource; //For re-names
  Response: DWord;

  function StrPadBefore(A: String; Len: Integer): String;
  begin
    while Length(A) < Len do
      A := ' ' + A;
    Result := A;
  end;

  function StrPadAfter(A: String; Len: Integer): String;
  begin
    while Length(A) < Len do
      A := A + ' ';
    Result := A;
  end;

begin

  Connection := GetConnection(UserData, Session);

  if Connection = nil then //This is a problem
    begin
      Result := SSH_Ok;
      Exit;
    end;

  Connection.LastActivity := GetTickCount64;
  Connection.ActiveChannel := Channel;

  PacketsRead := 0;
  while Connection.OffSet < Len do
    begin

      Inc(PacketsRead);
      P := Pointer(Data) + Connection.OffSet;

      case P^.PacketType of
        SSH_FXP_INIT:
          begin

            WriteLog(log_Debug, ServerName, 'SSH_FXP_INIT');

            Connection.PacketInit(SSH_FXP_VERSION, htonl(3));
            Connection.PacketPost(Channel);
          end;
        SSH_FXP_MKDIR:
          begin

            Path := Connection.ReadString(Pointer(P) + SizeOf(TSFTPPacketHeader));

            WriteLog(log_Info, ServerName, 'SSH_FXP_MKDIR: ' + Path);

            Resource := ResourceClass.Create;
            Resource.SetFullPath(Path);

            FlagsAsInteger := SSH_FXF_READ or SSH_FXF_WRITE or SSH_FXF_CREAT;

            if Connection.AllowOpenDir(Resource, FlagsAsInteger) then
              begin
                Connection.PacketInit(SSH_FXP_STATUS, P^.RequestID);
                Connection.SendBytes(SSH_OK); //Status code
                Connection.SendBytes(''); //Error Message
                Connection.SendBytes(''); //Error-specfic data
                Connection.PacketPost(Channel);
              end
            else
              begin
                Connection.PacketInit(SSH_FXP_STATUS, P^.RequestID);
                Connection.SendBytes(Resource.Status); //Status code
                Connection.SendBytes(Resource.StatusErrorMessage); //Error Message
                Connection.SendBytes(''); //Error-specfic data
                Connection.PacketPost(Channel);
              end;

            Resource.Free;

          end;
        SSH_FXP_REALPATH:
          begin

            Path := Connection.ReadString(Pointer(P) + SizeOf(TSFTPPacketHeader));

            WriteLog(log_Debug, ServerName, ' SSH_FXP_REALPATH: "' + Path + '"');

            RealPathObject := TRealPathObject.Create;

            if (Path = '.') or (Path = '/.') then
              begin
                RealPathObject.ClientPath := '/';
                RealPathObject.EntryKind := SSH_FILEXFER_TYPE_DIRECTORY;
                RealPathObject.Status := SSH_OK;
              end
            else
              begin
                RealPathObject.ClientPath := Path;
                Connection.RenderRealPath(RealPathObject);
              end;

            if RealPathObject.Status = SSH_OK then
              begin
                Connection.PacketInit(SSH_FXP_NAME, P^.RequestID);
                Connection.SendBytes(1);
                Connection.SendBytes(RealPathObject.ClientPath);
                Connection.SendBytes('');
                Connection.SendByte(RealPathObject.EntryKind);
                Connection.SendByte(255);
                Connection.PacketPost(Channel);
              end
            else
              begin
                Connection.PacketInit(SSH_FXP_STATUS, P^.RequestID);
                Connection.SendBytes(RealPathObject.Status); //Status code
                Connection.SendBytes('Path not found'); //Error Message
                Connection.SendBytes(''); //Error-specfic data
                Connection.PacketPost(Channel);
              end;

            RealPathObject.Free;

          end;
        SSH_FXP_OPEN:
          begin

            Path := Connection.ReadString(Pointer(P) + SizeOf(TSFTPPacketHeader));
            Flags := Pointer(P) + SizeOf(TSFTPPacketHeader) + Length(Path) + SizeOf(DWord);
            FlagsAsInteger := htonl(Flags^);

            Resource := ResourceClass.Create;
            Resource.SetFullPath(Path);

            if (Path = '.') or (Path = '/.') then
              begin
                //We don't allow SSH_FXP_OPEN to work on directories
                //Resource.EntryKind := SSH_FILEXFER_TYPE_DIRECTORY;
                Resource.Status := SSH_OK;
              end
            else
              begin
                //RealPathObject.ClientPath := Path;
                //Connection.RenderRealPath(RealPathObject);
              end;

            //Res := '';
            if Connection.AllowOpenFile(Resource, FlagsAsInteger) then
              begin

                if Length(Resource.Handle) = 0 then
                  begin
                    Resource.Handle := IntToHex(Connection.LastResourceID, 4);
                    Inc(Connection.LastResourceID);
                  end;

                WriteLog(log_Debug, ServerName, 'SSH_FXP_OPEN File: "' + Path + '" Flags:' + Connection.OpenFlagsToString(FlagsAsInteger));
                //Resource := Connection.NewResource(Path, Res);
                Connection.Resources.Add(Resource);
                Resource.AddEntry(SSH_FILEXFER_TYPE_REGULAR, Path);
                Resource.ReadState := frs_Init;
                Resource.ReadIndex := 0;
                Connection.PacketInit(SSH_FXP_HANDLE, P^.RequestID);
                Connection.SendBytes(Resource.Handle);
                Connection.PacketPost(Channel);
              end
            else
              begin
                //Send FXP_STATUS
                WriteLog(log_Info, ServerName, 'SSH_FXP_OPEN denied: "' + Path + '" Flags:' + Connection.OpenFlagsToString(FlagsAsInteger));
                if Length(Resource.StatusErrorMessage) = 0 then Resource.StatusErrorMessage := 'Cannot open resource';

                Connection.PacketInit(SSH_FXP_STATUS, P^.RequestID);
                Connection.SendBytes(SSH_FX_FAILURE); //Status code
                Connection.SendBytes(Resource.StatusErrorMessage); //Error Message
                Connection.SendBytes(''); //Error-specfic data
                Connection.PacketPost(Channel);

                Resource.Free;
              end;

          end;
        SSH_FXP_OPENDIR:
          begin

            Path := Connection.ReadString(Pointer(P) + SizeOf(TSFTPPacketHeader));


            Resource := ResourceClass.Create;
            Resource.SetFullPath(Path);

            //Res := '';
            if Connection.AllowOpenDir(Resource, SSH_FXF_READ) then
              begin
                WriteLog(log_Debug, ServerName, 'SSH_FXP_OPEN DIR: "' + Path + '"');

                if Length(Resource.Handle) = 0 then
                  begin
                    Resource.Handle := IntToHex(Connection.LastResourceID, 4);
                    Inc(Connection.LastResourceID);
                  end;

                //Resource := Connection.NewResource(Path, Res);
                //Resource.AddEntry(SSH_FILEXFER_TYPE_DIRECTORY, Path);
                Connection.Resources.add(Resource);
                Resource.ReadState := frs_Init;
                Resource.ReadIndex := 0;
                Connection.PacketInit(SSH_FXP_HANDLE, P^.RequestID);
                Connection.SendBytes(Resource.Handle);
                Connection.PacketPost(Channel);
              end
            else
              begin
                //Send FXP_STATUS
                WriteLog(log_Info, ServerName, 'SSH_FXP_OPENDIR denied: "' + Path + '"');
                Connection.PacketInit(SSH_FXP_STATUS, P^.RequestID);
                Connection.SendBytes(Resource.Status); //Status code
                Connection.SendBytes(Resource.StatusErrorMessage); //Error Message
                Connection.SendBytes(''); //Error-specfic data
                Connection.PacketPost(Channel);

                Resource.Free;
              end;
          end;
        SSH_FXP_CLOSE:
          begin

            Res := Connection.ReadString(Pointer(P) + SizeOf(TSFTPPacketHeader)); //This is a FileHandle;

            WriteLog(log_Info, ServerName, 'Resource Close: ' + Res);

            Connection.PacketInit(SSH_FXP_STATUS, P^.RequestID);
            Connection.SendBytes(SSH_FX_OK); //Status code
            Connection.SendBytes('Close'); //Error Message
            Connection.SendBytes(''); //Error-specfic data
            Connection.PacketPost(Channel);
          end;
        SSH_FXP_READ:
          begin

            Res := Connection.ReadString(Pointer(P) + SizeOf(TSFTPPacketHeader)); //This is a FileHandle;

            WriteLog(log_Debug, ServerName, 'SSH_FXP_READ Res:' + Res);

            Resource := Connection.Resources.FindByResourceID(Res);

            A := '  Read resource: ' + Res;
            if (Resource <> nil) and (Resource.Entries.Count > 0) then
              A := A + ' => ' + Resource.Entries[0].Name;
            FileOffSetA := Connection.ReadInt64(Pointer(P) + SizeOf(TSFTPPacketHeader) + Length(Res) + SizeOf(DWord));
            //Pointer(P) + SizeOf(TSFTPPacketHeader) + Length(Res) + SizeOf(DWord);
            A := A + ' Offset:' + IntToStr(FileOffSetA);
            ContentLength := htonl(PDword(Pointer(P) + SizeOf(TSFTPPacketHeader) + Length(Res) + SizeOf(DWord) + SizeOf(Int64))^);
            A := A + ' Len:' + IntToStr(ContentLength);
            WriteLog(log_Info, ServerName, A);

            case Resource.ReadState of
              frs_Init, frs_Reading:
                begin
                  Resource.Status := SSH_FX_OP_UNSUPPORTED;
                  Resource.StatusErrorMessage := '';
                  Connection.ReadFileContent(Resource, Channel, P^.RequestID, FileOffSetA, ContentLength);
                  if Resource.Status <> SSH_OK then
                    begin
                      WriteLog(log_Info, ServerName, 'Read resource failed: ' + IntToStr(Resource.Status));
                      Connection.PacketInit(SSH_FXP_STATUS, P^.RequestID);
                      Connection.SendBytes(Resource.Status); //Status code
                      Connection.SendBytes(Resource.StatusErrorMessage);
                      Connection.SendBytes(''); //Error-specfic data
                      Connection.PacketPost(Channel);
                    end;
                end;
              frs_Complete:
                begin
                  Connection.PacketInit(SSH_FXP_STATUS, P^.RequestID);
                  Connection.SendBytes(SSH_FX_EOF); //Status code
                  Connection.SendBytes('End of file'); //Error Message
                  Connection.SendBytes(''); //Error-specfic data
                  Connection.PacketPost(Channel);
                end;
            end;

          end;
        SSH_FXP_READDIR:
          begin

            Res := Connection.ReadString(Pointer(P) + SizeOf(TSFTPPacketHeader)); //This is a FileHandle

            WriteLog(log_Debug, ServerName, ' SSH_FXP_READDIR Res:' + Res);

            Resource := Connection.Resources.FindByResourceID(Res);
            if (Resource = nil) then
              begin

                //WriteLog(log_Debug, ServerName, ' SSH_FXP_READDIR ResA: nil');
                Connection.PacketInit(SSH_FXP_STATUS, P^.RequestID);
                Connection.SendBytes(SSH_FX_BAD_MESSAGE); //Status code
                Connection.SendBytes('Resource not found'); //Error Message
                Connection.SendBytes(''); //Error-specfic data
                Connection.PacketPost(Channel);

              end
            else
              begin

                //WriteLog(log_Debug, ServerName, ' SSH_FXP_READDIR ResA:' + Res);
                //Not clear if this is necessary. Esp if the resource spans folders
                //if Resource.ReadState = frs_Init then
                //  begin
                //    Resource.ClearEntries;
                //    Resource.ReadIndex := 0;
                //    Resource.StatusErrorMessage := 'End of file';
                //  end;
                if Resource.ReadIndex = 0 then
                  begin
                    //Resource.ClearEntries;
                    //Resource.ReadIndex := 0;
                    Resource.StatusErrorMessage := 'End of file';
                  end;

                Response := Connection.ReadDir(Resource);

                if Response = SSH_FX_OK then
                  begin

                    Connection.PacketInit(SSH_FXP_NAME, P^.RequestID);

                    Connection.SendBytes(Resource.Entries.Count - Resource.ReadIndex);

                    for I := Resource.ReadIndex to Resource.Entries.Count - 1 do
                      begin

                        Connection.SendBytes(Resource.Entries[I].Name); //ShortName

                        A :=
                          StrPadAfter(Resource.Entries[I].Permissions, 10) + ' ' +
                          StrPadBefore(IntToStr(Resource.Entries[I].LinkCount), 4) + ' ' +
                          StrPadAfter(Resource.Entries[I].Owner, 8) + ' ' +
                          StrPadAfter(Resource.Entries[I].Group, 8) + ' ' +
                          StrPadBefore(Resource.Entries[I].FileSizeAsPrettyString, 8) + ' ' +
                          'May 15  2023' + ' ' + //To-do: .DateAsPrettyString()
                          Resource.Entries[I].Name
                          ;

                        //WriteLog(log_Debug, ServerName, ' Long-Name: ' + A);

                        Connection.SendBytes(A); //Long Name

                        J := SSH_FILEXFER_ATTR_ACCESSTIME;
                        Connection.SendBytes(J);

                        Connection.SendAsResourceDate(Resource.Entries[I].DateModified); //Access Time

                      end;
                    Connection.PacketPost(Channel);

                    Resource.ReadIndex := Resource.Entries.Count - 1;

                  end
                else
                  begin
                    Connection.PacketInit(SSH_FXP_STATUS, P^.RequestID);
                    Connection.SendBytes(Response); //Status code
                    Connection.SendBytes(Resource.StatusErrorMessage); //Error Message
                    Connection.SendBytes(''); //Error-specfic data
                    Connection.PacketPost(Channel);
                  end;

              end;

          end;
        SSH_FXP_REMOVE:
          begin
            Path := Connection.ReadString(Pointer(P) + SizeOf(TSFTPPacketHeader));

            WriteLog(log_Info, ServerName, 'SSH_FXP_REMOVE: ' + Path);

            Resource := ResourceClass.Create;
            Resource.SetFullPath(Path);

            FlagsAsInteger := SSH_FXF_READ or SSH_FXF_WRITE;

            if Connection.AllowOpenFile(Resource, FlagsAsInteger) and Connection.RemoveFile(Resource) then
              begin
                Connection.PacketInit(SSH_FXP_STATUS, P^.RequestID);
                Connection.SendBytes(SSH_OK); //Status code
                Connection.SendBytes(''); //Error Message
                Connection.SendBytes(''); //Error-specfic data
                Connection.PacketPost(Channel);
              end
            else
              begin
                Connection.PacketInit(SSH_FXP_STATUS, P^.RequestID);
                Connection.SendBytes(Resource.Status); //Status code
                Connection.SendBytes(Resource.StatusErrorMessage); //Error Message
                Connection.SendBytes(''); //Error-specfic data
                Connection.PacketPost(Channel);
              end;

            Resource.Free;

          end;
        SSH_FXP_RENAME:
          begin

            Path := Connection.ReadString(Pointer(P) + SizeOf(TSFTPPacketHeader));
            A := Connection.ReadString(Pointer(P) + SizeOf(TSFTPPacketHeader) + Length(Path) + SIzeOf(DWord));

            WriteLog(log_Info, ServerName, 'SSH_FXP_RENAME FROM: ' + Path);
            WriteLog(log_Info, ServerName, 'SSH_FXP_RENAME   TO: ' + A);

            Resource := ResourceClass.Create;
            Resource.SetFullPath(Path);
            ResourceB := ResourceClass.Create;
            ResourceB.SetFullPath(A);

            FlagsAsInteger := SSH_FXF_READ or SSH_FXF_WRITE;

            if (Connection.AllowOpenFile(Resource, FlagsAsInteger) and Connection.RenameFile(Resource, ResourceB)) or
               (Connection.AllowOpenDir(Resource, FlagsAsInteger) and Connection.RenameDir(Resource, ResourceB))
              then
              begin
                Connection.PacketInit(SSH_FXP_STATUS, P^.RequestID);
                Connection.SendBytes(SSH_OK); //Status code
                Connection.SendBytes(''); //Error Message
                Connection.SendBytes(''); //Error-specfic data
                Connection.PacketPost(Channel);
              end
            else
              begin
                Connection.PacketInit(SSH_FXP_STATUS, P^.RequestID);
                Connection.SendBytes(Resource.Status); //Status code
                Connection.SendBytes(Resource.StatusErrorMessage); //Error Message
                Connection.SendBytes(''); //Error-specfic data
                Connection.PacketPost(Channel);
              end;

            ResourceB.Free;
            Resource.Free;

          end;
        SSH_FXP_RMDIR:
          begin

            Path := Connection.ReadString(Pointer(P) + SizeOf(TSFTPPacketHeader));

            WriteLog(log_Info, ServerName, 'SSH_FXP_REMOVE: ' + Path);

            Resource := ResourceClass.Create;
            Resource.SetFullPath(Path);

            FlagsAsInteger := SSH_FXF_READ or SSH_FXF_WRITE;

            if Connection.AllowOpenDir(Resource, FlagsAsInteger) and Connection.RemoveDir(Resource) then
              begin
                Connection.PacketInit(SSH_FXP_STATUS, P^.RequestID);
                Connection.SendBytes(SSH_OK); //Status code
                Connection.SendBytes(''); //Error Message
                Connection.SendBytes(''); //Error-specfic data
                Connection.PacketPost(Channel);
              end
            else
              begin
                Connection.PacketInit(SSH_FXP_STATUS, P^.RequestID);
                Connection.SendBytes(Resource.Status); //Status code
                Connection.SendBytes(Resource.StatusErrorMessage); //Error Message
                Connection.SendBytes(''); //Error-specfic data
                Connection.PacketPost(Channel);
              end;

            Resource.Free;

          end;
        SSH_FXP_STAT, SSH_FXP_LSTAT:
          begin
            Path := Connection.ReadString(Pointer(P) + SizeOf(TSFTPPacketHeader));

            WriteLog(log_Info, ServerName, 'SSH_FXP_STAT: ' + Path);

            Resource := Connection.Resources.FindByPath(Path);
            if Resource = nil then
              begin

                Resource := ResourceClass.Create;
                Resource.SetFullPath(Path);

                //Res := '';

                //if (Path = '.') or (Path = '/.') then
                //  begin
                //    RealPathObject.ClientPath := '/';
                //    RealPathObject.EntryKind := SSH_FILEXFER_TYPE_DIRECTORY;
                //    RealPathObject.Status := SSH_OK;
                //  end
                //else
                //  begin
                //    RealPathObject.ClientPath := Path;
                //    Connection.RenderRealPath(RealPathObject);
                //  end;

                if Connection.AllowOpenFile(Resource, SSH_FXF_READ, True) then
                  begin
                    //Resource := Connection.NewResource(Path, Res);
                    if Length(Resource.Handle) = 0 then
                      begin
                        Resource.Handle := IntToHex(Connection.LastResourceID, 4);
                        Inc(Connection.LastResourceID);
                      end;
                    Connection.Resources.Add(Resource); //Do we rly need to maintain a resource created by a STAT?
                    Resource.AddEntry(SSH_FILEXFER_TYPE_REGULAR, Path);  //To-Do: Can we safely assume the client only stats a file?
                    Resource.ReadState := frs_Init;
                    Resource.ReadIndex := 0;
                  end
                else
                  begin
                    Resource.Free;
                    Resource := nil;
                  end;

              end;

            if (Resource <> nil) and (Resource.Entries.Count > 0) then
              begin
                Connection.PacketInit(SSH_FXP_ATTRS, P^.RequestID);
                J := SSH_FILEXFER_ATTR_ACCESSTIME;// or SSH_FILEXFER_ATTR_SIZE;
                Connection.SendBytes(J);
                //Size
                //Connection.SendInt64(Resource.Entries[0].FileSize);
                //Access Time
                Connection.SendAsResourceDate(Resource.Entries[0].DateModified);
                Connection.PacketPost(Channel);
              end
            else
              begin
                Connection.PacketInit(SSH_FXP_STATUS, P^.RequestID);
                Connection.SendBytes(SSH_FX_NO_SUCH_PATH); //Status code
                Connection.SendBytes('Path error'); //Error Message
                Connection.SendBytes(''); //Error-specfic data
                Connection.PacketPost(Channel);
              end;

            //Resource.Free;

          end;
        SSH_FXP_WRITE:
          begin
            Res := Connection.ReadString(Pointer(P) + SizeOf(TSFTPPacketHeader)); //This is a FileHandle
            FileOffSet := Pointer(P) + SizeOf(TSFTPPacketHeader) + Length(Res) + SizeOf(DWord);
            ContentLengthPtr := Pointer(FileOffSet) + SizeOf(Int64);
            Content := Pointer(FileOffSet) + SizeOf(Int64) + SizeOf(DWord);

            FileOffSetA := htonl(FileOffset^);
            ContentLength := htonl(ContentLengthPtr^);

            WriteLog(log_Debug, ServerName, ' SSH_FXP_WRITE Res:' + Res + ' Len:' + IntToStr(ContentLength) + ' Offset:' + IntToStr(FileOffsetA));

            Resource := Connection.Resources.FindByResourceID(Res);
            if Resource <> nil then
              begin
                WriteLog(log_Debug, ServerName, ' Connection.WriteFile Len:' + IntToStr(ContentLength) + ' Content:' + Copy(StrPas(Content), 1, 5));
                Connection.WriteFileContent(Resource, Content, FileOffsetA, ContentLength );

                Connection.PacketInit(SSH_FXP_STATUS, P^.RequestID);
                Connection.SendBytes(SSH_FX_OK); //Status code
                Connection.SendBytes('0b'); //Error Message
                Connection.SendBytes(''); //Error-specfic data
                Connection.PacketPost(Channel);

              end;
          end

        else
          WriteLog(log_Debug, ServerName, '  Pkt (Unknown): ' + IntToStr(P^.PacketType));
        end;

      Connection.OffSet := Connection.OffSet + htonl(P^.Len) + 4;

      if Connection.OffSet > Len then
        //Buffer overrun (Bad Client data)
        Break;

      if P^.Len = 0 then
        //Invalid packet format. This would be an infinite loop unless we break
        Break;

    end;

  WriteLog(log_Debug, ServerName, '  PacketsRead: ' + IntToStr(PacketsRead));

  Result := SSH_Ok;
end;

procedure OnChannelEof(Session: PLIBSSHSESSION; Channel: PSSHChannel; UserData: Pointer); cdecl;
var
  Connection: TConnection;
begin
  Connection := GetConnection(UserData, Session);

  WriteLog(log_Debug, ServerName, ' OnChannelEOF');

  if Connection <> nil then
    Connection.Disconnect;
end;

function OnChannelExec(Session: PLIBSSHSESSION; Channel: PSSHChannel; Command: PChar; UserData: Pointer): TLIBSSH_API; cdecl;
begin

  WriteLog(log_Debug, ServerName, ' OnChannelExec Command:' + Command);

  Result := SSH_Ok; //FileZilla passed a lot of weird stufff here. Maybe it was trying to launch the SFTP subsystem?

end;

//procedure OnChannelPtyRequest(Session: PLIBSSHSESSION; Channel: PSSHChannel; Term: PChar; Width: Integer; Height: Integer; pxWidth: Integer; pwHeight: Integer; UserData: Pointer); cdecl;
//var
//  Connection: TConnection;
//begin
//  Connection := GetConnection(UserData, Session);
//
//  WriteLog(log_Debug, ServerName, ' OnChannelPtyRequest Connection:' + IntToStr(Int64(Connection)));
//
//end;

function OnChannelSubsystemRequest(Session: PLIBSSHSESSION; Channel: PSSHChannel; SubSystem: PChar; UserData: Pointer): DWord; cdecl;
begin
  if LowerCase(SubSystem) = 'sftp' then
    Result := SSH_Ok
  else
    Result := 1; //1=Denied. We only allow SFTP requests
end;

function OnChannelWrite(Session: PLIBSSHSESSION; Channel: PSSHChannel; BytesLeftInThisWindow: Integer; UserData: Pointer): DWord; cdecl;
var
  //Buffer: Pointer;
  //BufferLen: Integer;
  Connection: TConnection;
  C, I: Integer;
  //CountOfPacketsSent
  //DataLen: Integer;
  P: PSFTPPacketHeader;

  PacketBodyLength: DWord;
  PacketIndex: Integer;
  TotalBytesPending: DWord;
  yBuffer: Pointer;
  AmountToSend: Integer;

begin

  Result := SSH_Ok;

  Connection := GetConnection(UserData, Session);

  //WriteLog(log_DebugX, ServerName, ' OnChannelWrite Connection:' + IntToStr(Int64(Connection)));

  if Connection = nil then //This is a problem
    begin
      Result := SSH_Ok;
      Exit;
    end;

  Connection.LastActivity := GetTickCount64;

  if Connection.xBuffer <> nil then
    begin
      yBuffer := Pointer(Connection.xBuffer) + Connection.xBufferUsed;
      AmountToSend := Connection.xBufferLen - Connection.xBufferUsed;
      if AmountToSend > $4000-13 then
        AmountToSend := $4000-13;
      C := ssh_channel_write(Channel, yBuffer, AmountToSend);
      if C > -1 then
        begin
          Connection.xBufferUsed := Connection.xBufferUsed + C;
          if Connection.xBufferUsed >= Connection.xBufferLen then
            begin
              FreeMem(Connection.xBuffer, Connection.xBufferLen);
              Connection.xBuffer := nil;
              Connection.InBlockingWriteOperation := False;
            end;
        end;
      WriteLog(log_Debug, ServerName, '  Packets Sent X Bytes-Delivered:' + IntToStr(C) + ' Pending:' + IntToStr(Connection.PendingData.Count));
      Exit;
    end;

  Connection.InBlockingWriteOperation := False;

  Connection.LastPendingPacketCount := Connection.PendingData.Count;
  if Connection.PendingData.Count = 0 then
    Exit;

  //Figure out how much PendingData bytes are sitting around
  TotalBytesPending := 0;
  PacketIndex := 0;
  for I := 0 to Connection.PendingData.Count - 1 do
    begin
      P := Connection.PendingData[I];
      PacketBodyLength := htonl(P^.Len) - 1 - SizeOf(DWord);

      if TotalBytesPending + SizeOf(TSFTPPacketHeader) + PacketBodyLength > BytesLeftInThisWindow then
        Break;

      TotalBytesPending :=  TotalBytesPending + SizeOf(TSFTPPacketHeader) + PacketBodyLength;
      PacketIndex := I;
    end;

  //Allocate a send buffer to unify all available packets
  GetMem(Connection.xBuffer, TotalBytesPending);
  yBuffer := Connection.xBuffer;

  for I := 0 to PacketIndex do
    begin
      P := Connection.PendingData[I];
      PacketBodyLength := htonl(P^.Len) - 1 - SizeOf(DWord);
      Move(P^, yBuffer^, SizeOf(TSFTPPacketHeader) + PacketBodyLength);
      yBuffer := Pointer(yBuffer) + SizeOf(TSFTPPacketHeader) + PacketBodyLength;
    end;

  if TotalBytesPending < $4000-13 then
    begin
      C := ssh_channel_write(Channel, Connection.xBuffer, TotalBytesPending);
      FreeMem(Connection.xBuffer, TotalBytesPending);
      Connection.xBuffer := nil;
    end
  else
    begin
      C := ssh_channel_write(Channel, Connection.xBuffer, $4000-13);
      Connection.xBufferLen := TotalBytesPending;
      Connection.xBufferUsed := $4000-13;
    end;


  //Send
  //C := ssh_channel_write(Channel, xBuffer, TotalBytesPending);

  if C > -1 then
    for I := PacketIndex downto 0 do
      Connection.PendingData.Delete(I);

  //WriteLog(log_Debug, ServerName, 'Packets Sent:' + IntToStr(CountOfPacketsSent) +  ' Buffer-Generated:' + IntToStr(BufferLen) +  ' Bytes-Delivered:' + IntToStr(C));
  //WriteLog(log_Debug, ServerName, 'Packets Sent:' + IntToStr(CountOfPacketsSent) +  ' Buffer-Generated:' + IntToStr(DataLen) +  ' Bytes-Delivered:' + IntToStr(C) + ' Pending:' + IntToStr(Connection.PendingData.Count));
  WriteLog(log_Debug, ServerName, '  Packets Sent:' + IntToStr(PacketIndex) +  ' Buffer-Generated:' + IntToStr(TotalBytesPending) +  ' Bytes-Delivered:' + IntToStr(C) + ' Pending:' + IntToStr(Connection.PendingData.Count));
  //if C = -1 then
  //  WriteLog(log_Debug, ServerName, '  Error: ' + ssh_get_error(Int64(Connection.Session)));

end;

function cbAuthUserPassword(Session: PLIBSSHSESSION; Username: PChar; Password: PChar; UserData: Pointer): Integer; cdecl;
var
  Connection: TConnection;
begin
  Connection := TConnection(UserData);
  Result := Connection.Authorize(Username, Password);
  Sleep(Random(3000));
  if Result = SSH_OK then
    begin
      Connection.LastActivity := GetTickCount64;
      Connection.fAuthorized := True;
    end;
end;

var
  //Global... Crashes if this is a local variable (But ServerCallbacks works either way)
  //  This is documented in LibSSH under https://api.libssh.org/stable/group__libssh__callbacks.html#gacea52d1373970a4922bf60e6b1680919
  ChannelCallbacks: TChannelCallbacks;

function cbNewChannel(Session: PLIBSSHSESSION; UserData: Pointer): PSSHChannel; cdecl;
var
  Rc: Integer;
  Connection: TConnection;
begin

  Result := ssh_channel_new(session);

  Connection := GetConnection(UserData, Session);
  if Connection <> nil then
    Connection.ActiveChannel := Result;

  WriteLog(log_Debug, ServerName, 'cbNewChannel');

  FillChar(ChannelCallbacks{%H-}, Sizeof(TChannelCallbacks), 0);
  ChannelCallbacks.Size := Sizeof(TChannelCallbacks);
  ChannelCallbacks.channel_close_function := @OnChannelClose;
  ChannelCallbacks.channel_eof_function := @OnChannelEof;
  ChannelCallbacks.channel_exec_request_function := @OnChannelExec; //This isn't really used
  ChannelCallbacks.channel_data_function := @OnChannelData; //New data from client triggers our function to parse it
  //ChannelCallbacks.channel_pty_request_function := @OnChannelPtyRequest;
  ChannelCallbacks.channel_subsystem_request_function := @OnChannelSubsystemRequest; //Satisfy client that we have SFTP capability (Not clear to me what else they arrived here to find)
  ChannelCallbacks.channel_write_wontblock_function := @OnChannelWrite; //Sending data now no longer blocks
  Rc := ssh_set_channel_callbacks(Result, ChannelCallbacks);

  if Rc <> SSH_OK then
    WriteLog(log_Info, ServerName, 'New Channel Callback Error: ' + IntToStr(Rc));

  ssh_blocking_flush(Session, 1000);

end;

function ServerThread(Param: Pointer): {$IFDEF Win64}Int64{$ELSE}Integer{$ENDIF};
var
  Connection: TConnection;
  Ev: array[0..20] of THandle;
  EvCount: Integer;
  Event: PSSHEvent;
  Finished: Boolean;
  MyServerIndex: Integer;
  W: DWord;

  procedure ScanForAvailableConnections;
  var
    FoundAWaitingClientConnection: Boolean;
    I: Integer;
  begin
    FoundAWaitingClientConnection := False;
    for I := 0 to Connections.Count - 1 do
      if TConnection(Connections[I]).ServerIndex = -1 then
        begin

          FoundAWaitingClientConnection := True;

          ServerThreads[MyServerIndex].Busy := True;
          Connection := TConnection(Connections[I]);
          Connection.ServerIndex := MyServerIndex;
          Connection.LastActivity := GetTickCount64;

          Event := ssh_event_new();
          ssh_event_add_session(Event, Connection.Session);

          WriteLog(log_Info, ServerName, 'Attached to waiting client. Idx: ' + IntToStr(I));

          Break;
        end;

    //if there were no waiting clients, that means everything's been gobbled up, so tell the other servers they can stop searching for clients (for now)
    if not FoundAWaitingClientConnection then
      ResetEvent(hConnectionAvailable);

  end;

begin
  Result := 0;

  MyServerIndex := PInteger(Param)^;
  ServerName := 'TH' + Format('%0.3d', [MyServerIndex]);

  Ev[0] := hCloseEverything;
  Ev[1] := hConnectionAvailable; //This must always be last so "Idle" can capture it

  try

  Connection := nil;
  Finished := False;
  while not Finished do
    begin

      if Connection <> nil then
        begin

          //WriteLog(log_Debug, ServerName, ' POLL ');

          ssh_event_dopoll(Event, 5000);

          //On Disconnect, Connection.Free, Remove from list, Idle -> False
          if not Connection.Connected then
            begin
              WriteLog(log_Info, ServerName, 'Detached client. Enter Wait mode');
              EnterCriticalSection(FTPCriticalSection);
              Connections.Delete(Connections.IndexOf(Connection));
              LeaveCriticalSection(FTPCriticalSection);
              Connection.Free;
              Connection := nil;
              ServerThreads[MyServerIndex].Busy := False;
            end;

          if (Connection <> nil) and (GetTickCount64 - Connection.LastActivity > MAX_IDLE_TIME_MS) then
            begin
              if Connection.ActiveChannel <> nil then
                begin
                  ssh_channel_send_eof(Connection.ActiveChannel);
                  ssh_channel_close(Connection.ActiveChannel);
                  Sleep(1000);
                end;
              ssh_disconnect(Connection.Session); //No disconnect?
              ssh_free(Connection.Session);

              WriteLog(log_Info, ServerName, 'Exceeded MAX_IDLE');
              EnterCriticalSection(FTPCriticalSection);
              Connections.Delete(Connections.IndexOf(Connection));
              LeaveCriticalSection(FTPCriticalSection);
              Connection.Free;
              Connection := nil;
              ServerThreads[MyServerIndex].Busy := False;;
            end;

        end;

      EvCount := 1;
      if not ServerThreads[MyServerIndex].Busy then
        Inc(EvCount);

      W := MsgWaitForMultipleObjects(EvCount, Ev, False, 1000, 0);

      if W = WAIT_OBJECT_0 then
        Finished := True;

      if W = WAIT_OBJECT_0 + 1 then
        begin
          EnterCriticalSection(FTPCriticalSection);
          ScanForAvailableConnections;
          LeaveCriticalSection(FTPCriticalSection);
        end;

    end;

  WriteLog(log_Info, ServerName, 'EndThread');

  except
    on E: Exception do
      begin
         WriteLog(log_Info, ServerName, 'Exception: ' + E.Message);
         raise;
      end;
  end;

  EndThread(0);
end;

end.

