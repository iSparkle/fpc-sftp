program Simple_SFTP_Server;

//https://github.com/iSparkle/fpc-sftp

//Req:
//ssh.dll
//libcrypto-3-x64.dll
//zlib.dll

uses
  Classes, SysUtils,
  Winsock, libssh;

type
  TPacketDataList = class(TList)
    public
      procedure Delete(Index: Integer);
  end;

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

var
  PendingData: TPacketDataList;
  UserDataBuffer: array[0..400] of Integer;
  LastPendingPacketCount: Integer = -1;
  InBlockingWriteOperation: Boolean = False;

procedure SendSFTPData(Channel: PSSHChannel; PacketType: Byte; RequestID: DWord; Data: Pointer; DataLen: DWord);
var
  P: PSFTPPacketHeader;
  N: Pointer;
  C: Integer;
begin
  GetMem(P, SizeOf(TSFTPPacketHeader) + DataLen);
  P^.PacketType := PacketType;
  P^.RequestID := RequestID;
  P^.Len := htonl(DataLen + 1 + SizeOf(DWord)); //Len = PacketType + RequestID + DataLen

  if Data <> nil then
    begin
      N := Pointer(P) + SizeOf(TSFTPPacketHeader);
      Move(Data^, N^, DataLen);
    end;

  //This should not be needed, but if the server seems to randomly time out, this is a good way to "poke" activity
  if (LastPendingPacketCount = 0) and not InBlockingWriteOperation then
    begin
      C := ssh_channel_write(Channel, P, SizeOf(TSFTPPacketHeader) + DataLen);
      if C > 0 then
        begin
          InBlockingWriteOperation := True;
          FreeMem(P, SizeOf(TSFTPPacketHeader) + DataLen);
          Exit; //Since we successfully poked the data across to the client we exit here. We do NOT add to Pending
        end;
    end;

  PendingData.Add(P)

end;

procedure SendSFTPData(Channel: PSSHChannel; PacketType: Byte; RequestID: DWord; Data: Integer);
begin
  Data := htonl(Data);
  SendSFTPData(Channel, PacketType, RequestID, @Data, SizeOf(Integer));
end;

procedure SendSFTPData(Channel: PSSHChannel; PacketType: Byte; RequestID: DWord; Data: String);
begin
  SendSFTPData(Channel, PacketType, RequestID, PChar(Data), Length(Data));
end;

type
  TFolderReadState = (frs_Init, frs_Complete);

var
  FolderReadState: TFolderReadState;
  OffSet: Integer; //Seems like LibSSH is resuookying the entire buffer on each OnChannelData callback. There's probably a call somewhere to clear it out

type
  TStatusBody = packed record
    StatusCode: DWord;
    ErrorData: array[0..1024] of Char;
  end;

function OnChannelData(Session: PLIBSSHSESSION; Channel: PSSHChannel; Data: Pointer; Len: DWord; is_stderr: Integer; UserData: Pointer): DWord; cdecl;
var
  P: PSFTPPacketHeader;
  Status: TStatusBody;
begin

  while OffSet < Len do
    begin
      P := Pointer(Data) + OffSet;

      case P^.PacketType of
        SSH_FXP_INIT:
          begin
            SendSFTPData(Channel, SSH_FXP_VERSION, htonl(3), nil, 0); //We're supposed to negotiate with the client, not send a flat v3
          end;
        SSH_FXP_REALPATH:
          begin
            SendSFTPData(Channel, SSH_FXP_NAME, P^.RequestID, #0#0#0#1 + #0#0#0#1 + '/' + #0#0#0#0 + chr(SSH_FILEXFER_TYPE_DIRECTORY) + #255);
          end;
        SSH_FXP_OPENDIR:
          begin
            FolderReadState := frs_Init;
            SendSFTPData(Channel, SSH_FXP_HANDLE, P^.RequestID, #0#0#0#3'123');
          end;
        SSH_FXP_CLOSE:
          begin
            Status.StatusCode := htonl(SSH_FX_OK);
            Status.ErrorData := #0#0#0#5'Close' + #0#0#0#0;
            SendSFTPData(Channel, SSH_FXP_STATUS, P^.RequestID, @Status, SizeOf(DWord) + 19);
          end;
        SSH_FXP_READDIR:
          begin

            case FolderReadState of
              frs_Init:
                begin

                  //Hard-coding two folders + 1 file. To-Do: Find the simplest way to make a packet-forming function
                  //  This code was designed to show using LibSSL's undocumented functions, not a study of SSH
                  SendSFTPData(Channel, SSH_FXP_NAME, P^.RequestID, #0#0#0#3 +

                    #0#0#0#01 + '.'            + #0#0#0#57 + 'dr-xr-x---    7 root     root          236 Jun 14  2023 .' +
                    #0#0#0#15 + #0#0#0#0#0#0#0#236 + #0#0#0#0#0#0#0#0#0#0#65#104#103#190#159#211#100#138#028#011 +

                    #0#0#0#02 + '..'           + #0#0#0#58 + 'dr-xr-xr-x   17 root     root          244 Dec  6  2019 ..' +
                    #0#0#0#15 + #0#0#0#0#0#0#0#244 + #0#0#0#0#0#0#0#0#0#0#65#109#103#190#159#208#093#234#147#144 +

                    #0#0#0#12 + 'test file 01' + #0#0#0#58 + 'D-rw-r--r--    1 root     root           18 Dec 28  2013 test file 01' +
                    #0#0#0#15 + #0#0#0#0#0#0#0#18 +  #0#0#0#0#0#0#0#0#0#0#129#128#103#190#159#211#100#138#028#011
                  );

                  FolderReadState := frs_Complete;
                end;
              frs_Complete:
                begin
                  Status.StatusCode := htonl(SSH_FX_EOF);
                  Status.ErrorData := #0#0#0#11'End of file' + #0#0#0#0;
                  SendSFTPData(Channel, SSH_FXP_STATUS, P^.RequestID, @Status, SizeOf(DWord) + 19);
                end;
            end;

          end;
        end;

      OffSet := OffSet + htonl(P^.Len) + 4;

      if OffSet > Len then
        //Buffer overrun (Bad Client data)
        Break;

      if P^.Len = 0 then
        //Invalid packet format. This would be an infinite loop unless we break
        Break;

    end;

  Result := SSH_Ok;
end;


function OnChannelExec(Session: PLIBSSHSESSION; Channel: PSSHChannel; Command: PChar; UserData: Pointer): TLIBSSH_API; cdecl;
begin
  Result := SSH_Ok; //Filezilla passed a lot of weird stufff here. Maybe it was trying to launch the SFTP subsystem?
end;

function OnChannelSubsystemRequest(Session: PLIBSSHSESSION; Channel: PSSHChannel; SubSystem: PChar; UserData: Pointer): DWord; cdecl;
begin
  if LowerCase(SubSystem) = 'sftp' then
    Result := SSH_Ok
  else
    Result := 1; //1=Denied. We only allow SFTP requests
end;

var
  WriteBuffer: array[0..$FFFF] of Byte;

function OnChannelWrite(Session: PLIBSSHSESSION; Channel: PSSHChannel; BytesLeftInThisWindow: Integer; UserData: Pointer): DWord; cdecl;
var
  Buffer: Pointer;
  BufferLen: Integer;
  CountOfPacketsSent, C, I: Integer;
  DataLen: Integer;
  P: PSFTPPacketHeader;
begin

  Result := SSH_Ok;
  InBlockingWriteOperation := False;

  LastPendingPacketCount := PendingData.Count;
  if PendingData.Count = 0 then
    Exit;

  Buffer := @WriteBuffer;
  BufferLen := 0;
  CountOfPacketsSent := 0;

  while (BytesLeftInThisWindow > 0) and (CountOfPacketsSent < PendingData.Count) do
    begin

      P := PendingData[CountOfPacketsSent];
      DataLen := htonl(P^.Len) - 1 - SizeOf(DWord);
      BytesLeftInThisWindow := BytesLeftInThisWindow - (SizeOf(TSFTPPacketHeader) + DataLen);
      if BytesLeftInThisWindow < 0 then Break;

      Move(P^, Buffer^, SizeOf(TSFTPPacketHeader) + DataLen);
      Buffer := Pointer(Buffer) + SizeOf(TSFTPPacketHeader) + DataLen;
      BufferLen := BufferLen + SizeOf(TSFTPPacketHeader) + DataLen;

      Inc(CountOfPacketsSent);

    end;

  C := 0;
  if BufferLen > 0 then
    begin
      C := ssh_channel_write(Channel, @WriteBuffer, BufferLen);

      if C > -1 then
        for I := CountOfPacketsSent - 1 downto 0 do
          PendingData.Delete(I);

    end;

  //Debug Writeln('Packets Sent: ', CountOfPacketsSent, ' Buffer-Generated: ', BufferLen, ' Bytes-Delivered: ', C);

end;

var
  ChannelCallbacks: TChannelCallbacks;

function cbAuthUserPassword(Session: PLIBSSHSESSION; Username: PChar; Password: PChar; UserData: Pointer): Integer; cdecl;
begin
  Writeln('#User: ', Username);
  Writeln('#Pass: ', Password);
  Result:= SSH_AUTH_SUCCESS; //Let any user in!
end;

function cbNewChannel(Session: PLIBSSHSESSION; UserData: Pointer): PSSHChannel; cdecl;
var
  Rc: Integer;
begin

  Result := ssh_channel_new(session);

  FillChar(ChannelCallbacks, Sizeof(TChannelCallbacks), 0);
  ChannelCallbacks.Size := Sizeof(TChannelCallbacks);
  ChannelCallbacks.channel_exec_request_function := @OnChannelExec; //This isn't really used
  ChannelCallbacks.channel_data_function := @OnChannelData; //New data from client triggers our function to parse it
  ChannelCallbacks.channel_subsystem_request_function := @OnChannelSubsystemRequest; //Satisfay client that we have SFTP capability (Not clear to me what else they arrived here to find)
  ChannelCallbacks.channel_write_wontblock_function := @OnChannelWrite; //Sending data now no longer blocks which is a horrible mess for a single-thread server. SFTP activities  are ASYNC! A read and a write may collide!
  Rc := ssh_set_channel_callbacks(Result, ChannelCallbacks);

  if Rc <> SSH_OK then
    Writeln('  New Channel Callback Error: ', Rc);

  ssh_blocking_flush(Session, 1000);

end;

procedure Main;
var
  Cb: TServerCallbacks;
  Event: PSSHEvent;
  Rc: Integer;
  Session: PLIBSSHSESSION;
  SshBind: TLIBSSH_API;
begin

  PendingData := TPacketDataList.Create;

  Rc := ssh_init();
  if Rc <> SSH_OK then
    Writeln('  Initialization Error: ', Rc);

  SshBind := ssh_bind_new();

  //Debug
  //Rc := SSH_LOG_WARNING;
  //ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, @Rc);

  Rc := ssh_bind_options_set(SShBind, SSH_BIND_OPTIONS_BINDADDR, PChar('0.0.0.0'));
  if Rc <> SSH_OK then
    Writeln('  Set Addr Error: ', ssh_get_error(SShBind));

  Rc := 22; //Default SFTP port
  Rc := ssh_bind_options_set(SShBind, SSH_BIND_OPTIONS_BINDPORT, @Rc);
  if Rc <> SSH_OK then
    Writeln('  Set Port Error: ', ssh_get_error(SShBind));

  Rc := ssh_bind_options_set(SshBind, SSH_BIND_OPTIONS_RSAKEY, PChar('my_server_private_key.key'));
  if Rc <> SSH_OK then
    Writeln('  Set RSA Error: ', ssh_get_error(SShBind));

  Rc := ssh_bind_listen(SshBind);
  if Rc <> SSH_OK then
    Writeln('  Listen Error: ', ssh_get_error(SShBind));

  //ssh_callbacks_init(); //This is a macro, not a .dll function, so we can't simulate it in FPC

  FillChar(Cb{%H-}, Sizeof(TServerCallbacks), 0);
  Cb.Size := SizeOf(TServerCallbacks);
  Cb.UserData := @UserDataBuffer;
  Cb.auth_password_function := @cbAuthUserPassword;
  Cb.channel_open_request_session_function := @cbNewChannel;

  Writeln('Start Main Loop');
  while true do
    begin

      Session := ssh_new();
      if Session = nil then Continue;

      Rc := ssh_bind_accept(SshBind, Session);
      Writeln('#A new client connected');

      if Rc <> SSH_OK then
        begin
          Writeln('  Bind-Accept Error: ', ssh_get_error(SShBind));
          Break;
        end;

      Rc := ssh_handle_key_exchange(Session);
      if Rc <> SSH_OK then
        Writeln('  Key Exchange Error: ', ssh_get_error(SShBind));

      Rc := ssh_set_server_callbacks(Session, cb);
      if Rc <> SSH_OK then
        Writeln('  Set callbacks Error: ', ssh_get_error(SShBind));

      ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);

      Event := ssh_event_new();
      ssh_event_add_session(Event, session);

      while True do
        begin

          ssh_event_dopoll(Event, 1000);

        end;


      ssh_disconnect(Session);
      ssh_free(Session);

      while PendingData.Count > 0 do
        PendingData.Delete(0);


    end;

  ssh_bind_free(sshbind);
  //ssh_finalize();
  Writeln('End');

  PendingData.Free;
end;

begin

  Main;

end.

