unit uChildProcess;

interface

uses
  Classes, SysUtils, Windows, libssh, uServerConstants, uServerProcs, uLoggingUtils, uServerThread;

  procedure RunAsChildProcess;

var
  TempRoot: String;

implementation

var
  CriticalFailure: Boolean = False; //Stop all connection processing and sleep until admin steps in
  Deadlock: Boolean;
  InKeyExchange: Int64;
  SshBind: TLIBSSH_API;
  SessionD: PLIBSSHSESSION; //Delegator's session

procedure CreateBinding;
var
  Rc: Integer;
begin

  SshBind := ssh_bind_new();

  Rc := ssh_bind_options_set(SShBind, SSH_BIND_OPTIONS_BINDADDR, PChar('0.0.0.0'));
  if Rc <> SSH_OK then
    WriteLog(log_Info, 'Child', 'Set Addr Error: ' + ssh_get_error(SShBind));

  Rc := 22;
  Rc := ssh_bind_options_set(SShBind, SSH_BIND_OPTIONS_BINDPORT, @Rc);
  if Rc <> SSH_OK then
    WriteLog(log_Info, 'Child', 'Set Port Error: ' + ssh_get_error(SShBind));

  Rc := ssh_bind_options_set(SshBind, SSH_BIND_OPTIONS_RSAKEY, PChar(TempRoot + '\RSA.key'));
  if Rc <> SSH_OK then
    begin
      WriteLog(log_Critical, 'Child', 'Set RSA Error: ' + ssh_get_error(SShBind));
      CriticalFailure := True; //This error will spam the logs if allowed to recur
    end;

  Rc := ssh_bind_listen(SshBind);
  if Rc <> SSH_OK then
    WriteLog(log_Info, 'Child', 'Listen Error: ' + ssh_get_error(SShBind));

  //Set LibSSH to Debug mode
  //Rc := SSH_LOG_FUNCTIONS;
  //ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, @Rc);

end;

//This thread does nothing but listen for new incoming connections and prepare them to be serviced by the next available ServerThread.
//If all ServerThreads are occupied, it creates a new ServerThread (up to MAX_SERVER_THREAD). Past this limit, new connections need to wait.
//This thread cannot close on its own when the service needs to shutdown because it blocks. The ChildProcess will need to force it closed.
//  (Tried using a ssh_bind_set_callbacks with the New-Connection callback but it never triggered. Could be a version issue. Polling may fix)
//  Ref: https://archive.libssh.org/libssh/2015-07/0000045.html
//  Ref: https://api.libssh.org/master/group__libssh__poll.html
function ConnectionDelegationThread(Param: Pointer): {$IFDEF Win64}Int64{$ELSE}Integer{$ENDIF};
var
  BusyServers, TotalServersInstantiated: Integer;
  Connection: TConnection;
  I, ReservedServerIndex: Integer;
  MustCreateNewServer: Boolean;
  Rc: Integer;
begin
  Result := 0;

  try

  while true do
    begin

      if CriticalFailure then
        begin
          Sleep(1000);
          Continue;
        end;

      DeadLock := False;

      SessionD := ssh_new();
      if SessionD = nil then
        ///??? What should we do here??
        WriteLog(log_Info, 'Main', 'Nil Session');

      Sleep(1000);
      CreateBinding;

      Rc := ssh_bind_accept(SshBind, SessionD);
      WriteLog(log_Info, 'Main', '#A new client connected');

      if Rc <> SSH_OK then
        begin
          WriteLog(log_Info, 'Main', 'Bind-Accept Error');// ssh_get_error(SShBind));
          ssh_disconnect(SessionD);
          ssh_free(SessionD);
          ssh_bind_free(sshbind);
          Continue;
        end;

      //This thread record's in-key-state so the external supervisor can hang up and break a deadlock
      //There needs to be a timeout of some sort so we don't need such squirrelly actions
      InKeyExchange := GetTickCount64;

      try
        Rc := ssh_handle_key_exchange(SessionD);
      except
        on E: Exception do
          WriteLog(log_Debug, 'Main', 'ssh_handle_key_exchange exception: ' + E.Message); //Typically it's an "Access Violation" if we land here
      end;

      InKeyExchange := 0;
      if DeadLock then
        begin
          Sleep(1000);
          Continue;
        end;

      if Rc <> SSH_OK then
        begin
          WriteLog(log_Info, 'Main', 'Key Exchange Error');
          ssh_disconnect(SessionD);
          ssh_free(SessionD);
          ssh_bind_free(sshbind);
          Continue;
        end;

      Connection := ConnectionClass.Create(SessionD);
      Connection.Initialize;
      Connection.ServerCallbacks.Size := SizeOf(TServerCallbacks);
      Connection.ServerCallbacks.UserData := Connection;
      Connection.ServerCallbacks.auth_password_function := @cbAuthUserPassword;
      Connection.ServerCallbacks.channel_open_request_session_function := @cbNewChannel;

      Rc := ssh_set_server_callbacks(SessionD, Connection.ServerCallbacks);
      if Rc <> SSH_OK then
        WriteLog(log_Info, 'Main', 'Set callbacks Error: ' + ssh_get_error(SShBind));

      ssh_set_auth_methods(SessionD, SSH_AUTH_METHOD_PASSWORD);

      //Do we need more ServerThreads?
      BusyServers := 0;
      TotalServersInstantiated := 0;
      ReservedServerIndex := -1;
      for I := 0 to MAX_SERVER_THREAD - 1 do
        begin
          if ServerThreads[I].ThreadID <> 0 then
            begin
              Inc(TotalServersInstantiated);
              if ServerThreads[I].Busy then
                Inc(BusyServers);
            end
          else if ReservedServerIndex = -1 then
            ReservedServerIndex := I;
        end;

      MustCreateNewServer := False;
      if BusyServers = TotalServersInstantiated then
        begin
          if TotalServersInstantiated < MAX_SERVER_THREAD then
            MustCreateNewServer := True;
        end;

      if MustCreateNewServer then
        begin
          WriteLog(log_Info, 'Main', 'Spin up new server thread ' + IntToStr(ReservedServerIndex));
          ServerThreads[ReservedServerIndex].ThreadID := BeginThread(@ServerThread, @ReservedServerIndex, ThreadID);
          Sleep(250); //Give new thread a split second to hit the floor running
        end
      else
        WriteLog(log_Info, 'Main', 'Submit to server thread queue');

      EnterCriticalSection(FTPCriticalSection);
      Connections.Add(Connection); //This add() is all the way down here so a random (idle) server doesn't try to start before everything is ready with this connection
      LeaveCriticalSection(FTPCriticalSection);

      SetEvent(hConnectionAvailable);

      //Remove socket binding, which allows us to restart the
      //parent process, without terminating existing sessions.
      Sleep(2000);
      ssh_bind_free(sshbind);
      sshbind := 0;

    end;

  except
    on E: Exception do
      begin
         WriteLog(log_Info, 'cdt', 'Collection Delegate Thread Exception: ' + E.Message);
         raise;
      end;
  end;

  EndThread(0);
end;

procedure RunAsChildProcess;
var
  Ev: array[0..20] of THandle;
  Finished: Boolean;
  hDelegatorThreadID: THandle;
  W: DWord;
begin

  InitLogging;

  Connections := TConnections.Create;

  hDelegatorThreadID := BeginThread(@ConnectionDelegationThread, nil, ThreadID);

  Ev[0] := hCloseEverything;

  Finished := False;
  while not Finished do
    begin

      W := MsgWaitForMultipleObjects(1, Ev, False, 6000, 0);

      if W = WAIT_OBJECT_0 then
        Finished := True;

      //This is for stopping the client when you run it directly at command prompt
      if FileExists(TempRoot + '\Stop.txt') then
        begin
          SetEvent(hCloseEverything);
          DeleteFile(PChar(TempRoot + '\Stop.txt'));
        end;

      if not Finished and (InKeyExchange > 0) and (GetTickCount64 - InKeyExchange > 6000) then
        begin
          InKeyExchange := 0;
          WriteLog(log_Info, 'Child', 'Deadlock conditions detected');

          Deadlock := True;
          ssh_disconnect(SessionD);
          ssh_free(SessionD);
          ssh_bind_free(sshbind);

        end;

    end;

  TerminateThread(hDelegatorThreadID, 0);

  if sshbind <> 0 then
    ssh_bind_free(sshbind);

  Sleep(5000); //Wait for Servers to spot the shutdown
  Connections.Free;

end;

end.

