unit uSupervisorProcess;

//My job is to make sure a ChildProcess is always active
//If the ChildProcess crashes, it's my job to restart it

interface

uses
  Classes, SysUtils, Windows, DateUtils, uServerConstants;

  procedure InstallAsAService;
  procedure Supervisor(ArgI: LongWord; ArgS: LPPSTR); stdcall;

const
  ServiceTable: array[0..1] of TServiceTableEntry = (
    (lpServiceName: 'FPC-SFTP'; lpServiceProc: @Supervisor),
    (lpServiceName: nil; lpServiceProc: nil)
  );

implementation

var
  Finished: Boolean = False;
  hChildProcessID: THandle = 0;
  hServiceID: SERVICE_STATUS_HANDLE;
  NeedTimedReset: Boolean = False;

procedure ForkChildProcess;
var
  PI: TProcessInformation;
  Sec: TSecurityAttributes;
  StartUpInfo: TStartUpInfo;
begin
  ResetEvent(hCloseEverything);
  ResetEvent(hTimedReset);
  FillChar(Sec{%H-}, SizeOf(TSecurityAttributes), 0);
  Sec.nLength := SizeOf(TSecurityAttributes);
  Sec.bInheritHandle := True;
  FillChar(StartUpInfo{%H-}, SizeOf(TStartUpInfo), 0);
  StartUpInfo.cb := SizeOf(TStartUpInfo);

  CreateProcess(nil, PChar(ParamStr(0) + ' /child_process'), @Sec, nil, True, 0, nil, nil, StartUpInfo, PI{%H-});
  hChildProcessID := PI.hThread;
  NeedTimedReset := False;
end;

procedure InstallAsAService;
var
  PI: TProcessInformation;
  Sec: TSecurityAttributes;
  StartUpInfo: TStartUpInfo;
begin
  ResetEvent(hCloseEverything);
  ResetEvent(hTimedReset);
  FillChar(Sec{%H-}, SizeOf(TSecurityAttributes), 0);
  Sec.nLength := SizeOf(TSecurityAttributes);
  Sec.bInheritHandle := True;
  FillChar(StartUpInfo{%H-}, SizeOf(TStartUpInfo), 0);
  StartUpInfo.cb := SizeOf(TStartUpInfo);

  if CreateProcess(nil, PChar('sc.exe create fpcsftp binpath= "' + ParamStr(0) + '" displayname="fpc-sftp"'), @Sec, nil, True, 0, nil, nil, StartUpInfo, PI{%H-}) then
    Writeln('Service created')
  else
    Writeln('sc-Create failed. Error: ', GetLastError);

end;

function ServiceHandler(fdwControl: LongWord): LongBool; stdcall;
var
  ServiceStatus: TServiceStatus;
begin

  Result := True;

  ServiceStatus.dwServiceType := SERVICE_WIN32; //Place holder to hide error message

  FillChar(ServiceStatus, SizeOf(TServiceStatus), 0);
  ServiceStatus.dwServiceType := SERVICE_WIN32_OWN_PROCESS;
  ServiceStatus.dwCurrentState := SERVICE_RUNNING;
  ServiceStatus.dwControlsAccepted := SERVICE_ACCEPT_STOP or SERVICE_ACCEPT_SHUTDOWN;
  ServiceStatus.dwWin32ExitCode := No_Error;
  ServiceStatus.dwServiceSpecificExitCode := 0;
  case fdwControl of
    SERVICE_CONTROL_INTERROGATE:
      begin
        if Finished then
          ServiceStatus.dwCurrentState := SERVICE_STOPPED
        else
          ServiceStatus.dwCurrentState := SERVICE_RUNNING;
        SetServiceStatus(hServiceID, ServiceStatus);
      end;
    SERVICE_CONTROL_SHUTDOWN:
      begin
        Finished := True;
        SetEvent(hCloseEverything);
        ServiceStatus.dwCurrentState := SERVICE_STOPPED;
        SetServiceStatus(hServiceID, ServiceStatus);
      end;
    SERVICE_CONTROL_STOP:
      begin
        Finished := True;
        SetEvent(hCloseEverything);
        Sleep(100);
        ServiceStatus.dwCurrentState := SERVICE_STOPPED;
        SetServiceStatus(hServiceID, ServiceStatus);
      end;
  end;
end;

procedure Supervisor(ArgI: LongWord; ArgS: LPPSTR); stdcall;
var
  Ev: array[0..4] of THandle;
  ServiceStatus: TServiceStatus;
  TimedResetStartTime: TDateTime;
  Today: Integer;
begin

  hServiceID := RegisterServiceCtrlHandler(PChar('FPC-SFTP' ), @ServiceHandler);

  FillChar(ServiceStatus{%H-}, SizeOf(TServiceStatus), 0);
  ServiceStatus.dwServiceType := SERVICE_WIN32;
  ServiceStatus.dwServiceType := SERVICE_WIN32_OWN_PROCESS;
  ServiceStatus.dwCurrentState := SERVICE_START_PENDING;
  ServiceStatus.dwControlsAccepted := SERVICE_ACCEPT_STOP or SERVICE_ACCEPT_SHUTDOWN;
  ServiceStatus.dwCurrentState := SERVICE_RUNNING;
  SetServiceStatus(hServiceID, ServiceStatus);

  SetThreadPriority(GetCurrentThread, THREAD_PRIORITY_LOWEST);

  Today := Round(Int(Now));
  ForkChildProcess;

  Ev[0] := hChildProcessID;
  Finished := False;
  while not Finished do
    begin

      if MsgWaitForMultipleObjects(1, Ev, False, 1000, 0) = WAIT_OBJECT_0 + 0 then
        begin
          Sleep(3000);
          ForkChildProcess;
          Ev[0] := hChildProcessID;
        end;

      if Today <> Round(Int(Now)) then
        begin
          Today := Round(Int(Now));
          TimedResetStartTime := Now;
          SetEvent(hTimedReset);
          NeedTimedReset := True;
          Sleep(3000); //Wait to complete client activities
        end;

      if NeedTimedReset and (MinutesBetween(Now, TimedResetStartTime) > 2) then
        begin
          SetEvent(hCloseEverything);
          NeedTimedReset := False;
          Sleep(3000);
        end;

    end;

  SetEvent(hCloseEverything);

  ServiceStatus.dwCurrentState := SERVICE_Stopped;
  ServiceStatus.dwWin32ExitCode := No_Error;
  ServiceStatus.dwServiceSpecificExitCode := 0;
  SetServiceStatus(hServiceID, ServiceStatus);

end;

end.

