unit uServerConstants;

interface

uses
  Classes, SysUtils, Windows;

const
  MAX_SERVER_THREAD = 30;
  MAX_IDLE_TIME_MS = 1000 * 60; //60 seconds? Boot that free-loadin' client

type
  TServerThreadInfo = record
    ThreadID: THandle;
    Busy: Boolean;
  end;
  TUserData = packed record
    Connection: TObject;
    Filler: array[1..396] of byte;
  end;

var
  FTPCriticalSection: TRTLCriticalSection;
  hCloseEverything: THandle;
  hConnectionAvailable: THandle;
  hTimedReset: THandle;
  ServerThreads: array[0..MAX_SERVER_THREAD-1] of TServerThreadInfo;
  UserData: TUserData;

implementation

initialization
  hCloseEverything := CreateEvent(nil, True, False, 'fpcSFTPCloseEverything');
  hConnectionAvailable := CreateEvent(nil, False, False, nil);
  hTimedReset := CreateEvent(nil, False, False, 'fpcSFTPTimedReset');
  FillChar(ServerThreads, SizeOf(TServerThreadInfo) * MAX_SERVER_THREAD, 0);
  InitializeCriticalSection(FTPCriticalSection);
finalization
  DeleteCriticalSection(FTPCriticalSection);
  CloseHandle(hTimedReset);
  CloseHandle(hConnectionAvailable);
  CloseHandle(hCloseEverything);

end.

