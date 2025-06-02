unit uLoggingUtils;

//ChildProcess only. Not for use by Supervisor Process

interface

uses
  Classes, SysUtils;

type
  TLogLevel = (log_Debug, log_Info, log_Warn, log_Critical, log_None);

var
  //CurrentLogLevel: TLogLevel = log_Info;
  CurrentLogLevel: TLogLevel = log_Debug;

  procedure InitLogging;
  procedure WriteLog(LogLevel: TLogLevel; Identifier: String; Content: String);

implementation

var
  LogFile: Text;
  LogFolder: String;
  LogInitialized: Boolean = False;

procedure InitLogging;
var
  Ms: String;
  Y, M, D: Word;
begin

  if LogInitialized then Exit;
  LogInitialized := True;
  if CurrentLogLevel = log_None then Exit;

  LogFolder := ExtractFilePath(ParamStr(0));

  if not DirectoryExists(LogFolder + 'Logs') then
    CreateDir(LogFolder + 'Logs');
  LogFolder := LogFolder + 'Logs';

  DecodeDate(Now, Y, M, D);

  if not DirectoryExists(LogFolder + '\' + IntToStr(Y)) then
    CreateDir(LogFolder + '\' + IntToStr(Y));
  LogFolder := LogFolder + '\' + IntToStr(Y);

  Ms := IntToStr(M);
  if Length(Ms) = 1 then Ms := '0' + Ms;

  if not DirectoryExists(LogFolder + '\' + Ms) then
    CreateDir(LogFolder + '\' + Ms);
  LogFolder := LogFolder + '\' + Ms;

  AssignFile(LogFile, LogFolder + '\SFTPLog_' + FormatDateTime('yyyymmdd', Now) + '.txt');
  {$I-}
  Append(LogFile);
  if IOResult <> 0 then
    Rewrite(LogFile);
  {$I-}

end;

function LogLevelToShort(LogLevel: TLogLevel): String;
begin
  case LogLevel of
    log_Debug: Result := 'DBUG';
    log_Info: Result := 'INFO';
    log_Warn: Result := 'WARN';
    log_Critical: Result := 'CRIT';
    log_None: Result := 'NONE';
  end;
end;

var
  LC: Integer;

procedure WriteLog(LogLevel: TLogLevel; Identifier: String; Content: String);
begin
  Inc(Lc); if LC > 100000 then Exit;  //To-Do: Remove this infinite log cap
  //if CurrentLogLevel > LogLevel then Exit;
  while Length(Identifier) < 5 do Identifier := ' ' + Identifier;
  Writeln(LogFile,
    FormatDateTime('yyyy-mm-dd hh:nn:ss', Now), #9,
    '[', LogLevelToShort(LogLevel), ']', #9,
    Identifier, #9,
    Content);
  Flush(LogFile); //Send right away to avoid log-loss in event of process crash
end;

finalization
  if LogInitialized and (CurrentLogLevel <> log_None) then
    CloseFile(LogFile);

end.

