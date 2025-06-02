program fpcSFTP;

uses
  Classes, SysUtils, Windows, libssh, uSupervisorProcess, uServerThread, uServerProcs, uServerConstants, uChildProcess;

type
  TMySTPConnection = class(TConnection)
    private
      VirtualRootFolder: TSFTPResource;
      ExampleSubFolder: TSFTPResource;
    protected
      procedure RenderRealPath(RealPathObject: TRealPathObject); override;
    public
      destructor Destroy; override;
      function  AllowOpenDir(Resource: TSFTPResource; Flags: DWord): Boolean; override;
      function  AllowOpenFile(Resource: TSFTPResource; Flags: DWord; IsTest: Boolean = False): Boolean; override;
      function  Authorize(Username, Password: String): Integer; override;
      procedure Initialize; override;
      function  ReadDir(Resource: TSFTPResource): DWord; override;
  end;


destructor TMySTPConnection.Destroy;
begin
  VirtualRootFolder.Free;
  ExampleSubFolder.Free;
  inherited Destroy;
end;

function TMySTPConnection.AllowOpenDir(Resource: TSFTPResource; Flags: DWord): Boolean;
begin

  //In this example: All Directories are automatically read, no write
  //Note that the SFTP spec does not indicate a "Flag" concept for directories. It is simulated here by OpenDir vs MKDir vs RMDir
  Result := True;

end;

function TMySTPConnection.AllowOpenFile(Resource: TSFTPResource; Flags: DWord; IsTest: Boolean = False): Boolean;
begin
  //Check the file systems for permission for this user to access Path
  //  You need to check your file system for read/write permission
  //  Do not worry about concurrency issues like two users accessing the same resource for write access. User #2 will be automatically denied (See Note 2)
  //  Ignore ResourceID. You may choose some internally meaningful value here for logging purposes, but if left empty, a sequential value will be asserted
  //  Note: A bad actor may arrive here without using RenderRealPath() so look out for the old ../../../system-folder trick
  //  Note: You may do your own check on flag SSH_FXF_EXCL since the code does not know what else may be going on outside of client access
  //  Note: If "IsTest" then go ahead and close the resource. We don't need it now, just testing if it is there and accessible

  //In this example: All files are automatically read/write
  Result := True;

  if Flags and SSH_FXF_CREAT > 0 then
    begin
      //if Path = VirtualRootFolder.PathPart then ?
    end;

end;

function TMySTPConnection.Authorize(Username, Password: String): Integer;
begin
  //Allow anyone except Leonardo
  //  Note: We should save some sort of identifier to the user for later when AllowOpenResource() is called
  if Username = 'Leonardo' then
    Result := SSH_AUTH_DENIED
  else
    Result := SSH_AUTH_SUCCESS;
end;

procedure TMySTPConnection.Initialize;
var
  R: TSFTPResourceEntry;
begin
  inherited Initialize;

  //This example creates two "virtual folders" with fixed contents (doesn't rely on native file system)

  VirtualRootFolder := TSFTPResource.Create;
  VirtualRootFolder.PathPart := '/';

  R := VirtualRootFolder.AddEntry(SSH_FILEXFER_TYPE_DIRECTORY, '.');
  R.Permissions := 'dr-xr-x---';
  R.FileSize := 236;
  R.LinkCount := 7;

  R := VirtualRootFolder.AddEntry(SSH_FILEXFER_TYPE_DIRECTORY, '..');
  R.Permissions := 'dr-xr-xr-x';
  R.FileSize := 244;
  R.LinkCount := 17;

  R := VirtualRootFolder.AddEntry(SSH_FILEXFER_TYPE_DIRECTORY, 'A subfolder');
  R.Permissions := 'dr-xr-x---';
  R.DateCreated := Now - 15;
  R.DateModified := Now - 5;
  R.FileSize := 1000;

  R := VirtualRootFolder.AddEntry(SSH_FILEXFER_TYPE_REGULAR, 'Test file D1.txt');
  R.Permissions := '-rw-r--r--'; // file owner permission to read and write, and the group and world permission read only
  R.DateCreated := Now - 2;
  R.DateModified := Now - 1;
  R.FileSize := 6123;

  ExampleSubFolder := TSFTPResource.Create;

end;

function TMySTPConnection.ReadDir(Resource: TSFTPResource): DWord;
var
  R: TSFTPResourceEntry;
begin

  if Resource.PathPart = '/' then //A virtual root folder
    if Resource.Entries.Count = 0 then
      Resource.Assign(VirtualRootFolder);

  if Resource.PathPart = '/A subfolder/' then //A virtual subfolder
    begin

      R := Resource.AddEntry(SSH_FILEXFER_TYPE_DIRECTORY, '.');
      R.Permissions := 'dr-xr-x---';
      R.FileSize := 236;
      R.LinkCount := 7;

      R := Resource.AddEntry(SSH_FILEXFER_TYPE_DIRECTORY, '..');
      R.Permissions := 'dr-xr-xr-x';
      R.FileSize := 244;
      R.LinkCount := 17;

      R := Resource.AddEntry(SSH_FILEXFER_TYPE_REGULAR, 'Test file 04.txt');
      R.Permissions := '-rw-r--r--';
      R.DateCreated := Now - 2;
      R.DateModified := Now - 1;
      R.FileSize := 4555;

    end;

  Result := SSH_FX_OK; //This will soon change to boolean with the success/fail in Resource object

end;

procedure TMySTPConnection.RenderRealPath(RealPathObject: TRealPathObject);
begin
  //Your implementation must find the CANONICAL name of this resource
  //  Meaning /whatever/../my-stuff tranforms to /actual-folder/my-stuff
  //  Beware of users trying to sneak into ../../../../../../../Windows/System32 and other such hacks
  //Since this demo does not touch the file system, I can use the default renderer which is a silly StringReplace()
  inherited RenderRealPath(RealPathObject);
end;

begin

  ConnectionClass := TMySTPConnection;

  SetErrorMode(SEM_FAILCRITICALERRORS or SEM_NOGPFAULTERRORBOX);

  case LowerCase(ParamStr(1)) of
    '/child_process':
      RunAsChildProcess;
    '/install':
      InstallAsAService;
    '/supervisor':
      Supervisor(0, nil)
  else
    StartServiceCtrlDispatcher(@ServiceTable);
  end;

end.

