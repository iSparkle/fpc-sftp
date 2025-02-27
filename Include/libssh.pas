unit libssh;

(*
Version 0.7 (-Keneto:2025-02)
This is a minimalist port of the LibSSH C header file. MANY functions and constants are not yet implemented / ported
*)

interface

const
  SSH_OK = 0;

  SSH_AGAIN = -2;

  SSH_AUTH_METHOD_UNKNOWN = $0000;
  SSH_AUTH_METHOD_NONE    = $0001;
  SSH_AUTH_METHOD_PASSWORD = $0002;
  SSH_AUTH_METHOD_PUBLICKEY = $0004;
  SSH_AUTH_METHOD_HOSTBASED = $0008;
  SSH_AUTH_METHOD_INTERACTIVE = $0010;
  SSH_AUTH_METHOD_GSSAPI_MIC = $0020;

  SSH_AUTH_SUCCESS = SSH_OK;
  //SSH_AUTH_DENIED = ??;

  SSH_FILEXFER_TYPE_REGULAR            = 1;
  SSH_FILEXFER_TYPE_DIRECTORY          = 2;
  SSH_FILEXFER_TYPE_SYMLINK            = 3;
  SSH_FILEXFER_TYPE_SPECIAL            = 4;
  SSH_FILEXFER_TYPE_UNKNOWN            = 5;
  SSH_FILEXFER_TYPE_SOCKET             = 6;
  SSH_FILEXFER_TYPE_CHAR_DEVICE        = 7;
  SSH_FILEXFER_TYPE_BLOCK_DEVICE       = 8;
  SSH_FILEXFER_TYPE_FIFO               = 9;

  SSH_FX_OK                            =  0;
  SSH_FX_EOF                           =  1;
  SSH_FX_NO_SUCH_FILE                  =  2;
  SSH_FX_PERMISSION_DENIED             =  3;
  SSH_FX_FAILURE                       =  4;
  SSH_FX_BAD_MESSAGE                   =  5;
  SSH_FX_NO_CONNECTION                 =  6;
  SSH_FX_CONNECTION_LOST               =  7;
  SSH_FX_OP_UNSUPPORTED                =  8;
  SSH_FX_INVALID_HANDLE                =  9;
  SSH_FX_NO_SUCH_PATH                  = 10;
  SSH_FX_FILE_ALREADY_EXISTS           = 11;
  SSH_FX_WRITE_PROTECT                 = 12;
  SSH_FX_NO_MEDIA                      = 13;
  SSH_FX_NO_SPACE_ON_FILESYSTEM        = 14;
  SSH_FX_QUOTA_EXCEEDED                = 15;
  SSH_FX_UNKNOWN_PRINCIPAL             = 16;
  SSH_FX_LOCK_CONFLICT                 = 17;
  SSH_FX_DIR_NOT_EMPTY                 = 18;
  SSH_FX_NOT_A_DIRECTORY               = 19;
  SSH_FX_INVALID_FILENAME              = 20;
  SSH_FX_LINK_LOOP                     = 21;
  SSH_FX_CANNOT_DELETE                 = 22;
  SSH_FX_INVALID_PARAMETER             = 23;
  SSH_FX_FILE_IS_A_DIRECTORY           = 24;
  SSH_FX_BYTE_RANGE_LOCK_CONFLICT      = 25;
  SSH_FX_BYTE_RANGE_LOCK_REFUSED       = 26;
  SSH_FX_DELETE_PENDING                = 27;
  SSH_FX_FILE_CORRUPT                  = 28;

  SSH_FXP_INIT              =   1;
  SSH_FXP_VERSION           =   2;
  SSH_FXP_OPEN              =   3;
  SSH_FXP_CLOSE             =   4;
  SSH_FXP_READ              =   5;
  SSH_FXP_WRITE             =   6;
  SSH_FXP_LSTAT             =   7;
  SSH_FXP_FSTAT             =   8;
  SSH_FXP_SETSTAT           =   9;
  SSH_FXP_FSETSTAT          =  10;
  SSH_FXP_OPENDIR           =  11;
  SSH_FXP_READDIR           =  12;
  SSH_FXP_REMOVE            =  13;
  SSH_FXP_MKDIR             =  14;
  SSH_FXP_RMDIR             =  15;
  SSH_FXP_REALPATH          =  16;
  SSH_FXP_STAT              =  17;
  SSH_FXP_RENAME            =  18;
  SSH_FXP_READLINK          =  19;
  SSH_FXP_LINK              =  21;
  SSH_FXP_BLOCK             =  22;
  SSH_FXP_UNBLOCK           =  23;

  SSH_FXP_REALPATH_NO_CHECK    = $00000001;
  SSH_FXP_REALPATH_STAT_IF     = $00000002;
  SSH_FXP_REALPATH_STAT_ALWAYS = $00000003;

  SSH_FXP_STATUS            = 101;
  SSH_FXP_HANDLE            = 102;
  SSH_FXP_DATA              = 103;
  SSH_FXP_NAME              = 104;
  SSH_FXP_ATTRS             = 105;

  SSH_FXP_EXTENDED          = 200;

  SSL_LOG_NOLOG = 0;
  SSH_LOG_WARNING = 1;
  SSH_LOG_PROTOCOL = 2;
  SSH_LOG_PACKET = 3;
  SSH_LOG_FUNCTIONS = 4;

type
  TLIBSSH_API = Integer;
  PLIBSSHSESSION = Pointer;

  TSSH_bind_options_e = (
    SSH_BIND_OPTIONS_BINDADDR , SSH_BIND_OPTIONS_BINDPORT , SSH_BIND_OPTIONS_BINDPORT_STR , SSH_BIND_OPTIONS_HOSTKEY ,
    SSH_BIND_OPTIONS_DSAKEY , SSH_BIND_OPTIONS_RSAKEY , SSH_BIND_OPTIONS_BANNER , SSH_BIND_OPTIONS_LOG_VERBOSITY ,
    SSH_BIND_OPTIONS_LOG_VERBOSITY_STR , SSH_BIND_OPTIONS_ECDSAKEY , SSH_BIND_OPTIONS_IMPORT_KEY , SSH_BIND_OPTIONS_KEY_EXCHANGE ,
    SSH_BIND_OPTIONS_CIPHERS_C_S , SSH_BIND_OPTIONS_CIPHERS_S_C , SSH_BIND_OPTIONS_HMAC_C_S , SSH_BIND_OPTIONS_HMAC_S_C ,
    SSH_BIND_OPTIONS_CONFIG_DIR , SSH_BIND_OPTIONS_PUBKEY_ACCEPTED_KEY_TYPES , SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS , SSH_BIND_OPTIONS_PROCESS_CONFIG ,
    SSH_BIND_OPTIONS_MODULI , SSH_BIND_OPTIONS_RSA_MIN_SIZE , SSH_BIND_OPTIONS_IMPORT_KEY_STR);

  PSSHChannel = ^TSSHChannel;
  TSSHChannel = Pointer;
  PSSHChannels = ^TSSHChannels;
  TSSHChannels = array[0..0] of PSSHChannel;
  PSSHEvent = ^TSSHEvent;
  TSSHEvent = Pointer;

  PSFTPPacketHeader = ^TSFTPPacketHeader;
  TSFTPPacketHeader = packed record
    Len: DWord;
    PacketType: Byte;
    RequestID: DWord;
  end;

  PPubkey = Pointer; //This should map to a *PubKey

  TAuthGssapiMicCallback = function(Session: PLIBSSHSESSION; User: PChar; Principal: PChar; UserData: Pointer): Integer; cdecl;
  TAuthNoneCallback = function(Session: PLIBSSHSESSION; User: PChar; UserData: Pointer): Integer; cdecl;
  TAuthPasswordCallback = function(Session: PLIBSSHSESSION; User: PChar; Password: PChar; UserData: Pointer): Integer; cdecl;
  TAuthPubkeyCallBack = function(Session: PLIBSSHSESSION; User: PChar; ssh_key_struct: PPubkey; SignatureState: PChar; UserData: Pointer): Integer; cdecl;
  TChannelOpenRequestSessionCallback = function(Session: PLIBSSHSESSION; UserData: Pointer) : PSSHChannel; cdecl;
  TGssapiAcceptSecCtxCallback = function(Session: PLIBSSHSESSION; InputTkoen: PChar; OutputToken: PChar; UserData: Pointer): Integer; cdecl;
  TGssapiSelectOidCallback = function(Session: PLIBSSHSESSION; User: Pointer; N_Oid: DWord; Oids: PChar; UserData: Pointer): PChar; cdecl;
  TGssapiVerifyMicCallback = function(Session: PLIBSSHSESSION; Mic: PChar; MicBuffer: Pointer; MicBufferSize: DWord; UserData: Pointer): Integer; cdecl;
  TServiceRequestCallback = function(Session: PLIBSSHSESSION; Service: PChar; UserData: Pointer): Integer; cdecl;

  TServerCallbacks = packed record
    Size: Int64;
    UserData: Pointer;
    auth_password_function: TAuthPasswordCallback;
    auth_none_function: TAuthNoneCallback;
    auth_gssapi_mic_function: TAuthGssapiMicCallback;
    auth_pubkey_function: TAuthPubkeyCallBack;
    service_request_function: TServiceRequestCallback;
    channel_open_request_session_function: TChannelOpenRequestSessionCallback;
    gssapi_select_oid_function: TGssapiSelectOidCallback; //Generic Security Services API
    gssapi_accept_sec_ctx_function: TGssapiAcceptSecCtxCallback;
    gssapi_verify_mic_function: TGssapiVerifyMicCallback;
  end;

  //To-Do: Finish the Channel Callback definitions
  TChannelDataCallback = function(Session: PLIBSSHSESSION; Channel: PSSHChannel; Data: Pointer; Len: DWord; is_stderr: Integer; UserData: Pointer): DWord; cdecl;
  TChannelEofCallback = function (Session: PLIBSSHSESSION; Channel: PSSHChannel; UserData: Pointer): TLIBSSH_API; cdecl;
  SSHChannel_close_callback = procedure; cdecl;
  SSHChannel_signal_callback = procedure; cdecl;
  SSHChannel_exit_status_callback = procedure; cdecl;
  SSHChannel_exit_signal_callback = procedure; cdecl;
  SSHChannel_pty_request_callback = procedure; cdecl;
  TChannelShellRequestCallback = function (Session: PLIBSSHSESSION; Channel: PSSHChannel; UserData: Pointer): TLIBSSH_API; cdecl;
  SSHChannel_auth_agent_req_callback = procedure; cdecl;
  SSHChannel_x11_req_callback = procedure; cdecl;
  SSHChannel_pty_window_change_callback = procedure; cdecl;
  TChannelExecRequestCallback = function(Session: PLIBSSHSESSION; Channel: PSSHChannel; Command: PChar; UserData: Pointer): TLIBSSH_API; cdecl;
  TChannelEnvRequestCallback = function(Session: PLIBSSHSESSION; Channel: PSSHChannel; EnvName: PChar; EnvValue: PChar; UserData: Pointer): DWord; cdecl;
  TChannelSubsystemRequestCallback = function(Session: PLIBSSHSESSION; Channel: PSSHChannel; SubSystem: PChar; UserData: Pointer): DWord; cdecl;
  TChannelWriteWontblockCallback = function(Session: PLIBSSHSESSION; Channel: PSSHChannel; Bytes: Integer; UserData: Pointer): DWord; cdecl;
  TChannelOpenRespCallback = function(Session: PLIBSSHSESSION; Channel: PSSHChannel; IsSuccess: Boolean; UserData: Pointer): DWord; cdecl;
  TChannelRequestRespCallback =  function (Session: PLIBSSHSESSION; Channel: PSSHChannel; UserData: Pointer): TLIBSSH_API; cdecl;

  TChannelCallbacks = packed record
    Size: Int64;
    UserData: Pointer;
    channel_data_function: TChannelDataCallback;
    channel_eof_function: TChannelEofCallback;
    channel_close_function: SSHChannel_close_callback;
    channel_signal_function: SSHChannel_signal_callback;
    channel_exit_status_function: SSHChannel_exit_status_callback;
    channel_exit_signal_function: SSHChannel_exit_signal_callback;
    channel_pty_request_function: SSHChannel_pty_request_callback;
    channel_shell_request_function: TChannelShellRequestCallback;
    channel_auth_agent_req_function: SSHChannel_auth_agent_req_callback;
    channel_x11_req_function: SSHChannel_x11_req_callback;
    channel_pty_window_change_function: SSHChannel_pty_window_change_callback;
    channel_exec_request_function: TChannelExecRequestCallback;
    channel_env_request_function: TChannelEnvRequestCallback;
    channel_subsystem_request_function: TChannelSubsystemRequestCallback;
    channel_write_wontblock_function: TChannelWriteWontblockCallback;
    channel_open_response_function: TChannelOpenRespCallback;
    channel_request_response_function: TChannelRequestRespCallback;
  end;

  function ssh_bind_accept(SshBind: TLIBSSH_API; Session: PLIBSSHSESSION ): Integer; cdecl; external 'ssh.dll';
  procedure ssh_bind_free(SshBind: TLIBSSH_API); cdecl; external 'ssh.dll';
  function ssh_bind_listen(SshBind: TLIBSSH_API): TLIBSSH_API; cdecl; external 'ssh.dll';
  function ssh_bind_new(): TLIBSSH_API; cdecl; external 'ssh.dll';// name 'libssh2_init';
  function ssh_bind_options_set(SshBind: TLIBSSH_API; fType: TSSH_bind_options_e; Value: Pointer): Integer; cdecl; external 'ssh.dll';
  function ssh_blocking_flush(Session: PLIBSSHSESSION; TimeOut: Integer): TLIBSSH_API; cdecl; external 'ssh.dll';
  function ssh_channel_close(Channel: PSSHChannel): TLIBSSH_API; cdecl; external 'ssh.dll';
  function ssh_channel_new(Session: PLIBSSHSESSION): PSSHChannel; cdecl; external 'ssh.dll';
  function ssh_channel_open_session(Channel: PSSHChannel): TLIBSSH_API; cdecl; external 'ssh.dll';
  function ssh_channel_is_eof(Channel: PSSHChannel): Boolean; cdecl; external 'ssh.dll';
  function ssh_channel_read_timeout(Channel: PSSHChannel; Destination: Pointer; DestinationSize: Integer; IsStdError: Boolean; Timeout: Integer): TLIBSSH_API; cdecl; external 'ssh.dll';
  function ssh_channel_send_eof(Channel: PSSHChannel): DWord; cdecl; external 'ssh.dll';
  procedure ssh_channel_set_blocking(Channel: PSSHChannel; Blocking: Boolean); cdecl; external 'ssh.dll';
  function ssh_channel_write(Channel: PSSHChannel; Data: Pointer; Len: DWord): DWord; cdecl; external 'ssh.dll';
  procedure ssh_disconnect(Session: PLIBSSHSESSION); cdecl; external 'ssh.dll';
  procedure ssh_event_add_session(Event: PSSHEvent; Session: PLIBSSHSESSION); cdecl; external 'ssh.dll';
  function ssh_event_dopoll(Event: PSSHEvent; Timeout: Integer): TLIBSSH_API; cdecl; external 'ssh.dll';
  function ssh_event_new(): PSSHEvent; cdecl; external 'ssh.dll';
  procedure ssh_free(Session: PLIBSSHSESSION); cdecl; external 'ssh.dll';
  function ssh_get_error(SshBind: TLIBSSH_API): PChar; cdecl; external 'ssh.dll';
  function ssh_handle_key_exchange(Session: PLIBSSHSESSION): TLIBSSH_API; cdecl; external 'ssh.dll';
  function ssh_init(): TLIBSSH_API; cdecl; external 'ssh.dll';
  function ssh_new(): PLIBSSHSESSION; cdecl; external 'ssh.dll';
  function ssh_select(Channels: PSSHChannels; OutChannels: PSSHChannels; maxFd: THandle; ReadDfs: Pointer; Timeout: Integer): TLIBSSH_API; cdecl; external 'ssh.dll';
  procedure ssh_set_auth_methods(Session: PLIBSSHSESSION; AuthMethods: Integer); cdecl; external 'ssh.dll';
  function ssh_set_channel_callbacks(Channel: PSSHChannel; Cb: TChannelCallbacks): TLIBSSH_API; cdecl; external 'ssh.dll';
  function ssh_set_server_callbacks(Session: PLIBSSHSESSION; Cb: TServerCallbacks): TLIBSSH_API; cdecl; external 'ssh.dll';


implementation

end.
