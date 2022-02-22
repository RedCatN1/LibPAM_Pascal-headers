{
*******************************************************
*                                                     *
*      LibPAM Headers by Andrey Devyatkin             *
*    a.k.a (RedCat NeLeGaLoFF)  or  UK8LCJ            *
*       Special thanks to Alex Dudar for              *
*   his help during the creation of this binding      *
*   GitHub: https://github.com/itanswers              *
*   GitLab: https://gitlab.com/adudar                 *
*******************************************************
}

unit pam_header;
{$IFDEF FPC}
  {$mode objfpc}{$H+}
{$ENDIF}

interface

{$DEFINE USE_LIBPAM_MISC}
uses
  Classes, SysUtils, ctypes, cmem;

const
  {$IFDEF FPC}
    {$IFDEF LINUX}
      libPAM = 'libpam.so';
    {$ENDIF}
   {$ENDIF}

  {$IFDEF USE_LIBPAM_MISC}
   {$IFDEF FPC}
    {$IFDEF LINUX}
      const
      libPAM_misc = 'libpam_misc.so';
    {$ENDIF}
   {$ENDIF}
   {$ENDIF}

const
    __LINUX_PAM__ = 1;
    __LINUX_PAM_MINOR__ = 0;
  { ----------------- The Linux-PAM return values ------------------  }
  { Successful function return  }
    PAM_SUCCESS = 0;
  { dlopen() failure when dynamically  }
    PAM_OPEN_ERR = 1;
  { loading a service module  }
  { Symbol not found  }
    PAM_SYMBOL_ERR = 2;
  { Error in service module  }
    PAM_SERVICE_ERR = 3;
  { System error  }
    PAM_SYSTEM_ERR = 4;
  { Memory buffer error  }
    PAM_BUF_ERR = 5;
  { Permission denied  }
    PAM_PERM_DENIED = 6;
  { Authentication failure  }
    PAM_AUTH_ERR = 7;
  { Can not access authentication data  }
    PAM_CRED_INSUFFICIENT = 8;
  { due to insufficient credentials  }
  { Underlying authentication service  }
    PAM_AUTHINFO_UNAVAIL = 9;
  { can not retrieve authentication  }
  { information   }
  { User not known to the underlying  }
    PAM_USER_UNKNOWN = 10;
  { authenticaiton module  }
  { An authentication service has  }
    PAM_MAXTRIES = 11;
  { maintained a retry count which has  }
  { been reached.  No further retries  }
  { should be attempted  }
  { New authentication token required.  }
    PAM_NEW_AUTHTOK_REQD = 12;
  { This is normally returned if the  }
  { machine security policies require  }
  { that the password should be changed  }
  { beccause the password is NULL or it  }
  { has aged  }
  { User account has expired  }
    PAM_ACCT_EXPIRED = 13;
  { Can not make/remove an entry for  }
    PAM_SESSION_ERR = 14;
  { the specified session  }
  { Underlying authentication service  }
    PAM_CRED_UNAVAIL = 15;
  { can not retrieve user credentials  }
  { unavailable  }
  { User credentials expired  }
    PAM_CRED_EXPIRED = 16;
  { Failure setting user credentials  }
    PAM_CRED_ERR = 17;
  { No module specific data is present  }
    PAM_NO_MODULE_DATA = 18;
  { Conversation error  }
    PAM_CONV_ERR = 19;
  { Authentication token manipulation error  }
    PAM_AUTHTOK_ERR = 20;
  { Authentication information  }
    PAM_AUTHTOK_RECOVERY_ERR = 21;
  { cannot be recovered  }
  { Authentication token lock busy  }
    PAM_AUTHTOK_LOCK_BUSY = 22;
  { Authentication token aging disabled  }
    PAM_AUTHTOK_DISABLE_AGING = 23;
  { Preliminary check by password service  }
    PAM_TRY_AGAIN = 24;
  { Ignore underlying account module  }
    PAM_IGNORE = 25;
  { regardless of whether the control  }
  { flag is required, optional, or sufficient  }
  { Critical error (?module fail now request)  }
    PAM_ABORT = 26;
  { user's authentication token has expired  }
    PAM_AUTHTOK_EXPIRED = 27;
  { module is not known  }
    PAM_MODULE_UNKNOWN = 28;
  { Bad item passed to pam_*_item()  }
    PAM_BAD_ITEM = 29;
  { conversation function is event driven
  				     and data is not available yet  }
    PAM_CONV_AGAIN = 30;
  { please call this function again to
  				   complete authentication stack. Before
  				   calling again, verify that conversation
  				   is completed  }
    PAM_INCOMPLETE = 31;
  {
   * Add new #define's here - take care to also extend the libpam code:
   * pam_strerror() and "libpam/pam_tokens.h" .
    }
  { this is the number of return values  }
    _PAM_RETURN_VALUES = 32;
  { ---------------------- The Linux-PAM flags --------------------  }
  { Authentication service should not generate any messages  }
    PAM_SILENT = $8000;
  { Note: these flags are used by pam_authenticate,_secondary()  }
  { The authentication service should return PAM_AUTH_ERROR if the
   * user has a null authentication token  }
    PAM_DISALLOW_NULL_AUTHTOK = $0001;
  { Note: these flags are used for pam_setcred()  }
  { Set user credentials for an authentication service  }
    PAM_ESTABLISH_CRED = $0002;
  { Delete user credentials associated with an authentication service  }
    PAM_DELETE_CRED = $0004;
  { Reinitialize user credentials  }
    PAM_REINITIALIZE_CRED = $0008;
  { Extend lifetime of user credentials  }
    PAM_REFRESH_CRED = $0010;
  { Note: these flags are used by pam_chauthtok  }
  { The password service should only update those passwords that have
   * aged.  If this flag is not passed, the password service should
   * update all passwords.  }
    PAM_CHANGE_EXPIRED_AUTHTOK = $0020;
  { ------------------ The Linux-PAM item types -------------------  }
  { These defines are used by pam_set_item() and pam_get_item().
     Please check the spec which are allowed for use by applications
     and which are only allowed for use by modules.  }
  { The service name  }
    PAM_SERVICE = 1;
  { The user name  }
    PAM_USER = 2;
  { The tty name  }
    PAM_TTY = 3;
  { The remote host name  }
    PAM_RHOST = 4;
  { The pam_conv structure  }
    PAM_CONV = 5;
  { The authentication token (password)  }
    PAM_AUTHTOK = 6;
  { The old authentication token  }
    PAM_OLDAUTHTOK = 7;
  { The remote user name  }
    PAM_RUSER = 8;
  { the prompt for getting a username  }
    PAM_USER_PROMPT = 9;
  { Linux-PAM extensions  }
  { app supplied function to override failure delays  }
    PAM_FAIL_DELAY = 10;
  { X display name  }
    PAM_XDISPLAY = 11;
  { X server authentication data  }
    PAM_XAUTHDATA = 12;
  { The type for pam_get_authtok  }
    PAM_AUTHTOK_TYPE = 13;
  { Linux-PAM message styles }
    PAM_PROMPT_ECHO_OFF  =  1;
    PAM_PROMPT_ECHO_ON   =  2;
    PAM_ERROR_MSG        =  3;
    PAM_TEXT_INFO        =  4;
   { Linux-PAM maximal array sizes }
    PAM_MAX_RESP_SIZE = 512;
    PAM_MAX_MSG_SIZE = 512;
type
pam_handle_t=record
end;

type
  pam_message = record
      msg_style : longint;
      msg : ^Char;
    end;

type
  pam_response = record
      resp : ^Char;
      resp_retcode : longint;
    end;

type
Ppam_message  = ^pam_message;
Ppam_response  = ^pam_response;
PPpam_message  = ^Ppam_message;
PPpam_response  = ^Ppam_response;

type
pamc_bp_t = record
    length:dword;
     control:byte;
end;
  type
pam_conv_t = record
          conv : function (num_msg:longint; msg:PPpam_message; resp:PPpam_response; appdata_ptr:pointer):longint;cdecl;
          appdata_ptr : pointer;
        end;


type
Ppam_handle_t = ^pam_handle_t;
PPpam_handle_t = ^Ppam_handle_t;

type
Ppam_conv = ^pam_conv_t;
Ppamc_bp_t = ^pamc_bp_t;
{ -------------- The Linux-PAM Framework layer API ------------- }
function pam_start(const service_name : Pchar; const user : Pchar; const pam_conversation : Ppam_conv; pamh : PPpam_handle_t):longint; cdecl; external libPAM;
function pam_end(pamh : Ppam_handle_t;pam_status:longint):longint; cdecl; external libPAM;
{ Authentication API's }
function pam_authenticate(pamh : Ppam_handle_t; flags : longint):longint; cdecl; external libPAM;
function pam_setcred(pamh : Ppam_handle_t; flags : longint):longint; cdecl; external libPAM;
{ Account Management API's }
function pam_acct_mgmt(pamh : Ppam_handle_t; flags : longint):longint; cdecl; external libPAM;
 {$IFDEF USE_LIBPAM_MISC}
{ functions defined in pam_misc.* libraries }
function misc_conv(num_msg:longint; msg:PPpam_message; resp:PPpam_response; appdata_ptr:pointer):longint; cdecl; external libPAM_misc;

function pam_misc_conv_warn_time: cint64;cdecl;external libPAM_misc; {time that we should warn user }
function pam_misc_conv_die_time:cint64;cdecl;external libPAM_misc;         { cut-off time for input }
function pam_misc_conv_warn_line: longint;cdecl;external libPAM_misc;           { warning notice }
function pam_misc_conv_die_line: longint;cdecl;external libPAM_misc;           { cut-off remark }
function pam_misc_conv_died:longint;cdecl;external libPAM_misc;      {1 = cut-off time reached (0 not) }



{
  Environment helper functions
 }

{ transcribe given environment (to pam) }
{ (const char * const * user_env)=(const user_env:PPByte) ??? }

function pam_misc_paste_env(pamh : Ppam_handle_t; const user_env:PPByte):longint; cdecl; external libPAM_misc;
{ delete environment as obtained from (pam_getenvlist) }
function pam_misc_drop_env(env:PPByte):PPbyte; cdecl; external libPAM_misc;

{ provide something like the POSIX setenv function for the (Linux-)PAM
 * environment. }

function pam_misc_setenv(pamh : Ppam_handle_t; const name:PByte; const value:PByte; readonly:longint):longint; cdecl; external libPAM_misc;
 {$ENDIF}

 type
 pam_misc_callbacks=record
     pam_binary_handler_fn : function (appdata:pointer; prompt_p:Ppamc_bp_t):longint;cdecl;
     pam_binary_handler_free : procedure (appdata:pointer; prompt_p:Ppamc_bp_t)cdecl;
 end;
{My conversation function}
 type
 PAMUserData = record
     PamUName : string;
     PamUPass : string;
   end;
type PPAMUserData = ^PAMUserData;

function CatConversation(num_msg:longint; msg:PPpam_message; resp:PPpam_response; appdata_ptr:pointer):longint;cdecl;
implementation

function CatConversation(num_msg:longint; msg:PPpam_message; resp:PPpam_response; appdata_ptr:pointer):longint;cdecl;
var
i:longint;
passstr:^char;
unamestr:^char;
m:ppam_message;
testP:pointer;
Pr:^pam_response;
PAMUserAccounData:PPAMUserData;
begin
   PAMUserAccounData:=appdata_ptr;
   unamestr:=Pchar(PAMUserAccounData^.PamUName);
   passstr:=Pchar(PAMUserAccounData^.PamUPass);
    // check the count of message
    if (num_msg <= 0 ) or (num_msg >= PAM_MAX_MSG_SIZE) then
    begin
        writeln('invalid num_msg '+inttostr(num_msg));
        result:=PAM_CONV_ERR;
    end;
    // alloc memory for response
    resp^:=Calloc(num_msg,SizeOf(pam_response));
   if resp^=nil then
    begin
      writeln('bad alloc ');
      result:=PAM_BUF_ERR;
    end;
   // response for message
    for i:= 0 to num_msg-1 do
    Begin
     m:=msg[i];
     Pr:=resp[i];
     Pr^.resp_retcode:= 0;
     if m^.msg_style = PAM_PROMPT_ECHO_OFF then
      begin
       TestP:=Calloc(num_msg,Length(passstr));
       move(passstr^,TestP^,Length(passstr));
       Pr^.resp:=TestP;
       break;
      end;
     if m^.msg_style = PAM_PROMPT_ECHO_ON then
      begin
       TestP:=Calloc(num_msg,Length(unamestr));
       move(unamestr^,TestP^,Length(unamestr));
       Pr^.resp:=TestP;
       break;
      end;
     if m^.msg_style = PAM_TEXT_INFO then
      begin
       writeln(' '+Pchar(m^.msg));
      end;
     if m^.msg_style = PAM_ERROR_MSG then
      begin
       writeln(''+Pchar(m^.msg));
      end;
  end;
result:=PAM_SUCCESS;
end;

end.



