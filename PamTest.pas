program PamTest;

uses
  Classes, SysUtils, pam_header;
var
res:integer;
pam_hannn:Ppam_handle_t;
TestConv:pam_conv_t;
UserAccountData:PAMUserData;
begin
UserAccountData.PamUName:='user';
UserAccountData.PamUPass:='pass';
TestConv.conv:=@CatConversation;
TestConv.appdata_ptr:=@UserAccountData;
res:=pam_start(PChar('check'),nil,@TestConv,@pam_hannn);
writeln('pam_start result is : '+IntToStr(res));
if res=PAM_SUCCESS then
res:=pam_authenticate(pam_hannn,0);
writeln('pam_authenticate result is : '+IntToStr(res));
if res=PAM_SUCCESS then
res:=pam_acct_mgmt(pam_hannn, 0);
writeln('pam_acct_mgmt result is : '+IntToStr(res));
res:=pam_end(pam_hannn,res);
writeln('pam_end result is : '+IntToStr(res));
end.

