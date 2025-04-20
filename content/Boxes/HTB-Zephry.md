
The Premonition:  ZEPHYR{HuM4n_3rr0r_1s_0uR_D0wnf4ll}  | Send malicious PDF via job board and intercept password hash for riley (Bad-PDF)  
Back Tracking:  ZEPHYR{L34v3_N0_St0n3_Un7urN3d} | Get root on mail.painters.htb (110.51) as Matt by authenticating with his password (retrieved from painters.htb DCSync)  
Recycled:  ZEPHYR{PwN1nG_W17h_P4s5W0rd_R3U53} | Get session as riley on WORKSTATION-1 (110.56) (password re-use, duh)  
Disclosure:  ZEPHYR{S3rV1c3_AcC0Un7_5PN_Tr0uBl35} |  Kerberoast web_svc, crack hash, then get a session as web_svc on PNT-SVRSVC  
Persistence:  ZEPHYR{P3r5isT4nc3_1s_k3Y_4_M0v3men7} |  Pass James hash obtained on PNT-SVRSVC (SAM dump) to PNT-SVRBPA  
Heartbreak:  ZEPHYR{7h3_Tru57_h45_B3eN_Br0k3n} |  Abuse ForceChangePassword from PNT-SVRBPA to Blake  
Domination:  ZEPHYR{P41n73r_D0m41n_D0m1n4nc3} |  Get service ticket (TGT) for Administrator with Blake (constrained delegation), then perform a secretsdump on the DC.  
Monitored:  ZEPHYR{Abu51ng_d3f4ul7_Func710n4li7y_ftw} |  Abuse Zabbix script functionality, escalate privs with sudo config on nmap (cve-2022-23131)  
The Forgotten:  ZEPHYR{C4n7_F0rg3t_ab0u7_7h1s_0n3} | Session on ADFS.zsm.local (you won't get this till you're toward the end)  
Movement:  ZEPHYR{C0n57r4in3d_d3l3g4710n_1s_d4ng3r0us} |  ZPH-SVRCA01 (C:\Users\Public\Desktop)  
Diverted:  ZEPHYR{K3y_Cr3d3n714l_l1nk_d4ng3r} |  AddKeyCredential link (shadow credentials) abuse on MGMT1  
The Statement:  ZEPHYR{SQLi_2_Imp3rs0n4710n_fun} |  Impersonate SA on SQL01 and get a session as SYSTEM (GodPotato priv esc)  
The Missing Link:  ZEPHYR{G0tt4_l1nk_Up_4m_1_r1gh7?} | Login to zph-svrsql01.zsm.local (192.168.210.15) with Zabbix DB creds, then crawl the link to SQL02 and get a session as SYSTEM  (GodPotato priv esc)  
Tweaked:  ZEPHYR{S3rv1c3_M4n4g3m3nt_f41L5} | Get a session on SVRCHR.internal.zsm.local  
  
You can get these flags on your own..  
The Fall: Session on SVRCSUP.internal.zsm.local  
Compromised: Session on ZPH-SVRDC01.zsm.local