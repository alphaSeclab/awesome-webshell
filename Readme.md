# 所有收集类项目:
- [收集的所有开源工具: sec-tool-list](https://github.com/alphaSeclab/sec-tool-list): 超过18K, 包括Markdown和Json两种格式
- [逆向资源: awesome-reverse-engineering](https://github.com/alphaSeclab/awesome-reverse-engineering): IDA/Ghidra/x64dbg/OllDbg/WinDBG/CuckooSandbox/Radare2/BinaryNinja/DynamoRIO/IntelPin/Frida/QEMU/Android安全/iOS安全/Window安全/Linux安全/macOS安全/游戏Hacking/Bootkit/Rootkit/Angr/Shellcode/进程注入/代码注入/DLL注入/WSL/Sysmon/...
- [网络相关的安全资源: awesome-network-stuff](https://github.com/alphaSeclab/awesome-network-stuff): 代理/GFW/反向代理/隧道/VPN/Tor/I2P，以及中间人/PortKnocking/嗅探/网络分析/网络诊断等
- [攻击性网络安全资源: awesome-cyber-security](https://github.com/alphaSeclab/awesome-cyber-security): 漏洞/渗透/物联网安全/数据渗透/Metasploit/BurpSuite/KaliLinux/C&C/OWASP/免杀/CobaltStrike/侦查/OSINT/社工/密码/凭证/威胁狩猎/Payload/WifiHacking/无线攻击/后渗透/提权/UAC绕过/...
- [开源远控和恶意远控分析报告: awesome-rat](https://github.com/alphaSeclab/awesome-rat): 开源远控工具: Windows/Linux/macOS/Android; 远控类恶意恶意代码的分析报告等




# webshell
- [English Version](https://github.com/alphaSeclab/awesome-webshell/blob/master/Readme_en.md)


# 目录
- [工具](#bad06ceb38098c26b1b8b46104f98d25)
    - [(91) 新添加](#faa91844951d2c29b7b571c6e8a3eb54)
    - [(20) Webshell收集](#e08366dcf7aa021c6973d9e2a8944dff)
    - [(3) Webshell管理](#3d555f25d9775b58890a8f82bc8c2a0b)
    - [(19) Webshell检测](#39e5bd43766abbdbc518390d86b3a0a5)
    - [(8) Webshell扫描](#b92430134aad35583d8470fb260406ed)
    - [(2) 其他](#e89361c3ac1f1c35355f57601fb2f6e0)
- [文章](#55572950f807e9e7c079edd49eab3dd0)
    - [(232) 新添加](#00afa6c71cbb358ba1c2b16fc8539112)


# <a id="bad06ceb38098c26b1b8b46104f98d25"></a>工具


***


## <a id="faa91844951d2c29b7b571c6e8a3eb54"></a>新添加


- [**1782**星][4m] [Py] [epinna/weevely3](https://github.com/epinna/weevely3) 用于后渗透的Web Shell，可以在运行时通过网络对其进行扩展
- [**1770**星][2y] [CSS] [b374k/b374k](https://github.com/b374k/b374k)  a useful tool for system or web administrator to do remote management without using cpanel, connecting using ssh, ftp etc.
- [**1059**星][1m] [Py] [yzddmr6/webshell-venom](https://github.com/yzddmr6/webshell-venom) 免杀webshell无限生成工具(利用随机异或无限免杀D盾)
- [**617**星][1y] [Shell] [wireghoul/htshells](https://github.com/wireghoul/htshells) 自包含的Web Shell和通过.htaccess文件进行的其他攻击。
- [**538**星][3y] [PHP] [dotcppfile/daws](https://github.com/dotcppfile/daws) Advanced Web Shell
- [**441**星][4y] [C#] [keepwn/altman](https://github.com/keepwn/altman) the cross platform webshell tool in .NET
- [**434**星][1y] [Py] [shmilylty/cheetah](https://github.com/shmilylty/cheetah) a very fast brute force webshell password tool
- [**354**星][8m] [PHP] [s0md3v/nano](https://github.com/s0md3v/nano) PHP Webshell家族
- [**321**星][2y] [PHP] [tanjiti/webshellsample](https://github.com/tanjiti/webshellsample) webshell sample for WebShell Log Analysis
- [**282**星][1y] [JS] [chrisallenlane/novahot](https://github.com/chrisallenlane/novahot) Webshell框架，实现了基于Json的API，可与任何语言编写的后门（默认支持PHP/Ruby/Python）进行通信。
- [**245**星][9m] [Py] [antoniococo/sharpyshell](https://github.com/antoniococo/sharpyshell) ASP.NET webshell，小型，混淆，针对C# Web App
- [**209**星][7m] [PHP] [samdark/yii2-webshell](https://github.com/samdark/yii2-webshell) Web shell allows to run yii console commands using a browser
- [**206**星][3m] [JS] [yzddmr6/as_webshell_venom](https://github.com/yzddmr6/as_webshell_venom) 免杀webshell无限生成工具蚁剑版
- [**203**星][6m] [Py] [ares-x/awd-predator-framework](https://github.com/ares-x/awd-predator-framework) AWD攻防赛webshell批量利用框架
- [**189**星][2y] [Java] [rebeyond/memshell](https://github.com/rebeyond/memshell) a webshell resides in the memory of java web server
- [**181**星][2y] [PHP] [lcatro/php-webshell-bypass-waf](https://github.com/lcatro/php-webshell-bypass-waf) 分享PHP WebShell 绕过WAF 的一些经验
- [**173**星][12m] [Java] [joychou93/webshell](https://github.com/joychou93/webshell) 入侵分析时发现的Webshell后门
- [**167**星][7y] [PHP] [secrule/falcon](https://github.com/secrule/falcon) 基于inotify-tools 开发的Web服务器文件监控平台 能够实时监控Web目录文件变化(新增，修改，删除)，判断文件内容是否包含恶意代码，自动隔离常见Webshell，保证Web目录文件安全
- [**133**星][10m] [PHP] [k4mpr3t/b4tm4n](https://github.com/k4mpr3t/b4tm4n) Php webshell
- [**124**星][8y] [evilcos/python-webshell](https://github.com/evilcos/python-webshell) webshell writen in python
- [**121**星][3y] [malwares/webshell](https://github.com/malwares/webshell) WebShell Dump
- [**106**星][3y] [JS] [boy-hack/webshellmanager](https://github.com/boy-hack/webshellmanager) w8ay 一句话WEB端管理工具
- [**99**星][1y] [Py] [wonderqs/blade](https://github.com/wonderqs/blade) A webshell connection tool with customized WAF bypass payloads
- [**98**星][2y] [Java] [securityriskadvisors/cmd.jsp](https://github.com/securityriskadvisors/cmd.jsp) A super small jsp webshell with file upload capabilities.
- [**96**星][2y] [Java] [tengzhangchao/pycmd](https://github.com/tengzhangchao/pycmd) python+php+jsp WebShell（一句话木马）
- [**82**星][5y] [Py] [xypiie/webshell](https://github.com/xypiie/webshell) a web-based ssh shell.
- [**78**星][3y] [PHP] [secwiki/webshell-2](https://github.com/secwiki/webshell-2) Webshell
- [**77**星][2y] [Py] [wofeiwo/webshell-find-tools](https://github.com/wofeiwo/webshell-find-tools) 分析web访问日志以及web目录文件属性，用于根据查找可疑后门文件的相关脚本。
- [**76**星][8m] [PHP] [s9mf/s9mf-php-webshell-bypass](https://github.com/s9mf/s9mf-php-webshell-bypass) 为方便WAF入库的项目 | 分享PHP免杀大马 | 菜是原罪 | 多姿势(假的就一个)
- [**76**星][3y] [C#] [zcgonvh/cve-2017-7269-tool](https://github.com/zcgonvh/cve-2017-7269-tool) CVE-2017-7269 to webshell or shellcode loader
- [**73**星][4y] [PHP] [phith0n/b374k](https://github.com/phith0n/b374k) PHP Webshell with handy features
- [**68**星][2y] [Py] [3xp10it/xdump](https://github.com/3xp10it/xdump) Drag database with "one sentence" webshell
- [**61**星][8m] [PHP] [michyamrane/wso-webshell](https://github.com/mIcHyAmRaNe/wso-webshell) php webshell
- [**47**星][2y] [PHP] [whitewinterwolf/wwwolf-php-webshell](https://github.com/whitewinterwolf/wwwolf-php-webshell) WhiteWinterWolf's PHP web shell
- [**47**星][5y] [PHP] [cloudsec/aioshell](https://github.com/cloudsec/aioshell) A php webshell run under linux based webservers. v0.05
- [**45**星][3y] [Py] [threatexpress/subshell](https://github.com/threatexpress/subshell)  a python command shell used to control and execute commands through HTTP requests to a webshell. 
- [**40**星][5y] [evi1m0/webshell](https://github.com/evi1m0/webshell) This is a webshell open source project
- [**40**星][4y] [PHP] [wso-shell/wso](https://github.com/wso-shell/wso) WSO SHELL , wso shell , WSO.php , wso.php , webshell , wso-shell веб-шелл , шелл , WSO2.5 , WSO2.5.1 , WSO2.php , Shell download, C99 , r57 , bypass shell , P.A.S. (php web-shell) , PPS 4.0 , Скачать WSO Web Shell , Скачать wso.php , Скачать Web Shell
- [**39**星][5y] [PHP] [ridter/webshell](https://github.com/ridter/webshell) This is a webshell open source project
- [**36**星][2m] [PHP] [linuxsec/indoxploit-shell](https://github.com/linuxsec/indoxploit-shell) IndoXploit Webshell V.3
- [**32**星][5y] [jgor/php-jpeg-shell](https://github.com/jgor/php-jpeg-shell) Simple PHP webshell with a JPEG header to bypass weak image verification checks
- [**32**星][4y] [PHP] [wstart/webshell](https://github.com/wstart/webshell) This is a webshell open source project
- [**31**星][2y] [Py] [bwsw/webshell](https://github.com/bwsw/webshell) Docker container which includes Shellinabox and enables SSH connections to arbitrary (not where installed) servers
- [**30**星][9m] [Py] [3xp10it/xupload](https://github.com/3xp10it/xupload) A tool for automatically testing whether the upload function can upload webshell
- [**30**星][4y] [PHP] [fuzzdb-project/webshell](https://github.com/fuzzdb-project/webshell) This is a webshell open source project
- [**27**星][11d] [JS] [onrik/django-webshell](https://github.com/onrik/django-webshell) Django application for running python code in your project's environment from django admin.
- [**21**星][3y] [Py] [l-codes/oneshellcrack](https://github.com/l-codes/oneshellcrack) a very very fast brute force webshell password tool
- [**21**星][4y] [PHP] [secwiki/webshell](https://github.com/secwiki/webshell) This is a webshell open source project
- [**18**星][2y] [ASP] [grcod/poly](https://github.com/grcod/poly) polymorphic webshells
- [**18**星][2y] [PHP] [incredibleindishell/php-web-shells](https://github.com/incredibleindishell/php-web-shells) when i started web application security testing, i fall in love with web shell development and designed some PHP based web shells. This repository contains all my codes which i released in public.
- [**17**星][4y] [PHP] [abcdlzy/webshell-manager](https://github.com/abcdlzy/webshell-manager) 一句话木马管理工具，重复造轮子项目
- [**16**星][2y] [PHP] [the404hacking/b374k-mini](https://github.com/the404hacking/b374k-mini) PHP Webshell with handy features.
- [**15**星][2y] [PHP] [abdilahrf/kerang](https://github.com/abdilahrf/kerang) Kerang is a Another Webshell Backdoor, For Educational Purposes!
- [**15**星][5y] [ASP] [le4f/aspexec](https://github.com/le4f/aspexec) asp命令执行webshell
- [**14**星][7m] [PHP] [tengzhangchao/maskfindshell](https://github.com/tengzhangchao/maskfindshell) linux下webshell查杀工具
- [**14**星][3y] [Py] [wangyihang/webshellcracker](https://github.com/wangyihang/webshellcracker) WebShell密码爆破工具
- [**13**星][7y] [PHP] [lordwolfer/webshells](https://github.com/lordwolfer/webshells) This is a compilation of various shells that I had found in the wild.
- [**11**星][3y] [PHP] [linuxsec/shu-shell](https://github.com/linuxsec/shu-shell) Webshell Jumping Edition
- [**11**星][4y] [JS] [maestrano/webshell-server](https://github.com/maestrano/webshell-server) Web based shell with configurable authentication
- [**11**星][3y] [C#] [niemand-sec/razorsyntaxwebshell](https://github.com/niemand-sec/razorsyntaxwebshell) Webshell for Razor Syntax (C#)
- [**10**星][2y] [ASP] [grcod/webshells](https://github.com/grcod/webshells) php - asp - aspx
- [**9**星][1y] [PHP] [itskindred/php-web-shell](https://github.com/itskindred/php-web-shell) A Simple PHP Web Shell used for Remote Code Execution.
- [**8**星][2y] [C++] [euphrat1ca/hatchet](https://github.com/euphrat1ca/hatchet) cknife（webshell manager）
- [**8**星][3y] [PHP] [magicming200/evil-koala-php-webshell](https://github.com/magicming200/evil-koala-php-webshell) 邪恶考拉php webshell。
- [**8**星][2y] [dubfr33/atlassian-webshell-plugin](https://github.com/dubfr33/atlassian-webshell-plugin) Webshell plugin that works on any Atlassian product employing their plugin framework
- [**7**星][8m] [PHP] [chrissy-morgan/php-webshell-deobfuscator](https://github.com/chrissy-morgan/php-webshell-deobfuscator) A Tool written in Python to help de-obfuscate the $GLOBALS type malware.
- [**7**星][2y] [PHP] [josexv1/wso-webshell](https://github.com/josexv1/wso-webshell) Copy of WSO-Webshell made by @Hardlinux
- [**6**星][1y] [PHP] [evil7/webshell](https://github.com/evil7/webshell) Some webshell useful like spy udf silic chatroom
- [**4**星][4y] [PHP] [blackhalt/webshells](https://github.com/blackhalt/webshells) An list of webshell vulnerability injection.
- [**4**星][12m] [PHP] [brianwrf/priwebshell](https://github.com/brianwrf/priwebshell) For Webshell downloading
- [**4**星][2y] [Java] [0x4e0x650x6f/pwn4jshell](https://github.com/0x4e0x650x6f/pwn4jshell) Java Web shell project
- [**3**星][4y] [JS] [mhelwig/wp-webshell-xss](https://github.com/mhelwig/wp-webshell-xss) A simple wordpress webshell injector
- [**3**星][3m] [PHP] [tulungagungcyberlink/webshellbackdoor](https://github.com/tulungagungcyberlink/webshellbackdoor) WebShell Backdoor. Use at your own risk.
- [**2**星][2y] [PHP] [blue-bird1/webshell](https://github.com/blue-bird1/webshell) webshell
- [**2**星][2y] [PHP] [thepacketbender/webshells](https://github.com/thepacketbender/webshells) webshells written with malice
- [**2**星][6m] [Py] [cbiu/rsawebshell](https://github.com/cbiu/rsawebshell) 主要用于AWD的RSA加密WebShell
- [**2**星][2y] [Py] [mperlet/pomsky](https://github.com/mperlet/pomsky) lightweight webshell
- [**1**星][3y] [Py] [doyler/rwsh](https://github.com/doyler/rwsh) Ray's Web SHell
- [**1**星][6y] [ettack/webshellccl](https://github.com/ettack/webshellccl) A python script help with webshell bypassing.
- [**1**星][2y] [C++] [pikeman20/webshell](https://github.com/pikeman20/webshell) 
- [**1**星][2y] [Py] [tincho9/webshell-protector](https://github.com/tincho9/webshell-protector) A small POC of defense from webshells
- [**1**星][2y] [Ruby] [lolwaleet/rubshell](https://github.com/lolwaleet/rubshell) A simple (and ugly) ruby-based webshell.
- [**1**星][2y] [Py] [jubal-r/tinywebshell](https://github.com/jubal-r/tinywebshell) A small, simple php web shell with an interactive console
- [**1**星][2y] [Swift] [wdg/webshell-builder](https://github.com/wdg/webshell-builder) A WebShell application builder (no use of Xcode)
- [**1**星][2y] [ASP] [badc0d3/webshellcreator](https://github.com/badc0d3/webshellcreator) Simple Python script to create webshells
- [**0**星][3y] [aaspky/webshell](https://github.com/aaspky/webshell) 
- [**0**星][3y] [dinamsky/webshell](https://github.com/dinamsky/webshell) 
- [**0**星][2y] [PHP] [kap0k/caidao_encrypt](https://github.com/kap0k/caidao_encrypt) In order to bypass waf, we use a php server, as a proxy, to encrypt the data flow between the China Chopper and the webshell. This tool is just for study and research.
- [**0**星][4y] [PHP] [kuniasahi/mpshell](https://github.com/kuniasahi/mpshell) my php webshell
- [**0**星][3y] [tghosth/webshelljar](https://github.com/tghosth/webshelljar) 
- [**0**星][3y] [zh3feng/php-webshell-checker](https://github.com/zh3feng/php-webshell-checker) PHP-WebShell-Checker


***


## <a id="e08366dcf7aa021c6973d9e2a8944dff"></a>Webshell收集


- [**22055**星][27d] [PHP] [danielmiessler/seclists](https://github.com/danielmiessler/seclists) 多种类型资源收集：用户名、密码、URL、敏感数据类型、Fuzzing  Payload、WebShell等
- [**5181**星][24d] [PHP] [tennc/webshell](https://github.com/tennc/webshell) webshell收集
- [**2307**星][30d] [PS] [k8gege/k8tools](https://github.com/k8gege/k8tools) K8工具合集(内网渗透/提权工具/远程溢出/漏洞利用/扫描工具/密码破解/免杀工具/Exploit/APT/0day/Shellcode/Payload/priviledge/BypassUAC/OverFlow/WebShell/PenTest) Web GetShell Exploit(Struts2/Zimbra/Weblogic/Tomcat/Apache/Jboss/DotNetNuke/zabbix)
- [**1392**星][4y] [PHP] [johntroony/php-webshells](https://github.com/johntroony/php-webshells) Common php webshells. Do not host the file(s) on your server!
- [**682**星][3y] [PHP] [xl7dev/webshell](https://github.com/xl7dev/webshell) Webshell && Backdoor Collection
- [**428**星][1y] [PHP] [ysrc/webshell-sample](https://github.com/ysrc/webshell-sample) 收集自网络各处的 webshell 样本，用于测试 webshell 扫描器检测率。
- [**369**星][1m] [PHP] [blackarch/webshells](https://github.com/blackarch/webshells) Various webshells. We accept pull requests for additions to this collection.
- [**289**星][13d] [Java] [mr-xn/penetration_testing_poc](https://github.com/mr-xn/penetration_testing_poc) 渗透测试有关的POC、EXP、脚本、提权、小工具等
- [**244**星][3y] [PHP] [tdifg/webshell](https://github.com/tdifg/webshell) WebShell Collect
- [**156**星][2y] [ASP] [testsecer/webshell](https://github.com/testsecer/webshell) 这是一个WebShell收集项目
- [**150**星][2y] [Py] [vduddu/malware](https://github.com/vduddu/malware) Rootkits | Backdoors | Sniffers | Virus | Ransomware | Steganography | Cryptography | Shellcodes | Webshells | Keylogger | Botnets | Worms | Other Network Tools
- [**145**星][3y] [PHP] [webshellpub/awsome-webshell](https://github.com/webshellpub/awsome-webshell) webshell样本大合集。收集各种webshell用于webshell分析与发现
- [**50**星][3y] [0xhjk/caidao](https://github.com/0xhjk/caidao) 中国菜刀及其衍生版本的Webshell管理工具收集
- [**48**星][2y] [PHP] [backlion/webshell](https://github.com/backlion/webshell) 这是一些常用的webshell
- [**37**星][4m] [PHP] [x-o-r-r-o/php-webshells-collection](https://github.com/x-o-r-r-o/php-webshells-collection) Most Wanted Private and Public PHP Web Shells Can Be Downloaded Here. (Educational Purpose Only)
- [**23**星][3y] [PHP] [3xp10it/xwebshell](https://github.com/3xp10it/xwebshell) 免杀webshell集合
- [**23**星][2y] [PHP] [xiaoxiaoleo/xiao-webshell](https://github.com/xiaoxiaoleo/xiao-webshell) a collection of webshell
- [**7**星][3y] [Py] [shewey/webshell](https://github.com/shewey/webshell) 各种漏洞PoC、ExP的收集或编写
- [**4**星][3m] [PHP] [suryamaulana/webshellbackdoor](https://github.com/suryamaulana/webshellbackdoor) WebShell Backdoor Collection.
- [**1**星][2y] [PHP] [12345bt/webshell](https://github.com/12345bt/webshell) webshell收集项目


***


## <a id="3d555f25d9775b58890a8f82bc8c2a0b"></a>Webshell管理


- [**310**星][9m] [Py] [wangyihang/webshell-sniper](https://github.com/wangyihang/webshell-sniper) webshell管理器，命令行工具
- [**232**星][5y] [PHP] [smaash/quasibot](https://github.com/smaash/quasibot) complex webshell manager, quasi-http botnet.
- [**50**星][3m] [C#] [guillac/wsmanager](https://github.com/guillac/wsmanager) Webshell Manager


***


## <a id="39e5bd43766abbdbc518390d86b3a0a5"></a>Webshell检测


- [**637**星][4y] [PHP] [emposha/php-shell-detector](https://github.com/emposha/php-shell-detector) a php script that helps you find and identify php/cgi(perl)/asp/aspx shells. 
- [**501**星][8m] [ASP] [landgrey/webshell-detect-bypass](https://github.com/landgrey/webshell-detect-bypass) 绕过专业工具检测的Webshell研究文章和免杀的Webshell
- [**298**星][4y] [Py] [emposha/shell-detector](https://github.com/emposha/shell-detector)  a application that helps you find and identify php/cgi(perl)/asp/aspx shells. 
- [**189**星][1y] [Py] [he1m4n6a/findwebshell](https://github.com/he1m4n6a/findwebshell) 基于python开发的webshell检测工具。
- [**106**星][3y] [Py] [lingerhk/fshell](https://github.com/lingerhk/fshell) 基于机器学习的分布式webshell检测系统
- [**92**星][2y] [Py] [lcatro/webshell-detect-by-machine-learning](https://github.com/lcatro/webshell-detect-by-machine-learning) 使用机器学习识别WebShell
- [**85**星][2y] [Py] [hi-wenr0/mlcheckwebshell](https://github.com/hi-wenr0/mlcheckwebshell) 机器学习检测Webshell
- [**33**星][3y] [Py] [jkkj93/mint-webshell-defender](https://github.com/jkkj93/mint-webshell-defender) 薄荷WEBSHELL防御系统，是一款WEBSHELL查杀/防御软件，采用PYTHON编写
- [**33**星][2y] [Java] [mindawei/aliyun-safe-match](https://github.com/mindawei/aliyun-safe-match) Webshell和钓鱼网站检测（阿里云安全算法挑战赛 第29名）
- [**21**星][6m] [Py] [manhnho/shellsum](https://github.com/manhnho/shellsum) A defense tool - detect web shells in local directories via md5sum
- [**15**星][5m] [Java] [wh1t3p1g/monitorclient](https://github.com/wh1t3p1g/MonitorClient) 网站实时监控文件变动及webshell检测查杀工具
- [**12**星][2y] [Py] [mylamour/oops-webshell](https://github.com/mylamour/oops-webshell) Oops, It's funny to detect a webshell. Temporarily not maintained
- [**10**星][4y] [PHP] [k0u5uk3/obfuscated-php-webshell-detector](https://github.com/k0u5uk3/obfuscated-php-webshell-detector) obfuscated-php-webshell-detector - Detect PHP Webshell in obfusucation
- [**10**星][7m] [PHP] [th1k404/unishell](https://github.com/th1k404/unishell) A piece of php webshell which are using khmer unicode and yak obfuscator to be undetectable and silently.
- [**8**星][2y] [Py] [mrfk/webshellcheck](https://github.com/mrfk/webshellcheck) Webshell Detection Based on Deep Learning
- [**8**星][7m] [YARA] [mxi4oyu/riskdetect](https://github.com/mxi4oyu/riskdetect) 恶意软件以及webshell检测
- [**7**星][2y] [Py] [grayddq/codeinspect](https://github.com/grayddq/codeinspect) 以代码发布的方式，从根本上实现WEBShell、网马或恶意链接等安全方面的检测。
- [**2**星][2y] [Py] [zhl2008/webshell_detector](https://github.com/zhl2008/webshell_detector) webshell detector for iqiyi
- [**1**星][2y] [Py] [zhl2008/webshell_detector_haozi](https://github.com/zhl2008/webshell_detector_haozi) 


***


## <a id="b92430134aad35583d8470fb260406ed"></a>Webshell扫描


- [**99**星][3y] [Py] [ym2011/scanbackdoor](https://github.com/ym2011/scanbackdoor) Webshell扫描工具，通过各种规则和算法实现服务器脚本后门查杀
- [**46**星][2y] [Py] [erevus-cn/scan_webshell](https://github.com/erevus-cn/scan_webshell) 很简单的webshell扫描
- [**46**星][4y] [Py] [secwiki/scaing-backdoor](https://github.com/secwiki/scaing-backdoor) 新一代Webshell扫描工具
- [**31**星][5y] [Py] [jofpin/fuckshell](https://github.com/jofpin/fuckshell) Simple Webshell Scanner
- [**31**星][2y] [ysrc/shelldaddy](https://github.com/ysrc/shelldaddy) 跨平台 webshell 静态扫描器
- [**10**星][17d] [PHP] [cvar1984/sqlscan](https://github.com/cvar1984/sqlscan) Quick SQL Scanner, Dorker, Webshell injector PHP
- [**4**星][6y] [followboy1999/webshell-scanner](https://github.com/followboy1999/webshell-scanner) The Web Shell Scanner
- [**2**星][3y] [Py] [junyu1991/webshellscanner](https://github.com/junyu1991/webshellscanner) A jsp webshell scanner,based on regex .


***


## <a id="e89361c3ac1f1c35355f57601fb2f6e0"></a>其他


- [**33**星][3m] [JS] [medicean/superterm](https://github.com/medicean/superterm) 利用 webshell 创建交互式终端
- [**4**星][1y] [Py] [jincon/killshell](https://github.com/jincon/killshell) a webshell Killer write by python


# <a id="55572950f807e9e7c079edd49eab3dd0"></a>文章


***


## <a id="00afa6c71cbb358ba1c2b16fc8539112"></a>新添加


- 2019.12 [freebuf] [冰蝎动态二进制加密WebShell基于流量侧检测方案](https://www.freebuf.com/articles/web/221241.html)
- 2019.11 [aliyun] [绕过WebShell检测的总结之文件免杀](https://xz.aliyun.com/t/6784)
- 2019.10 [aliyun] [记一次webshell的获取](https://xz.aliyun.com/t/6587)
- 2019.10 [aliyun] [红蓝对抗——加密Webshell“冰蝎”攻防](https://xz.aliyun.com/t/6550)
- 2019.10 [nsfocus] [冰蝎动态二进制加密WebShell的检测](http://blog.nsfocus.net/hail-dynamic-binary-encryption-webshell-detection/)
- 2019.09 [hackingarticles] [Web Shells Penetration Testing](https://www.hackingarticles.in/web-shells-penetration-testing/)
- 2019.09 [freebuf] [冰蝎动态二进制加密WebShell特征分析](https://www.freebuf.com/articles/web/213905.html)
- 2019.08 [aliyun] [基于机器学习的jsp/jspx webshell检测](https://xz.aliyun.com/t/5994)
- 2019.08 [aliyun] [基于AST的Webshell检测](https://xz.aliyun.com/t/5848)
- 2019.07 [aliyun] [一道题回顾php异或webshell](https://xz.aliyun.com/t/5677)
- 2019.06 [aliyun] [PHP Webshell下绕过disable_function的方法](https://xz.aliyun.com/t/5320)
- 2019.05 [detectify] [How-to Tutorial: PHP Webshell De-Obfuscation](https://labs.detectify.com/2019/05/24/how-to-tutorial-php-webshell-de-obfuscation/)
- 2019.05 [detectify] [Investigation of PHP Web Shell Hexedglobals.3793 Variants](https://labs.detectify.com/2019/05/24/investigation-of-php-web-shell-hexedglobals-3793-variants/)
- 2019.05 [aliyun] [对于asp免杀webshell的一些总结](https://xz.aliyun.com/t/5193)
- 2019.05 [aliyun] [对于php免杀webshell的一些总结](https://xz.aliyun.com/t/5152)
- 2019.05 [freebuf] [聊聊安全测试中如何快速搞定Webshell](https://www.freebuf.com/articles/web/201421.html)
- 2019.04 [360] [Machine Learning Recognition of WebShell](https://www.anquanke.com/post/id/176645/)
- 2019.04 [secvul] [权限维持 - 如何优雅的隐藏你的Webshell](https://secvul.com/topics/2117.html)
- 2019.03 [freebuf] [SharPyShell：用于C# Web应用程序的小型混淆版WebShell](https://www.freebuf.com/sectool/198286.html)
- 2019.02 [rsa] [Web Shells and RSA NetWitness Part 3](https://community.rsa.com/community/products/netwitness/blog/2019/02/19/web-shells-and-netwitness-part-3)
- 2019.02 [freebuf] [通过Webshell远程导出域控ntds.dit的方法](https://www.freebuf.com/articles/web/195709.html)
- 2019.02 [rsa] [Web Shells and NetWitness Part 2](https://community.rsa.com/community/products/netwitness/blog/2019/02/13/web-shells-and-netwitness-part-2)
- 2019.02 [rsa] [Web Shells and RSA NetWitness](https://community.rsa.com/community/products/netwitness/blog/2019/02/12/web-shells-and-netwitness)
- 2019.01 [aliyun] [过D盾webshell分享](https://xz.aliyun.com/t/3959)
- 2019.01 [sans] [Closing the Door on Web Shells](https://www.sans.org/cyber-security-summit/archives/file/summit_archive_1493740667.pdf)
- 2019.01 [sans] [Hunting Webshells on Microsoft Exchange Server](https://www.sans.org/cyber-security-summit/archives/file/summit_archive_1492558615.pdf)
- 2019.01 [sans] [Hunting Webshells: Tracking TwoFace](https://www.sans.org/cyber-security-summit/archives/file/summit_archive_1536345486.pdf)
- 2018.12 [valeriyshevchenko] [From basic User to full right Admin access on the server (via XSS, LFI, WebShell)](https://medium.com/p/995f816a6da2)
- 2018.12 [aliyun] [通过webshell导出域控ntds.dit文件](https://xz.aliyun.com/t/3636)
- 2018.11 [freebuf] [一次编码WebShell bypass D盾的分析尝试](https://www.freebuf.com/articles/web/189097.html)
- 2018.09 [freebuf] [Webshell入侵检测初探（一）](http://www.freebuf.com/articles/web/183520.html)
- 2018.08 [aliyun] [利用tomcat的JMX端口上传webshell](https://xz.aliyun.com/t/2653)
- 2018.08 [nsfocus] [【事件分析】No.9 潘多拉魔盒般的Webshell上传](http://blog.nsfocus.net/webshell/)
- 2018.08 [360] [利用php自包含特性上传webshell](https://www.anquanke.com/post/id/153376/)
- 2018.07 [4hou] [错误页面中隐藏webshell的骚思路](http://www.4hou.com/web/12813.html)
- 2018.07 [mazinahmed] [Creating an Emojis PHP WebShell](https://blog.mazinahmed.net/2018/07/creating-emojis-php-webshell.html)
- 2018.06 [aliyun] [正面绕过Xyntax 大佬用机器学习实现的PHP WEBSHELL检测](https://xz.aliyun.com/t/2393)
- 2018.06 [freebuf] [不包含数字字母的WebShell](http://www.freebuf.com/articles/web/173579.html)
- 2018.05 [freebuf] [利用“进程注入”实现无文件复活 WebShell](http://www.freebuf.com/articles/web/172753.html)
- 2018.04 [mitchmoser] [Stapler pt. 2 — Webshells & Cronjobs](https://medium.com/p/549b13dbf3d3)
- 2018.04 [ironcastle] [Webshell looking for interesting files, (Wed, Apr 18th)](https://www.ironcastle.net/webshell-looking-for-interesting-files-wed-apr-18th/)
- 2018.03 [aliyun] [PHP反序列化漏洞与Webshell](https://xz.aliyun.com/t/2202)
- 2018.02 [360] [通过PHP扩展实现Webshell识别（一）](https://www.anquanke.com/post/id/98938/)
- 2018.02 [360] [一类混淆变形的Webshell分析](https://www.anquanke.com/post/id/98889/)
- 2018.02 [freebuf] [TinyShop缓存文件获取WebShell之0day](http://www.freebuf.com/vuls/161409.html)
- 2018.02 [venus] [初探机器学习检测 PHP Webshell](https://paper.seebug.org/526/)
- 2018.02 [aliyun] [深度学习PHP webshell查杀引擎demo](https://xz.aliyun.com/t/2016)
- 2017.12 [freebuf] [一个比较好玩的WebShell上传检测绕过案例](http://www.freebuf.com/articles/web/157557.html)
- 2017.12 [freebuf] [PHP WebShell变形技术总结](http://www.freebuf.com/articles/web/155891.html)
- 2017.12 [] [维持访问  WebShell](http://www.91ri.org/17340.html)
- 2017.09 [sans] [Another webshell, another backdoor!](https://isc.sans.edu/forums/diary/Another+webshell+another+backdoor/22826/)
- 2017.09 [secist] [从getwebshell到绕过安全狗云锁提权再到利用matasploit进服务器](http://www.secist.com/archives/4606.html)
- 2017.09 [polaris] [利用sklearn检测webshell](http://polaris-lab.com/index.php/archives/372/)
- 2017.09 [freebuf] [挖洞经验 | 把PHP LFI漏洞变成Webshell的思路](http://www.freebuf.com/articles/web/145861.html)
- 2017.08 [secist] [我与网站的日常-webshell命令执行](http://www.secist.com/archives/4246.html)
- 2017.07 [paloaltonetworks] [TwoFace Webshell: Persistent Access Point for Lateral](https://unit42.paloaltonetworks.com/unit42-twoface-webshell-persistent-access-point-lateral-movement/)
- 2017.07 [securityriskadvisors] [A Smaller, Better JSP Web Shell](http://securityriskadvisors.com/blog/post/a-smaller-better-jsp-web-shell/)
- 2017.07 [freebuf] [通过非数字和字符的方式实现PHP WebShell](http://www.freebuf.com/articles/web/138687.html)
- 2017.06 [aliyun] [如何优雅的维持一个Webshell](https://xz.aliyun.com/t/1130)
- 2017.05 [fuping] [MSSQL DBA权限获取WEBSHELL的过程](https://fuping.site/2017/05/16/MSSQL-DBA-Permission-GET-WEBSHELL/)
- 2017.05 [aliyun] [sa权限获取webshell思路](https://xz.aliyun.com/t/1152)
- 2017.05 [antonioparata] [Hiding PHP Webshell in an effective way](http://antonioparata.blogspot.com/2017/05/hiding-php-webshell-in-effective-way.html)
- 2017.05 [evi1cg] [Xsl Exec Webshell (aspx)](https://evi1cg.me/archives/Xsl_Exec_Webshell.html)
- 2017.05 [crowdstrike] [How to Detect and Prevent Fileless Webshell Attacks with Falcon](https://www.crowdstrike.com/blog/tech-center/falcon-prevents-fileless-webshell-attacks/)
- 2017.05 [niemand] [From 404 and default pages to RCE via .cshtml webshell](https://niemand.com.ar/2017/05/05/from-404-and-default-pages-to-rce-via-cshtml-webshell/)
- 2017.04 [freebuf] [Webshell密码极速爆破工具 – cheetah](http://www.freebuf.com/sectool/132096.html)
- 2017.04 [freebuf] [Python安全运维实战：针对几种特定隐藏方式的Webshell查杀](http://www.freebuf.com/articles/web/131350.html)
- 2017.04 [rsa] [From SQL Injection to WebShell](https://community.rsa.com/community/products/netwitness/blog/2017/04/10/from-sql-injection-to-webshell)
- 2017.03 [trustwave] [Authentication and Encryption in PAS Web Shell Variant](https://www.trustwave.com/Resources/SpiderLabs-Blog/Authentication-and-Encryption-in-PAS-Web-Shell-Variant/)
- 2017.03 [freebuf] [一款好用的php webshell检测工具](http://www.freebuf.com/sectool/128592.html)
- 2017.02 [secist] [一些不包含数字和字母的webshell](http://www.secist.com/archives/2784.html)
- 2017.02 [hackingarticles] [Webshell to Meterpreter](http://www.hackingarticles.in/webshell-to-meterpreter/)
- 2017.02 [hackingarticles] [Web Shells Penetration Testing (Beginner Guide)](http://www.hackingarticles.in/web-shells-penetration-testing-beginner-guide/)
- 2017.02 [8090] [关于一句话webshell的隐藏(建议)](http://www.8090-sec.com/archives/6721)
- 2017.01 [freebuf] [绕过网站安全狗拦截，上传Webshell技巧总结（附免杀PHP一句话）](http://www.freebuf.com/articles/web/125084.html)
- 2017.01 [secvul] [偶遇WEBSHELL老套路](https://secvul.com/topics/534.html)
- 2017.01 [4hou] [如何全面防御Webshell（下）？](http://www.4hou.com/technology/2301.html)
- 2016.12 [4hou] [如何全面防御Webshell（上）？](http://www.4hou.com/technology/2189.html)
- 2016.12 [trustwave] [Raiding the Piggy Bank: Webshell Secrets Revealed](https://www.trustwave.com/Resources/SpiderLabs-Blog/Raiding-the-Piggy-Bank--Webshell-Secrets-Revealed/)
- 2016.12 [sevagas] [TVT DVR/CCTV webshell exploit](https://blog.sevagas.com/?TVT-DVR-CCTV-webshell-exploit)
- 2016.12 [rapid7] [Web Shells 101: Detection and Prevention](https://blog.rapid7.com/2016/12/14/webshells-101/)
- 2016.12 [aliyun] [Tomcat、Weblogic、JBoss、GlassFish、Resin、Websphere弱口令及拿webshell方法总结](https://xz.aliyun.com/t/309)
- 2016.12 [8090] [php webshell分析和绕过waf技巧](http://www.8090-sec.com/archives/5849)
- 2016.12 [360] [php webshell分析和绕过waf技巧](https://www.anquanke.com/post/id/85083/)
- 2016.12 [dfir] [Webshells: Rise of the Defenders (Part 4)](https://dfir.it/blog/2016/12/07/webshells-rise-of-the-defenders-part-4/)
- 2016.11 [] [Winmail最新直达webshell 0day漏洞挖掘实录](http://www.91ri.org/16519.html)
- 2016.11 [securityintelligence] [Ninety-Five Percent of Webshell Attacks Written in PHP](https://securityintelligence.com/ninety-five-percent-of-webshell-attacks-written-in-php/)
- 2016.11 [freebuf] [中国最大的Webshell后门箱子调查，所有公开大马全军覆没](http://www.freebuf.com/news/topnews/118424.html)
- 2016.10 [threatexpress] [Web shells as a covert channel – SubShell & TinyShell](http://threatexpress.com/2016/10/web-shells-covert-channel/)
- 2016.09 [venus] [渗透攻防 - 千变万化的WebShell](https://paper.seebug.org/36/)
- 2016.08 [vanimpe] [Exploring webshells on a WordPress site](https://www.vanimpe.eu/2016/08/14/exploring-webshells-wordpress-site/)
- 2016.07 [freebuf] [中国新型Web Shell “菜刀-Cknife”遭国外安全公司曝光](http://www.freebuf.com/news/109776.html)
- 2016.07 [360] [​分析Cknife,一个类似China Chopper的webshell管理工具（第二部分）](https://www.anquanke.com/post/id/84249/)
- 2016.07 [sans] [The Power of Web Shells](https://isc.sans.edu/forums/diary/The+Power+of+Web+Shells/21257/)
- 2016.07 [securityintelligence] [The Webshell Game Continues](https://securityintelligence.com/the-webshell-game-continues/)
- 2016.07 [dfir] [Webshells - Every Time the Same Story…(Part 3)](https://dfir.it/blog/2016/07/06/webshells-every-time-the-same-story-dot-dot-dot-part-3/)
- 2016.07 [acunetix] [Web Shells in Action – Introduction to Web-Shells – Part 4](https://www.acunetix.com/blog/articles/web-shells-action-introduction-web-shells-part-4/)
- 2016.06 [acunetix] [Keeping web shells under cover – An Introduction to Web Shells – Part 3](https://www.acunetix.com/blog/articles/keeping-web-shells-undercover-an-introduction-to-web-shells-part-3/)
- 2016.06 [acunetix] [Web-shells 101 using PHP – Introduction to Web Shells – Part 2](https://www.acunetix.com/blog/articles/web-shells-101-using-php-introduction-web-shells-part-2/)
- 2016.06 [safebuff] [Bypass imagecopyresampled and imagecopyresized generate PHP Webshell](http://blog.safebuff.com/2016/06/17/Bypass-imagecopyresampled-and-imagecopyresized-generate-PHP-Webshell/)
- 2016.06 [fidelissecurity] [Understanding the Web Shell Game](https://www.fidelissecurity.com/threatgeek/2016/06/understanding-web-shell-game)
- 2016.06 [freebuf] [利用PHP 7中的OPcache来实现Webshell](http://www.freebuf.com/articles/105793.html)
- 2016.05 [freebuf] [看我如何绕过一个Webshell认证](http://www.freebuf.com/articles/web/104730.html)
- 2016.05 [sec] [从“TI（威胁情报）”到“IR（事件响应）”：从webshell的安全说开](https://www.sec-un.org/from-ti-threat-information-to-ir-incident-response-from-the-webshell-security-talk/)
- 2016.05 [sec] [威胁捕捉：推出针对webshell的“一手”情报feed](https://www.sec-un.org/threat-of-capture-launch-webshell-first-hand-information-feed/)
- 2016.05 [sec] [基于恶意行为的专项威胁情报Feed之：webshell-feed](https://www.sec-un.org/based-on-specific-threat-information-for-malicious-behavior-of-feed-webshell-feed/)
- 2016.05 [] [利用 Java Binary Webshell 对抗静态检测](http://www.91ri.org/15747.html)
- 2016.05 [tencent] [利用 Java Binary Webshell 对抗静态检测](https://security.tencent.com/index.php/blog/msg/104)
- 2016.04 [360] [利用PHP 7中的OPcache来实现Webshell](https://www.anquanke.com/post/id/83844/)
- 2016.04 [sec] [威胁情报Feed：Webshell之常用“路径&名字”字典](https://www.sec-un.org/threat-intelligence-feedwebshell-path-and-name-dictionary/)
- 2016.04 [freebuf] [C99 php webshell攻击加剧，大量WordPress站点遭受威胁](http://www.freebuf.com/news/101924.html)
- 2016.04 [securityintelligence] [Got WordPress? PHP C99 Webshell Attacks Increasing](https://securityintelligence.com/got-wordpress-php-c99-webshell-attacks-increasing/)
- 2016.04 [sec] [由Webshell溯源攻击者的入侵途径](https://www.sec-un.org/by-webshell-intrusion-way-to-trace-the-attacker/)
- 2016.03 [rsa] [Detecting and Investigating Webshells – Another Reason for Deepening Your Security Visibility](https://community.rsa.com/community/products/netwitness/blog/2016/03/29/detecting-and-investigating-webshells-another-reason-for-deepening-your-security-visibility)
- 2016.03 [sec] [线索、挖掘、预警—基于威胁情报的一起Webshell的安全分析](https://www.sec-un.org/analysis-of-traffic-safety-hate-mail-encrypting-ransomware-virus-attack-1-3/)
- 2016.03 [doyler] [Introducing RWSH – Ray’s Web SHell](https://www.doyler.net/security-not-included/introducting-rwsh-rays-web-shell)
- 2016.03 [sec] [webshell的隐藏、伪装技巧](https://www.sec-un.org/webshell-hide-disguise-techniques/)
- 2016.03 [caceriadespammers] [Web Shell Detector](http://www.caceriadespammers.com.ar/2016/03/web-shell-detector.html)
- 2016.03 [] [Webshell清除-解决驱动级文件隐藏挂马](http://www.91ri.org/15356.html)
- 2016.03 [] [有趣的小技巧，Webshell的克星](http://www.91ri.org/15348.html)
- 2016.01 [dfir] [Webshells - Every Time the Same Story…(Part 2)](https://dfir.it/blog/2016/01/18/webshells-every-time-the-same-story-dot-dot-dot-part2/)
- 2016.01 [rsa] [Hunting Webshells with RSA ECAT](https://community.rsa.com/community/products/netwitness/blog/2016/01/14/hunting-webshells-with-rsa-ecat)
- 2016.01 [sec] [Metasploit Webshell初探](https://www.sec-un.org/study-on-the-metasploit-webshell/)
- 2015.12 [] [Webshell安全检测篇（2）-深入用户的内心](http://www.91ri.org/14928.html)
- 2015.12 [] [Webshell安全检测篇（1）-基于流量的检测方式](http://www.91ri.org/14927.html)
- 2015.12 [] [Webshell安全检测篇（3）-基于行为分析来发现“未知的Webshell”](http://www.91ri.org/14931.html)
- 2015.12 [] [Webshell安全检测篇（4）-基于流量的Webshell分析样例](http://www.91ri.org/14936.html)
- 2015.12 [] [Webshell系列（5）- webshell之“看见”的能力分析](http://www.91ri.org/14949.html)
- 2015.12 [sec] [结合威胁情报的Webshell事件处理谈（2）–攻击者画像与机读IOC](https://www.sec-un.org/webshell-event-handling-with-threat-information-about-2-portrait-of-attacker-and-machine-readable-ioc/)
- 2015.12 [sec] [如何检测隐藏的Webshell（三） Weevely.img](https://www.sec-un.org/how-to-detect-hidden-webshell-c-weevely-img/)
- 2015.12 [toolswatch] [[New Tool] quasiBot v0.3 Beta Complex Webshell Manager](http://www.toolswatch.org/2015/12/new-tool-quasibot-v0-3-beta-complex-webshell-manager/)
- 2015.12 [] [webshell检测－日志分析](http://www.91ri.org/14841.html)
- 2015.12 [sec] [高隐藏性webshell分析：Weevely 3.2 Backdoor流量特征（一）](https://www.sec-un.org/analysis-of-high-hidden-webshell-weevely-3-2-backdoor-flow-characteristics-a/)
- 2015.12 [sec] [Webshell安全检测（3）： WeBaCoo网站后门特征分析](https://www.sec-un.org/webshell-security-testing-3-characteristic-analysis-of-webacoo-web-site-back/)
- 2015.12 [sec] [Webshell安全检测（4）:Weevely  样本后门特征分析](https://www.sec-un.org/webshell-security-testing-4-characteristic-analysis-of-sample-weevely-backdoor/)
- 2015.12 [sec] [机读IOC文件下载–结合情报的Webshell分析](https://www.sec-un.org/webshell-event-handling-with-threat-information-about-3-marc-ioc-documents/)
- 2015.12 [sec] [结合威胁情报的Webshell事件处理谈（1）–结合kill chain的攻击还原](https://www.sec-un.org/webshell-event-handling-with-threat-information-about-1-attacks-combined-with-the-kill-chain-reduction/)
- 2015.11 [sec] [Webshell系列（5）- webshell之“看见”的能力分析](https://www.sec-un.org/webshell-5-webshell-see-capacity-analysis/)
- 2015.11 [sec] [Webshell安全检测篇（4）-基于流量的Webshell分析样例](https://www.sec-un.org/webshell-security-testing-4-webshell-based-on-flow-analysis-sample/)
- 2015.11 [] [DZ6.x的UC_KEY getwebshell exploit](http://www.91ri.org/14642.html)
- 2015.11 [checkpoint] [Check Point Threat Alert: Web Shells](https://blog.checkpoint.com/2015/11/19/check-point-threat-alert-web-shells/)
- 2015.11 [sec] [Webshell安全检测篇（3）-基于行为分析来发现“未知的Webshell”](https://www.sec-un.org/webshell-security-detection-3-based-on-behavioral-analysis-to-discover-unknown-webshell/)
- 2015.11 [ironcastle] [TA15-314A: Compromised Web Servers and Web Shells – Threat Awareness and Guidance](https://www.ironcastle.net/ta15-314a-compromised-web-servers-and-web-shells-threat-awareness-and-guidance/)
- 2015.11 [sec] [Webshell安全检测篇（2）-深入用户的内心](https://www.sec-un.org/webshell-security-testing-2-go-deep-inside-the-user/)
- 2015.11 [sec] [Webshell安全检测篇（1）-基于流量的检测方式](https://www.sec-un.org/webshell-security-testing-1-based-traffic-detection/)
- 2015.10 [freebuf] [B374K PHP WEBSHELL：一款简单却功能强大的远程管理工具](http://www.freebuf.com/sectool/82015.html)
- 2015.09 [evi1cg] [Linux查webshell](https://evi1cg.me/archives/Webshell_find.html)
- 2015.08 [] [APT时代-窃密型WebShell检测方法的思考](http://www.91ri.org/14003.html)
- 2015.08 [dfir] [Webshells - Every Time the Same Purpose, Every Time a Different Story… (Part 1)](https://dfir.it/blog/2015/08/12/webshell-every-time-the-same-purpose/)
- 2015.07 [freebuf] [窃密型WebShell检测方法](http://www.freebuf.com/articles/others-articles/71604.html)
- 2015.07 [n0where] [Stealthy PHP Web Shell Backdoor: Weevely](https://n0where.net/stealthy-php-web-shell-backdoor-weevely)
- 2015.06 [sec] [APT时代-窃密型WebShell检测方法的思考](https://www.sec-un.org/ideas-like-article-espionage-webshell-method/)
- 2015.05 [] [MS15-051 修正版Exploit(Webshell可用)](http://www.91ri.org/12860.html)
- 2015.05 [] [另类Webshell：Xml Shell简介](http://www.91ri.org/12824.html)
- 2015.03 [crowdstrike] [Chopping packets: Decoding China Chopper Web shell traffic over SSL](https://www.crowdstrike.com/blog/chopping-packets-decoding-china-chopper-web-shell-traffic-over-ssl/)
- 2015.02 [vxsecurity] [[ Technical Teardown: PHP WebShell ]](http://www.vxsecurity.sg/2015/02/27/technical-teardown-php-webshell/)
- 2015.02 [freebuf] [技术分享：如何在PNG图片的IDAT CHUNKS中插入Webshell](http://www.freebuf.com/articles/web/58278.html)
- 2015.01 [s1gnalcha0s] [SSJS Web Shell Injection](https://s1gnalcha0s.github.io/node/2015/01/31/SSJS-webshell-injection.html)
- 2015.01 [securityblog] [A quick and dirty php web shell](http://securityblog.gr/2179/a-quick-and-dirty-php-web-shell/)
- 2014.12 [freebuf] [ModSecurity技巧：使用ssdeep检测Webshell](http://www.freebuf.com/sectool/54222.html)
- 2014.12 [freebuf] [批量Webshell管理工具QuasiBot之后门代码分析](http://www.freebuf.com/sectool/53554.html)
- 2014.12 [n0tr00t] [批量 Webshell 管理工具 QuasiBot 之后门代码分析](https://n0tr00t.com/2014/12/04/quasibot-backdoor-analysis.html)
- 2014.12 [] [用Webshell直接杀入内网](http://www.91ri.org/11318.html)
- 2014.11 [] [Webshell实现与隐藏探究](http://www.91ri.org/11494.html)
- 2014.09 [room362] [OSX Persistence via PHP Webshell ·](https://malicious.link/post/2014/osx-persistence-via-php-webshell/)
- 2014.08 [3xp10it] [隐藏webshell的几条建议](http://3xp10it.cc/web/2016/07/28/%E9%9A%90%E8%97%8Fwebshell/)
- 2014.08 [3xp10it] [一句话webshell客户端脱库](http://3xp10it.cc/web/2016/11/25/%E4%B8%80%E5%8F%A5%E8%AF%9Dwebshell%E5%AE%A2%E6%88%B7%E7%AB%AF%E8%84%B1%E5%BA%93/)
- 2014.08 [3xp10it] [unserialize免杀webshell](http://3xp10it.cc/web/2017/04/18/unserialize%E5%85%8D%E6%9D%80webshell/)
- 2014.08 [3xp10it] [php中&引用免杀webshell](http://3xp10it.cc/web/2017/04/25/php%E4%B8%AD&%E5%BC%95%E7%94%A8%E5%85%8D%E6%9D%80/)
- 2014.08 [3xp10it] [自动测试上传功能是否可上传webshell](http://3xp10it.cc/web/2018/04/25/%E8%87%AA%E5%8A%A8%E6%B5%8B%E8%AF%95%E4%B8%8A%E4%BC%A0%E5%8A%9F%E8%83%BD%E6%98%AF%E5%90%A6%E5%8F%AF%E4%B8%8A%E4%BC%A0webshell/)
- 2014.08 [3xp10it] [自动测试上传功能是否可上传webshell](http://3xp10it.cc/web/2018/04/25/%E8%87%AA%E5%8A%A8%E6%B5%8B%E8%AF%95%E4%B8%8A%E4%BC%A0%E5%8A%9F%E8%83%BD%E6%98%AF%E5%90%A6%E5%8F%AF%E4%B8%8A%E4%BC%A0webshell/)
- 2014.08 [3xp10it] [unserialize免杀webshell](http://3xp10it.cc/web/2017/04/18/unserialize%E5%85%8D%E6%9D%80webshell/)
- 2014.08 [3xp10it] [php中&引用免杀webshell](http://3xp10it.cc/web/2017/04/25/php%E4%B8%AD&%E5%BC%95%E7%94%A8%E5%85%8D%E6%9D%80/)
- 2014.08 [3xp10it] [一句话webshell客户端脱库](http://3xp10it.cc/web/2016/11/25/%E4%B8%80%E5%8F%A5%E8%AF%9Dwebshell%E5%AE%A2%E6%88%B7%E7%AB%AF%E8%84%B1%E5%BA%93/)
- 2014.08 [3xp10it] [隐藏webshell的几条建议](http://3xp10it.cc/web/2016/07/28/%E9%9A%90%E8%97%8Fwebshell/)
- 2014.08 [n0where] [php-webshells](https://n0where.net/php-webshells)
- 2014.08 [freebuf] [揭秘渗透测试利器：Webshell批量管理工具QuasiBot](http://www.freebuf.com/sectool/40411.html)
- 2014.08 [] [PHPCMS后台低权限拿webSHELL](http://0day5.com/archives/2015/)
- 2014.06 [freebuf] [用搜索神器Everything定位Webshell木马后门](http://www.freebuf.com/articles/web/37122.html)
- 2014.06 [toolswatch] [[New Tool] Antak WebShell – PowerShell Console Released](http://www.toolswatch.org/2014/06/antak-webshell-powershell-console-released/)
- 2014.05 [] [科讯KESION CMS最新版任意文件上传WEBSHELL](http://0day5.com/archives/1613/)
- 2014.04 [] [[投稿]Webshell下命令执行限制及绕过方法](http://www.91ri.org/8700.html)
- 2014.04 [netspi] [Executing MSF Payloads via PowerShell Webshellery](https://blog.netspi.com/executing-msf-payloads-via-powershell-webshellery/)
- 2014.04 [] [[投稿]Webshell 远程提权](http://www.91ri.org/8618.html)
- 2014.03 [webroot] [Commercial Windows-based compromised Web shells management application spotted in the wild – part two](https://www.webroot.com/blog/2014/03/13/commercial-windows-based-compromised-web-shells-management-application-spotted-wild-part-two/)
- 2014.02 [crowdstrike] [Mo’ Shells Mo’ Problems – Deep Panda Web Shells](https://www.crowdstrike.com/blog/mo-shells-mo-problems-deep-panda-web-shells/)
- 2014.01 [freebuf] [浅谈webshell检测方法](http://www.freebuf.com/articles/web/23358.html)
- 2013.12 [webroot] [Commercial Windows-based compromised Web shells management application spotted in the wild](https://www.webroot.com/blog/2013/12/04/commercial-windows-based-compromised-web-shells-management-application-spotted-wild/)
- 2013.12 [freebuf] [《一个路径牵出连环血案》之三“向玩webshell的黑客钓鱼”（连载）](http://www.freebuf.com/articles/web/18841.html)
- 2013.11 [imperva] [Threat Advisory: A JBoss AS Exploit, Web Shell code Injection.](https://www.imperva.com/blog/2013/11/threat-advisory-a-jboss-as-exploit-web-shell-code-injection/)
- 2013.10 [] [最新一种过安全狗的webshell](http://www.91ri.org/7496.html)
- 2013.10 [] [php LFI读php文件源码以及直接post webshell](http://www.91ri.org/7469.html)
- 2013.10 [trustwave] [Hiding Webshell Backdoor Code in Image Files](https://www.trustwave.com/Resources/SpiderLabs-Blog/Hiding-Webshell-Backdoor-Code-in-Image-Files/)
- 2013.10 [] [齐博CMS GETWEBSHELL 0day](http://www.91ri.org/7392.html)
- 2013.08 [] [Webshell过安全狗的几种技巧[附特征免杀法]](http://www.91ri.org/7135.html)
- 2013.08 [] [高版本正方教务系统上传后缀过滤不严导致能直接上传Webshell](http://0day5.com/archives/716/)
- 2013.08 [] [PJ博客批量可以获取webshell](http://0day5.com/archives/710/)
- 2013.08 [] [用ZendGuard 加密php webshell](http://www.91ri.org/6901.html)
- 2013.07 [] [打破MS13-046不能webshell执行问题](http://www.91ri.org/6708.html)
- 2013.06 [trustwave] [[Honeypot Alert] Inside the Attacker's Toolbox: Webshell Usage Logging](https://www.trustwave.com/Resources/SpiderLabs-Blog/-Honeypot-Alert--Inside-the-Attacker-s-Toolbox--Webshell-Usage-Logging/)
- 2013.05 [tencent] [浅谈变形PHP WEBSHELL检测](https://security.tencent.com/index.php/blog/msg/19)
- 2013.05 [forcepoint] [WebShells WebShells on the Web Server](https://www.forcepoint.com/blog/security-labs/webshells-webshells-web-server)
- 2013.04 [netspi] [Adding PowerShell to Web Shells to get Database Access](https://blog.netspi.com/adding-powershell-to-web-shells-to-get-database-access/)
- 2013.04 [freebuf] [查找phpwebshell小工具](http://www.freebuf.com/sectool/8341.html)
- 2013.03 [] [旁注虚拟主机IIS权限重分配跨目录得webshell](http://www.91ri.org/5487.html)
- 2013.03 [freebuf] [分离Weevely加密模块加密任意WebShell](http://www.freebuf.com/sectool/7875.html)
- 2013.03 [] [解决Win下MySQL root导出Webshell换行符问题](http://www.91ri.org/5387.html)
- 2013.02 [] [siteserver后台getwebshell 8种方法](http://0day5.com/archives/350/)
- 2013.01 [freebuf] [Metasploit之使用socket通信的webshell简单分析](http://www.freebuf.com/articles/web/6740.html)
- 2013.01 [] [解密php webshell后门](http://www.91ri.org/5033.html)
- 2012.12 [] [Siteserver cms后台拿webshell另一种方法](http://0day5.com/archives/277/)
- 2012.11 [freebuf] [反向Web Shell处理工具-Shell of the Future](http://www.freebuf.com/sectool/6319.html)
- 2012.10 [freebuf] [[笔记]PHP一句话Webshell变形总结](http://www.freebuf.com/articles/web/5896.html)
- 2012.10 [] [利用社工绕道突破安全狗直取webshell](http://www.91ri.org/4387.html)
- 2012.09 [] [帝国cms最新版本后台拿webshell方法](http://0day5.com/archives/222/)
- 2012.08 [] [[挖0day]羊驼CMS 注入及getwebshell](http://www.91ri.org/3788.html)
- 2012.08 [toolswatch] [Web Shell Detector v1.62 – The Shell Scanner](http://www.toolswatch.org/2012/08/web-shell-detector-v1-62-the-shell-scanner/)
- 2012.07 [] [ShyPost企业网站管理系统V4.3注入XSS漏洞及后台拿webshell](http://0day5.com/archives/192/)
- 2012.07 [] [直接给asp防注入getwebshell](http://www.91ri.org/3403.html)
- 2012.06 [freebuf] [Webshell代码检测背后的数学应用](http://www.freebuf.com/articles/4240.html)
- 2012.06 [freebuf] [利用grep查找webshell](http://www.freebuf.com/articles/4074.html)
- 2012.06 [freebuf] [Webshell扫描工具WebShellDetector V1.51](http://www.freebuf.com/sectool/3939.html)
- 2012.06 [talosintelligence] [Web Shell Poses As A GIF](https://blog.talosintelligence.com/2012/06/web-shell-poses-as-gif.html)
- 2012.06 [idontplaydarts] [Encoding Web Shells in PNG IDAT chunks](https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/)
- 2012.05 [freebuf] [配置Apache防止webshell上传](http://www.freebuf.com/articles/2465.html)
- 2012.05 [] [SiteEngine 7.1 会员上传漏洞拿WEBSHELL](http://0day5.com/archives/133/)
- 2012.05 [] [91736cms Getip SQL Injection & 后台妙拿 WebShell](http://0day5.com/archives/123/)
- 2011.11 [] [WebShell的检测技术](http://www.91ri.org/2440.html)
- 2011.09 [] [突破VirtualWall上传webshell](http://www.91ri.org/2165.html)
- 2011.09 [toolswatch] [XCode SQLi/LFI/XSS and Webshell Scanning tool](http://www.toolswatch.org/2011/09/xcode-sqlilfixss-and-webshell-scanning-tool/)
- 2011.08 [] [access 导出webshell](http://www.91ri.org/1953.html)
- 2011.08 [] [Webshell下命令行跨站](http://www.91ri.org/7012.html)


# 贡献
内容为系统自动导出, 有任何问题请提issue