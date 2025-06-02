This is a LibSSH SFTP Server built in FPC

OS Windows 10. Lazarus IDE, target Win64. FPC 3.2.2

=== **Simple SFTP Server** ===

A bare-bones minumum SFTP host written in 396 lines of code. I was able to get Filezilla to connect to it and show the "file list". 

SimpleSFTPServer has no mechanisms to support get/put of files or any other SFTP commands. It can only support one incoming connection at a time.

Limitations: It has ugly memory issues; I've learned that the callbacks do not have a very big heap. This IS NOT DESIGNED for actual use.

=== **Sparkle-FTP Server** ===

This is the actual multi-threaded, multi-client application. I ran it for 72-hrs and ~2k connections per hour, so we can say it's not crashy.

Important: Generate your own RSA key if you plan to expose this server to the world. I've committed one into GitHub to help you get up and running faster, but it's therefore compromised.

Command-Line: fpcSTFP /child_process
(eg run an instance and you can enable live console debugging)

Command-Line: fpcSTFP /install
(Create a Windows service. You'll see it pop up in services.msc and should be able to launch it from there. There will still be logs by default.)

To code for this, see: ConnectionClass := TMySTPConnection; You'll basically override the default TConnection and replace the read/write calls with your own. I'm going to be using TMemDataset to shield the file system from bad actors. Also exposing the Windows file system is not convenient because of CP1252 which will mangle filenames.
