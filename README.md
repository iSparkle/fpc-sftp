This is a LibSSH SFTP Server built in FPC

OS Windows 10. I used Lazarus IDE target Win64. Tried both  FPC2.x and FPC3.06

=== Simple SFTP Server ===

A bare-bones minumum SFTP host written in 396 lines of code. I was able to get Filezilla to connect to it and show the "file list". 

SimpleSFTPServer has no mechanisms to support get/put of files or any other SFTP commands. It can only support one incoming connection at a time.

Limitations: It has ugly memory issues; I've learned that the callbacks do not have a very big stack. This IS NOT DESIGNED for actual use.

=== Sparkle-FTP Server ===

This will be the actual multi-threaded, multi-client application. I'll use events to help keep it OS agnostic. I hope to have it working soon (late-spring at worst)
