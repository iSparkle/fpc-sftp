This is a LibSSH SFTP Server built in FPC on Windows 10

=== Simple SFTP Server ===

A bare-bones minumum SFTP host written in 396 lines of code. I was able to get Filezilla to connect to it and show the "file list". 

SimpleSFTPServer is only a teaching apparatus; it has no mechanisms to support get/put of files or any other SFTP comments. It can only support one incoming connection at a time.

Limitations: It has ugly memory issues; I've learned that the callbacks do not have a very big stack. THIS IS NOT DESIGNED for actual use. Only learning.

=== Sparkle-FTP Server ===

This will be the actual multi-threaded, multi-client application. I hope to have it working soon (late-spring at worst)
