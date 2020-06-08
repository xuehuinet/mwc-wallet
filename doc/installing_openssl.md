The latest versions of mwc-wallet require openssl 1.1 to be installed on the system. Some popoular distributions of Linux
(like Ubuntu 16.04) have an older version of openssl and cannot be upgraded via package manager. In order to install openssl
1.1 on those systems, the following steps are required:

1.) Ensure the system has gcc and make (on ubuntu, this can be done with the following commands:
# apt upgrade
# apt install gcc make

2.) Obtain the openssl 1.1 sources. They can be obtained from the official website here: https://www.openssl.org/source/

3.) cd into the source directory and run config script:
# ./config

4.) build using make
# make

5.) Install using make install (note: you may need root permission for this command):
# make install

6.) Add /usr/local/lib (the default library installation directory) to your LD_LIBRARY_PATH variable
# export LD_LIBRARY_PATH=/usr/local/lib

7.) Execute mwc-wallet command
# mwc-wallet --help

Note: you may want to add this LD_LIBRARY_PATH to your login shell so that you don't have to set it each time before running
mwc-wallet.
