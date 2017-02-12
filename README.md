# CURSE: Certificate Utilization for Robust SSH Ephemerality

CURSE is an SSH certificating signing server, built as an alternative to Netflix's BLESS tool, but without the AWS dependencies.

This software is currently in a pre-alpha state and not recommended for use.

Requirements
------------
* OpenSSH 5.6+  
* CentOS 7
* Ubuntu 12.04+

Because SSH certificates are a relatively recent feature in OpenSSH, regrettably older versions of CentOS do not support their use.

TODO
----
* Authentication
* SSL support
* Client app
* More configuration options
* Per-user access ACLs

Maybe Somedays
--------------
* Interactive ssh client for command logging
