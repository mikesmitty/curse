# CURSE: Certificate Utilization for Robust SSH Ephemerality

CURSE is an SSH certificate signing server, built as an alternative to Netflix's BLESS tool, but without a dependency on AWS.

This software is currently in an alpha state and not recommended for use.

Requirements
------------
* OpenSSH 5.6+  
* CentOS 7
* Ubuntu 12.04+

Because SSH certificates are a relatively recent feature in OpenSSH, older versions of CentOS unfortunately do not support their use.

TODO
----
* ~~Authentication~~
* Document Authentication Setup
* ~~SSL support~~
* ~~Add support for maximum pubkey ages~~
* Client app
* More configuration options
* Per-user access ACLs

Maybe Somedays
--------------
* Interactive ssh client for command logging
