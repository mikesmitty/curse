# CURSE: Certificate Utilization for Robust SSH Ephemerality

CURSE is an SSH certificate signing server, built as an alternative to Netflix's BLESS tool, but without a dependency on AWS.

## Demo

![gif](http://i.imgur.com/UtDkYNo.gif)

This software is currently in a beta state, feel free to submit issues on GitHub with any issues encountered.

Requirements
------------
* OpenSSH 5.6+  
* CentOS 7
* Ubuntu 12.04+

Because SSH certificates are a relatively recent feature in OpenSSH, older versions of CentOS unfortunately do not support their use.

Install
-------
These instructions assume the bastion host is hosting the curse daemon. Adjust instructions as necessary if hosting cursed on another server, but for security reasons the reverse proxy and cursed service should always be hosted on the same server at this time.

**CURSE Daemon Installation**

First, ensure you have a working Go environment (prebuilt packages will be available in the future).

Add a curse service user (as root):

    $ sudo useradd -r -m -d "/opt/curse" -s /usr/sbin/nologin curse

`go get` the daemon and client:

    $ go get github.com/mikesmitty/curse/cursed
    $ go get github.com/mikesmitty/curse/jinx

Create directories inside the curse directory and set their permission:

    $ sudo mkdir -p /opt/curse/{etc,sbin}
    $ sudo chown -R curse. /opt/curse/
    $ sudo chmod 700 /opt/curse/

Copy the cursed binary (built in the go get command) to the curse path:

    $ sudo mv $GOPATH/bin/cursed /opt/curse/sbin/

Copy the jinx client to your prefered system path:

    $ sudo mv $GOPATH/bin/jinx /usr/bin/

**Install cursed Systemd Service**

You can use whatever method you prefer for running, but a systemd unit file has been added for convenience. Please note that the setcap command in the unit file is necessary to run on a privileged port as an unprivileged user. On Debian/Ubuntu you will likely need to install the `libcap2-bin` package, and the setcap binary is found at `/sbin/setcap` instead of `/usr/sbin/setcap`.

Edit the unit file if necessary, and copy the unit file to your systemd system directory. This will either be `/usr/lib/systemd/system/` or `/lib/systemd/system/`, and you can find out which by running the following command: `pkg-config systemd --variable=systemdsystemunitdir`

    $ cp $GOPATH/src/github/mikesmitty/curse/cursed.service cursed.service
    $ vim cursed.service
    $ sudo mv cursed.service /usr/lib/systemd/system/
    $ sudo systemctl daemon-reload
    $ sudo systemctl start cursed.service

**Configure cursed**

Generate your CA keypair and move it to the cursed config directory. Elliptic curve algorithms (ed25519, ecdsa) are strongly recommended, provided all your servers support them. If elliptic curves are not viable in your environment, RSA with a bit size of 4096 or greater is recommended.

    $ ssh-keygen -t ed25519 -f ./user_ca
    $ sudo mv user_ca user_ca.pub /opt/curse/etc/
    $ sudo chmod 600 /opt/curse/etc/user_ca
    $ sudo chmod 644 /opt/curse/etc/user_ca.pub

Next, generate SSL certificates for the curse daemon and move them to the curse config directory. Feel free to adjust certificate lifespan to a reasonable level:

    $ openssl ecparam -genkey -name secp384r1 -out server.key
    $ openssl req -new -x509 -sha256 -key server.key -out server.crt -days 730
    $ sudo mv server.key server.crt /opt/curse/etc/
    $ sudo chmod 600 /opt/curse/etc/server.key
    $ sudo chmod 644 /opt/curse/etc/server.crt
    $ sudo chown -R curse. /opt/curse/etc/

Copy the example cursed config file and edit it. The following fields are required:
* cakeyfile (SSH CA key file: `/opt/curse/etc/user_ca` in this example)
* proxyuser (used to authenticate the proxy to the curse daemon)
* proxypass
* sslcert (SSL key file location: `/opt/curse/etc/server.crt` in this example)
* sslkey (SSL cert file location: `/opt/curse/etc/server.key` in this example)

The curse daemon's port can be changed, but should be kept to a privileged port (below 1024) for security reasons.

    $ cp $GOPATH/src/github.com/mikesmitty/curse/cursed.yaml.example cursed.yaml
    $ vim cursed.yaml
    $ sudo mv cursed.yaml /opt/curse/etc/

Be sure to restrict file permissions on the cursed.yaml config file:

    $ sudo chmod 600 /opt/curse/etc/cursed.yaml
    $ sudo chown -R curse. /opt/curse/etc/

**Reverse Proxy Setup**

The reverse proxy should have a valid SSL certificate configured. Feel free to use Let's Encrypt or any other reputable cert provider, as long as the certificate can be verified (i.e. not a self-signed certificate). If this is not feasible, you can use self-signed certificates and enable the insecure flag in the jinx config file, but this is not recommended whatsoever for production use.

If using nginx, copy and edit the provided template, adjusting the following fields:
* server_name (needs to match your valid SSL certificate's FQDN)
* ssl_certificate (ssl certificate filename, should be chowned root)
* ssl_certificate_key (ssl key filename, should be chowned root, chmod 600)
* proxy_set_header Authorization (replace BASICAUTHSTRINGHERE with a base64-encoded string of the proxyuser and proxypass fields from the cursed setup earlier, like so: `echo -n 'proxyuser_goes_here:proxypass_goes_here' | base64`

At this point you will also need to configure authentication for the reverse proxy, which provides authentication for the curse daemon. You can use any authentication that nginx (or apache, provided you have opted for it) provides, such as htpasswd file authentication, local authentication using PAM, or LDAP authentication. If using htpasswd authentication be sure to `chown root.` and `chmod 600` your htpasswd file.

    $ cp $GOPATH/src/github.com/mikesmitty/curse/cursed.conf-example.nginx cursed.conf
    $ vim cursed.conf
    $ sudo mv cursed.conf /etc/nginx/conf.d/
    $ sudo chown root. /etc/nginx/conf.d/cursed.conf
    $ sudo chmod 600 /etc/nginx/conf.d/cursed.conf

If you want to use htpasswd-file authentication simply uncomment the `auth_basic` and `auth_basic_user_file` entries in the provided cursed.conf-example.nginx file and add users to your htpasswd file:

    $ sudo yum install httpd-tools # install the htpasswd utility
    $ sudo htpasswd -c /etc/nginx/htpasswd USERNAME_GOES_HERE
    $ sudo chmod 600 /etc/nginx/htpasswd
    $ sudo chown root. /etc/nginx/htpasswd

**Configure jinx**

Copy the example cursed config file and edit it with the commands below. The following fields are required:
* bastionip (if auto-detection of your bastion server's public IP fails)
* pubkey (if you do not want CURSE to periodically regenerate your SSH keys)
* url (URL of the proxy server, which should match your reverse proxy's hostname and SSL certificate)

Note: Jinx can be configured with a system-wide file at `/etc/jinx/jinx.yaml`
For testing purposes, `~/.jinx/jinx.yaml` can be used as well, but if `/etc/jinx/jinx.yaml` exists it will be ignored in favor of the system file.

    $ cp $GOPATH/src/github.com/mikesmitty/curse/jinx.yaml-example jinx.yaml
    $ vim jinx.yaml
    $ sudo mkdir /etc/jinx
    $ sudo mv jinx.yaml /etc/jinx/
    $ sudo chmod 755 /etc/jinx/
    $ sudo chmod 644 /etc/jinx/jinx.yaml
    $ sudo chown root. /etc/jinx/jinx.yaml

**Test Service**

By this point, you should have a working instance of CURSE, and you generate a certificate by running `jinx`, then inspecting the certificate file, which will be created in the folder with your pubkey, by running (substitute the proper filename based on the name of your pubkey)`ssh-keygen -Lf ~/.ssh/id_ed25519-cert.pub`

**Configuring Remote Hosts**

In order for hosts to allow logins with certificates you'll need to do the following:

* Add `TrustedUserCAKeys /etc/ssh/cas.pub` to `/etc/ssh/sshd_config`
* Add the contents of your CA private key (`/opt/curse/etc/user_ca.pub`) to `/etc/ssh/cas.pub` like you would a regular `authorized_keys` file.

Netflix recommends generating several CA keypairs and storing the private keys of all but one offline, in order to simplify CA key rotation. If you choose to do this you will want to also add the pubkeys of all of your CA keypairs to the `/etc/ssh/cas.pub` file at this time as well.

TODO
----
* ~~Authentication~~
* ~~Document Authentication Setup~~
* ~~SSL support~~
* ~~Add support for maximum pubkey ages in daemon~~
* ~~Client app~~
* ~~More configuration options~~
* ~~Add support for maximum pubkey ages in client and automatic key regeneration~~
* ~~Add support for key algorithm enforcement/auto-key-generation~~
* RPM/DEB packages for easier installation
* Per-user access ACLs

Maybe Somedays
--------------
* Interactive ssh client for command logging
