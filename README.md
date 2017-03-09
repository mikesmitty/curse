# CURSE

CURSE is an SSH certificate signing server, built as an alternative to Netflix's BLESS tool, but without a dependency on AWS.

## Demo

![gif](http://i.imgur.com/UtDkYNo.gif)

This software is currently in a beta state, feel free to submit issues on GitHub with any suggestions for improvement/feature requests or issues encountered.

Table of Contents
-----------------

* [Requirements](#requirements)
* [Install](#install)
  * [Ubuntu](#ubuntu)
  * [CentOS](#centos)
* [TLS Mutual Auth Setup (password-less)](#tls-mutual-auth-setup-password-less)
* [TODO List](#todo)

Requirements
------------
* OpenSSH 5.6+  
* CentOS 7
* Ubuntu 14.04+ (Destination servers)
* Ubuntu 15.10+ (Server running CURSE daemon)

Because SSH certificates are a relatively recent feature in OpenSSH, older versions of CentOS unfortunately do not support their use.

Install
-------
These instructions assume the bastion host is hosting the curse daemon. Adjust instructions as necessary if hosting cursed on another server, but for security reasons the reverse proxy and cursed service should always be hosted on the same server unless you have valid SSL certificates for both the reverse proxy and CURSE daemon, and have the `proxy_ssl_verify` setting enabled in nginx.

###Ubuntu

**Ubuntu 15.10+**

First, install the debian repo and GPG key:

    $ sudo sh -c 'echo "deb http://mirror.go-repo.io/curse/deb/ curse main" >/etc/apt/sources.list.d/curse.list'
    $ sudo apt-key adv --keyserver keyserver.ubuntu.com --recv 0732065B92735F2F

Update and install nginx, curse and jinx:

    $ sudo apt-get update && sudo apt-get install curse jinx nginx

Run the curse SSH CA keypair/SSL certificate generation script:

    $ sudo bash /opt/curse/sbin/setup.sh

This will output your CA public key to be added to destination servers, and helpful nginx setup commands.

Next, copy the nginx client SSL certificates to the nginx folder, as well as the curse nginx config:

    $ sudo cp -a /opt/curse/etc/cursed-client.{key,crt} /opt/curse/etc/cursed-ca_cert.crt /etc/nginx/
    $ sudo cp -a /opt/curse/etc/cursed.conf-nginx /etc/nginx/conf.d/cursed.conf

At this time, you will want to make sure you have a valid SSL cert ready for your nginx server (from Let's Encrypt or any other valid certificate authority).  
Edit the nginx config to update your `server_name` setting to match your SSL certificate FQDN, configure the valid SSL certs you got from your certificate authority (`/etc/nginx/cert.pem` and `/etc/nginx/key.pem` by default) as well as configure your authentication settings.  
If using basic authentication, you'll need to install `apache2-utils` to get the htpasswd tool, and create your htpasswd file at `/etc/nginx/htpasswd`.

    $ sudo vim /etc/nginx/conf.d/cursed.conf

Once your authentication is configured and certificates in place, restart nginx:

    $ sudo systemctl restart nginx

Update the `url` setting to match your SSL certificate FQDN in the jinx config (and edit any settings you would like to change):

    $ sudo vim /etc/jinx/jinx.yaml

If all went well you should now be able to request certificates:

    $ jinx echo test
    $ ssh-keygen -Lf ~/.ssh/id_jinx-cert.pub

Now, all that is left is to add the CA public key on the servers you want to connect to:

Add `TrustedUserCAKeys /etc/ssh/cas.pub` to `/etc/ssh/sshd_config` on your destination servers and
Put the contents of `/opt/curse/etc/user_ca.pub` into your /etc/ssh/cas.pub on the destination server.

Netflix recommends generating several CA keypairs and storing the private keys of all but one offline, in order to simplify CA key rotation. If you choose to do this you will want to also add the pubkeys of all of your CA keypairs to the `/etc/ssh/cas.pub` file at this time as well.

###CentOS

**CentOS 7**

**NOTICE**: If upgrading from CURSE 0.7 you will need to do some manual cleanup after installing the rpm.  
Versions 0.8+ use TLS mutual authentication between the reverse proxy and the curse daemon, and no longer support basic auth which was used in 0.7.
* After installing the new curse rpm, remove the old curse daemon SSL certificate/key: `mv /opt/curse/etc/server.key{,.old}` `mv /opt/curse/etc/server.crt{,.old}`
* Run `/opt/curse/sbin/setup.sh` again to generate the mutual auth certificates (if you have not yet removed the old server.key and server.crt, this will not work properly)
* Import your nginx customizations to (and update `server_name` field in) the new template file: `/opt/curse/etc/cursed.conf-nginx` and copy it to `/etc/nginx/conf.d/`
* Reload nginx to use the new config

First, install nginx:

    $ sudo yum install epel-release
    $ sudo yum install nginx

    $ sudo rpm --import https://mirror.go-repo.io/curse/centos/RPM-GPG-KEY-GO-REPO
    $ sudo curl -s https://mirror.go-repo.io/curse/centos/curse-repo.repo | tee /etc/yum.repos.d/curse-repo.repo
    $ sudo yum install curse jinx

After install setup (generates keys and proxy config):  
Please note the -a flag in the cp command, the permissions on this config file must be 600 to prevent open access to the curse daemon.

    $ sudo bash /opt/curse/sbin/setup.sh
    $ sudo cp -a /opt/curse/etc/cursed.conf-nginx /etc/nginx/conf.d/cursed.conf

Install/configure your SSL certificates authentication settings for the reverse proxy. Don't forget to set your `server_name` to match your valid SSL certificates as well:

    $ sudo vim /etc/nginx/conf.d/cursed.conf

Once your authentication is configured and certificates in place, restart nginx:

    $ sudo systemctl restart nginx

Copy the jinx config template into place and update the `url` setting to match your SSL certificate FQDN:

    $ sudo cp /etc/jinx/jinx.yaml-example /etc/jinx/jinx.yaml
    $ sudo vim /etc/jinx/jinx.yaml

If all went well you should now be able to request certificates:

    $ jinx echo test
    $ ssh-keygen -Lf ~/.ssh/id_jinx-cert.pub

Now, all that is left is to add the CA public key on the servers you want to connect to:

Add `TrustedUserCAKeys /etc/ssh/cas.pub` to `/etc/ssh/sshd_config` and
Put the contents of `/opt/curse/etc/user_ca.pub` into your /etc/ssh/cas.pub on the destination server.

Netflix recommends generating several CA keypairs and storing the private keys of all but one offline, in order to simplify CA key rotation. If you choose to do this you will want to also add the pubkeys of all of your CA keypairs to the `/etc/ssh/cas.pub` file at this time as well.

###TLS Mutual Auth Setup (password-less)

If you would like to avoid typing your password in each time when generating a certificate you can configure TLS mutual auth for jinx. This configuration also has the side benefit of not requiring a valid SSL certificate from an external certificate authority.

The first step is to generate your server's certificate and key, making sure that `CN=...` matches your nginx FQDN, if not using localhost-only:

    $ cd /etc/nginx/
    $ sudo openssl ecparam -genkey -name secp384r1 -out jinx-ca.key
    $ sudo openssl req -new -x509 -sha256 -key jinx-ca.key -out jinx-ca.crt -days 730 -subj "/C=US/ST=State/L=Locality/O=NGINX/CN=localhost"
    $ sudo chmod 600 jinx-ca.key
    $ sudo chmod 644 jinx-ca.crt
    $ sudo chown root. jinx-ca.key jinx-ca.crt

Update your nginx config to use this certificate and key for SSL, update your authentication config, and the `proxy_set_header REMOTE_USER` setting as shown below.

***NOTE***
Configure these fields:
`ssl_certificate`
`ssl_certificate_key`
`ssl_client_certificate`
`ssl_verify_client`
`proxy_set_header REMOTE_USER $ssl_client_fingerprint`

Disable these fields:
`auth_basic` 
`auth_basic_user_file` 
`proxy_set_header REMOTE_USER $remote_user`;

Example:

```
server {
  listen       127.0.0.1:443 ssl http2;
  server_name  localhost;

  ssl                       on;
  ssl_ciphers               'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
  ssl_prefer_server_ciphers on;
  ssl_session_tickets       off;
  #ssl_certificate           /etc/nginx/cert.pem;
  #ssl_certificate_key       /etc/nginx/key.pem;
  ssl_certificate           /etc/nginx/jinx-ca.crt;
  ssl_certificate_key       /etc/nginx/jinx-ca.key;

  # Enable with client-side TLS mutual auth
  ssl_client_certificate    /etc/nginx/jinx-ca.crt;
  ssl_verify_client         on;

  location / {
      root                 /usr/share/nginx/html;
      index                index.html index.htm;

      # Comment these fields if not using htpasswd-style authentication (and update with your own auth settings)
      #auth_basic           "Restricted";
      #auth_basic_user_file /etc/nginx/htpasswd;

      proxy_pass                    https://localhost:81;
      proxy_ssl_protocols           TLSv1.2;
      proxy_ssl_ciphers             'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
      proxy_ssl_certificate         /etc/nginx/cursed-client.crt;
      proxy_ssl_certificate_key     /etc/nginx/cursed-client.key;
      proxy_ssl_trusted_certificate /etc/nginx/cursed-ca_cert.crt;
      proxy_ssl_verify              on;
      proxy_set_header              Host        $host;

      # Use with basic auth
      #proxy_set_header              REMOTE_USER $remote_user;

      # Use with TLS mutual auth
      proxy_set_header              REMOTE_USER $ssl_client_fingerprint;
  }
}
```

Reload nginx after making your updates:

    $ sudo systemctl reload nginx

Copy the jinx-ca.crt file to `/etc/jinx/`:

    $ sudo cp /etc/nginx/jinx-ca.crt /etc/jinx/ca.crt

Update the jinx config to enable TLS mutual auth (add or update `mutualauth: true`):

    $ sudo vim /etc/jinx/jinx.yaml

Next, for each user you'll need to generate a client certificate, and be sure to replace `username_here` with their username:

    $ export USERNAME="username_here"
    $ mkdir -p /home/$USERNAME/.jinx/client.key
    $ openssl ecparam -genkey -name secp384r1 -out /home/$USERNAME/.jinx/client.key
    $ chmod 600 /home/$USERNAME/.jinx/client.key
    $ openssl req -new -key /home/$USERNAME/.jinx/client.key -out /home/$USERNAME/.jinx/client.csr -subj "/C=US/ST=State/L=Locality/O=NGINX/CN=$USERNAME"
    
NOTE: You'll want to increment the `-set_serial` argument for each client certificate:

    $ sudo openssl x509 -req -sha256 -in /home/$USERNAME/.jinx/client.csr -CA /etc/nginx/jinx-ca.crt -CAkey /etc/nginx/jinx-ca.key -days 730  -set_serial 01 -out /home/$USERNAME/.jinx/client.crt
    $ sudo chown -R $USERNAME. /home/$USERNAME/.jinx/

If all went well, your users should now be able to request SSH certificates without entering credentials:

    $ jinx
    $ ssh-keygen -Lf ~/.ssh/id_jinx-cert.pub

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
* ~~RPM/DEB packages for easier installation~~
* Per-user access ACLs

Maybe Somedays
--------------
* Interactive ssh client for command logging
