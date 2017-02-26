#!/bin/bash

# Requires:
# openssl
# openssh
# libcap || libcap2-bin (debian/ubuntu)

CURSE_ROOT="/opt/curse"
CURSE_ALGO="ed25519"

# Create curse system user account
NOLOGIN=$(which nologin)
getent passwd curse >/dev/null || useradd -r -m -d "$CURSE_ROOT" -s $NOLOGIN curse
chmod 700 "$CURSE_ROOT"
chown curse. "$CURSE_ROOT"

# Generate SSH CA keypair
if [ ! -e "$CURSE_ROOT/etc/user_ca" ] && [ ! -e "$CURSE_ROOT/etc/user_ca.pub" ]; then
    echo "Generating $CURSE_ALGO SSH CA certificates..."
    ssh-keygen -q -N "" -t "$CURSE_ALGO" -f "$CURSE_ROOT/etc/user_ca"
    chmod 600 "$CURSE_ROOT/etc/user_ca"
    chmod 644 "$CURSE_ROOT/etc/user_ca.pub"
    echo "$CURSE_ALGO SSH CA keypair generated. Here is the CA PubKey for adding to your servers:"
    echo
    cat "$CURSE_ROOT/etc/user_ca.pub"
    echo
    echo
    echo "This key can also be found at $CURSE_ROOT/etc/user_ca.pub"
else
    echo "SSH CA keypair already exists. Skipping generation."
fi

# Generate SSL key and certificate
if [ ! -e "$CURSE_ROOT/etc/server.key" ] || [ ! -e "$CURSE_ROOT/etc/server.crt" ]; then
    echo
    echo "Generating SSL certificates..."
    openssl ecparam -genkey -name secp384r1 -out "$CURSE_ROOT/etc/server.key"
    openssl req -new -x509 -sha256 -key "$CURSE_ROOT/etc/server.key" -out "$CURSE_ROOT/etc/server.crt" -days 730 \
        -subj "/C=US/ST=State/L=Location/O=CURSE/CN=localhost"
    chmod 600 "$CURSE_ROOT/etc/server.key"
    chmod 644 "$CURSE_ROOT/etc/server.crt"
else
    echo "SSL certificates already exist. Skipping generation."
fi

# Generate SSL client key/certs for proxy authentication
if [ ! -e "$CURSE_ROOT/etc/cursed-client.key" ]; then
    echo
    echo "Generating client cert for proxy..."
    openssl ecparam -genkey -name secp384r1 -out "$CURSE_ROOT/etc/cursed-client.key"
    openssl req -new -key "$CURSE_ROOT/etc/cursed-client.key" -out "$CURSE_ROOT/etc/cursed-client.csr" -subj "/C=US/ST=State/L=Location/O=NGINX/CN=localhost"
    openssl x509 -req -sha256 -in "$CURSE_ROOT/etc/cursed-client.csr" -CA "$CURSE_ROOT/etc/server.crt"  -days 730 \
        -CAkey "$CURSE_ROOT/etc/server.key" -set_serial 01 -out "$CURSE_ROOT/etc/cursed-client.crt"
    cp -f "$CURSE_ROOT/etc/server.crt" "$CURSE_ROOT/etc/cursed-ca_cert.crt"

    rm -f "$CURSE_ROOT/etc/cursed-client.csr"

    chmod 600 "$CURSE_ROOT/etc/cursed-client.key"
    chmod 644 "$CURSE_ROOT/etc/cursed-client.crt"
    chmod 644 "$CURSE_ROOT/etc/cursed-ca_cert.crt"

    echo "Generated client certificates for cursed and nginx. Please copy them to /etc/nginx/ or your preferred HTTP server's config directory:"
    ls -l $CURSE_ROOT/etc/cursed-client.{key,crt} $CURSE_ROOT/etc/cursed-ca_cert.crt
    echo
    echo "cp -a $CURSE_ROOT/etc/cursed-client.{key,crt} $CURSE_ROOT/etc/cursed-ca_cert.crt /etc/nginx/"
    echo
    echo "If using nginx, copy $CURSE_ROOT/etc/cursed.conf-nginx to /etc/nginx/conf.d/cursed.conf or manually include it in your nginx.conf file, after adding your desired configuration settings."
    echo
    echo "cp -a $CURSE_ROOT/etc/cursed.conf-nginx /etc/nginx/conf.d/cursed.conf"
    echo
else
    echo "$CURSE_ROOT/etc/cursed.yaml already exists. Leaving existing config file, but please review $CURSE_ROOT/etc/cursed.yaml-example for any new configuration settings."
fi

# Generate credentials for configuration files
if [ ! -e "$CURSE_ROOT/etc/cursed.yaml" ]; then
    cp -n "$CURSE_ROOT/etc/cursed.yaml-example" "$CURSE_ROOT/etc/cursed.yaml"
    chmod 600 "$CURSE_ROOT/etc/cursed.yaml"
    chown curse. "$CURSE_ROOT/etc/cursed.yaml"

    echo
    echo "Generated config files for cursed and nginx:"
    echo "$CURSED_ROOT/etc/cursed.yaml"
    echo "$CURSED_ROOT/etc/cursed-nginx.conf"
    echo "If using nginx, please move $CURSE_ROOT/etc/cursed.conf-nginx to /etc/nginx/conf.d/ or manually include it in your nginx.conf file after adding your desired configuration settings."
else
    echo "$CURSE_ROOT/etc/cursed.yaml already exists. Leaving existing config file, but please review $CURSE_ROOT/etc/cursed.yaml-example for any new configuration settings."
fi

# Fix curse directory permissions
chown -R curse. "$CURSE_ROOT"
chown root. "$CURSE_ROOT/etc/cursed-client.key"
chown root. "$CURSE_ROOT/etc/cursed-client.crt"
chown root. "$CURSE_ROOT/etc/cursed-ca_cert.crt"
chown root. "$CURSE_ROOT/etc/cursed.conf-nginx"

# This will allow us to run on a privileged port without root privileges
/usr/sbin/setcap 'cap_net_bind_service=+ep' /opt/curse/sbin/cursed

# Install systemd service
PKG_CONFIG=$(pkg-config systemd --variable=systemdsystemunitdir)
if  [ "$PKG_CONFIG" != "" ]; then
    echo
    echo "Installing cursed systemd service..."
    SETCAP=$(which setcap)
    sed "s|SETCAP|$SETCAP|" "$CURSE_ROOT/etc/cursed.service" >"$PKG_CONFIG/cursed.service"
    systemctl daemon-reload
    systemctl enable cursed.service
    systemctl start cursed.service
else
    echo "Systemd unit file directory not found, you will need to install and configure cusred.service manually, or create a startup script for cursed"
fi
