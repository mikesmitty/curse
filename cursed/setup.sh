#!/bin/bash

# Requires:
# openssl
# openssh
# libcap || libcap2-bin (debian/ubuntu)

SCRIPT_NAME=$0
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
    echo -e "$CURSE_ALGO SSH CA keypair generated. Here is the CA PubKey for adding to your servers:\n\n`cat \"$CURSE_ROOT/etc/user_ca.pub\"`\n\nThis key can also be found at $CURSE_ROOT/etc/user_ca.pub"
else
    echo "SSH CA keypair already exists. Skipping generation."
fi

# Generate SSL key and certificate
if [ ! -e "$CURSE_ROOT/etc/server.key" ] && [ ! -e "$CURSE_ROOT/etc/server.crt" ]; then
    echo "Generating SSL certificates..."
    openssl ecparam -genkey -name secp384r1 -out "$CURSE_ROOT/etc/server.key"
    openssl req -new -x509 -sha256 -key "$CURSE_ROOT/etc/server.key" -out "$CURSE_ROOT/etc/server.crt" -days 730 \
        -subj "/C=US/ST=State/L=Location/O=Org/CN=CURSE"
    chmod 600 "$CURSE_ROOT/etc/server.key"
    chmod 644 "$CURSE_ROOT/etc/server.crt"
else
    echo "SSL certificates already exist. Skipping generation."
fi

# Generate credentials for configuration files
if [ ! -e "$CURSE_ROOT/etc/curse.yaml" ]; then
    echo "Generating proxy credentials..."
    PROXY_USER=$(openssl rand -base64 12)
    PROXY_PASS=$(openssl rand -base64 12)
    AUTH_STRING=$(echo -n "$PROXY_USER:$PROXY_PASS" | base64)

    sed -e "s|PROXYUSER_GOES_HERE|$PROXY_USER|" -e "s|PROXYUSER_GOES_HERE|$PROXY_USER|" "$CURSE_ROOT/etc/cursed.yaml-example" >"$CURSE_ROOT/etc/cursed.yaml"
    chmod 600 "$CURSE_ROOT/etc/cursed.yaml"
    chown curse. "$CURSE_ROOT/etc/cursed.yaml"

    sed "s|BASICAUTHSTRINGHERE|$AUTH_STRING|" "$CURSE_ROOT/etc/cursed.conf-example.nginx" >"$CURSE_ROOT/etc/cursed.conf-nginx"
    chmod 600 "$CURSE_ROOT/etc/cursed.conf-nginx"
    chown root. "$CURSE_ROOT/etc/cursed.conf-nginx"

    echo -e "Generated config files for cursed and nginx:\n$CURSED_ROOT/etc/cursed.yaml\n$CURSED_ROOT/etc/cursed-nginx.conf"
    echo "If using nginx, please move $CURSE_ROOT/etc/cursed.conf-nginx to /etc/nginx/conf.d/ or manually include it in your nginx.conf file after adding your desired configuration settings."
else
    echo "$CURSE_ROOT/etc/cursed.yaml already exists. Leaving existing config file, but please review $CURSE_ROOT/etc/cursed.yaml-example for any new configuration settings."
fi

# Fix curse directory permissions
chown -R curse. "$CURSE_ROOT"

# Install systemd service
PKG_CONFIG=$(pkg-config systemd --variable=systemdsystemunitdir)
if  [ "$PKG_CONFIG" != "" ]; then
    echo "Installing cursed systemd service..."
    SETCAP=$(which setcap)
    sed "s|SETCAP|$SETCAP|" "$CURSE_ROOT/etc/cursed.service" >"$PKG_CONFIG/cursed.service"
    systemctl daemon-reload
    systemctl enable cursed.service
    systemctl start cursed.service
else
    echo "Systemd unit file directory not found, you will need to install and configure cusred.service manually, or create a startup script for cursed"
fi

# This will allow us to run on a privileged port without root privileges
/usr/sbin/setcap 'cap_net_bind_service=+ep' /opt/curse/sbin/cursed
