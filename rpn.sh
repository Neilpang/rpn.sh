#!/usr/bin/env bash

DEFAULT_HOME="$HOME/.rpn"


if [ -z "$RPN_HOME" ] ; then
  RPN_HOME="$DEFAULT_HOME"
fi

N_VER="1.9.12"

SBIN="/usr/sbin/nginx"
CACHE="/var/cache/nginx"
NGINX_HOME="/etc/nginx"
CONFPATH="$NGINX_HOME/conf.d"
SSLPATH="$CONFPATH/ssl"
PID="/var/run/nginx.pid"

ACME=/root/.acme.sh/acme.sh

_debug() {
  if [ -z "$DEBUG" ] ; then
    return
  fi
  if [ -z "$2" ] ; then
    echo $1
  else
    echo "$1"="$2"
  fi
}

_info() {
  if [ -z "$2" ] ; then
    echo "$1"
  else
    echo "$1"="$2"
  fi
}

_err() {
  if [ -z "$2" ] ; then
    echo "$1" >&2
  else
    echo "$1"="$2" >&2
  fi
  return 1
}


buildnginx() {
  apt-get update
  
  for i in curl git  build-essential libc6 libpcre3 libpcre3-dev libpcrecpp0 libpcrecpp0v5 libssl-dev zlib1g-dev lsb-base libgeoip-dev libgd2-xpm-dev libatomic-ops-dev libxml2-dev libxslt1-dev ; do
    apt-get  install -y  $i
  done


  curl http://nginx.org/download/nginx-$N_VER.tar.gz -O
  

  tar xzf nginx-$N_VER.tar.gz
  
  cd nginx-$N_VER
  
  mkdir -p $CACHE/client_temp
  mkdir -p $CACHE/proxy_temp
  mkdir -p $CACHE/fastcgi_temp
  mkdir -p $CACHE/uwsgi_temp
  mkdir -p $CACHE/scgi_temp
  
  ./configure --prefix=/etc/nginx \
  --sbin-path=$SBIN \
  --conf-path=/etc/nginx/nginx.conf \
  --error-log-path=/var/log/nginx/error.log \
  --http-log-path=/var/log/nginx/access.log \
  --pid-path=$PID \
  --lock-path=/var/run/nginx.lock \
  --http-client-body-temp-path=$CACHE/client_temp \
  --http-proxy-temp-path=$CACHE/proxy_temp \
  --http-fastcgi-temp-path=$CACHE/fastcgi_temp \
  --http-uwsgi-temp-path=$CACHE/uwsgi_temp \
  --http-scgi-temp-path=$CACHE/scgi_temp \
  --user=nginx \
  --group=nginx \
  --with-http_ssl_module \
  --with-http_realip_module \
  --with-http_addition_module \
  --with-http_sub_module \
  --with-http_dav_module \
  --with-http_flv_module \
  --with-http_mp4_module \
  --with-http_gunzip_module \
  --with-http_gzip_static_module \
  --with-http_random_index_module \
  --with-http_secure_link_module \
  --with-http_stub_status_module \
  --with-http_auth_request_module \
  --with-mail \
  --with-mail_ssl_module \
  --with-file-aio \
  --with-http_v2_module \
  --with-cc-opt='-g -O2 -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2' \
  --with-ld-opt='-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,--as-needed' \
  --with-ipv6 \
  --with-http_sub_module

  make
  
  mkdir -p "$$CACHE"
  mkdir -p "$CONFPATH"
  mkdir -p "$SSLPATH"
  
  cd nginx-$N_VER
  
  make install
  cd ..
  
  useradd nginx
  
  chown -R nginx:nginx $CACHE


  
}



_installsystemd() {
  
echo "
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=$PID
ExecStartPre=$SBIN -t
ExecStart=$SBIN
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
" > /lib/systemd/system/nginx.service

  systemctl daemon-reload

}

_installupstart() {
echo "
description \"nginx http daemon\"
author \"George Shammas <georgyo@gmail.com>\"

start on (filesystem and net-device-up IFACE=lo)
stop on runlevel [!2345]

env DAEMON=$SBIN
env PID=$PID

expect fork
respawn
respawn limit 10 5
#oom never

pre-start script
        \$DAEMON -t
        if [ \$? -ne 0 ]
                then exit \$?
        fi
end script

exec \$DAEMON
" > /etc/init/nginx.conf

  initctl reload-configuration
  initctl list | grep nginx
  initctl start nginx


}

install() {

  mkdir -p "$RPN_HOME"
  cp  rpn.sh "$RPN_HOME/"
  cp  *.conf "$RPN_HOME/"
  
  if command -v systemctl > /dev/null ; then
    _installsystemd
  else 
    _installupstart
  fi
  
  cp nginx.conf  /etc/nginx/nginx.conf
  
  service nginx start 
  service nginx status
  

  
  PRF="$(_detect_profile)"
  
  if [ "$PRF" ] ; then
    _setopt "$PRF" "alias rpn=$RPN_HOME/rpn.sh"
  fi
  
  if command -v curl >/dev/null 2>&1 ; then
    curl  https://get.acme.sh | sh
  elif command -v wget >/dev/null 2>&1 ; then
    wget -O-  https://get.acme.sh | sh
  fi
}



add() {
  if [ -z "$1" ] ; then
    _err "Usage: add 'aa.com www.aa.com'  'http[s]://www.google.com'"
    return 1
  fi
  
  domainlist="$1"
  uphost="$2"

  
  maindomain="$(printf "$domainlist" | cut -d ' ' -f 1)"
  domainconf="$RPN_HOME/$maindomain.conf"
  cp $RPN_HOME/server.conf "$domainconf"
  
  _setopt "$domainconf" "    server_name" " " "$domainlist" ";"
  

  _setopt "$domainconf" "        proxy_pass" " " "$uphost" ";"

  if echo $uphost | grep '[0-9]*.[0-9]*.[0-9]*.[0-9]*' > /dev/null ; then
    updomain=$maindomain
  else
    updomain="$(echo $uphost | cut -d : -f 2 | tr -d "/")"
    sed -i  "/#subfilter/a \       sub_filter $updomain $maindomain;"  "$domainconf"
  fi

  _setopt "$domainconf" "        proxy_set_header Host" " " "$updomain" ";"
  
  mv "$domainconf" "$CONFPATH"
  service nginx restart


}


issuecert() {

  site="$1"
  if [ -z "$site" ] ; then
    echo  "Usage: site"
    return 1
  fi

  domainconf="$CONFPATH/$site.conf"
  if [ ! -f $domainconf ] ; then
    echo "$domainconf not found"
    return 1
  fi

  if ! sed -i "s|#\(location.*#acme$\)|\\1|" "$domainconf" ; then
    echo "#acme sed error."
    return 1
  fi
  service nginx restart

  $ACME --issue \
  $(grep -o "server_name.*;$" "$domainconf" | tr  -d ';' | sed "s/server_name//" | sed "s/ / -d /g") \
  -w $NGINX_HOME/html
  
  if [ "$?" != "0" ] ; then
    echo "issue cert error."
    return 1
  fi

  if ! sed -i "s|\(location.*#acme$\)|#\\1|" "$domainconf" ; then
    echo "#acme restore error."
    return 1
  fi
  service nginx restart
}


addssl() {
  domainlist="$1"
  uphost="$2"
  cert="$3"
  key="$4"
  ca="$5"
  
  if [ -z "$domainlist" ] ; then
    _err "Usage: addssl 'aa.com www.aa.com'  'http[s]://www.google.com'  [/path/to/aa.cer  /path/to/aa.key  /path/to/aa.ca]"
    return 1
  fi
  
  maindomain="$(printf "$domainlist" | cut -d ' ' -f 1)"
  sslconf="$RPN_HOME/$maindomain.ssl.conf"
  cp $RPN_HOME/serverssl.conf "$sslconf"
  
  _setopt "$sslconf" "    server_name" " " "$domainlist" ";"
  
  if [ "$cert" ] ; then
    cp "$cert" "$SSLPATH/$maindomain.cer"
    cp "$key"  "$SSLPATH/$maindomain.key"
    
    if [ "$ca" ] ; then
      echo ""  >> "$SSLPATH/$maindomain.cer"
      cat "$ca" >> "$SSLPATH/$maindomain.cer"
    fi
  else
    if ! issuecert $maindomain ; then
      echo "can not issue cert."
      return 1
    fi
    
    $ACME --installcert \
    -d $maindomain \
    --keypath "$SSLPATH/$maindomain.key" \
    --fullchainpath "$SSLPATH/$maindomain.cer" \
    --reloadcmd "service nginx reload"
    if [ "$?" != "0" ] ; then
      echo "install cert error"
      return 1
    fi
  fi
  
  _setopt "$sslconf" "    ssl_certificate" " " "$SSLPATH/$maindomain.cer" ";"
  _setopt "$sslconf" "    ssl_certificate_key" " " "$SSLPATH/$maindomain.key" ";"
  
  _setopt "$sslconf" "        proxy_pass" " " "$uphost" ";"

  if echo $uphost | grep '[0-9]*.[0-9]*.[0-9]*.[0-9]*' > /dev/null ; then
    updomain=$maindomain
  else
    updomain="$(echo $uphost | cut -d : -f 2 | tr -d "/")"
    sed -i  "/#subfilter/a \        sub_filter $updomain $maindomain;"  "$sslconf"
  fi
  
  _setopt "$sslconf" "        proxy_set_header Host" " " "$updomain" ";"

  
  
  mv "$sslconf" "$CONFPATH"
  service nginx restart
}



#setopt "file"  "opt"  "="  "value" [";"]
_setopt() {
  __conf="$1"
  __opt="$2"
  __sep="$3"
  __val="$4"
  __end="$5"
  if [ -z "$__opt" ] ; then 
    echo usage: $0  '"file"  "opt"  "="  "value" [";"]'
    return
  fi
  if [ ! -f "$__conf" ] ; then
    touch "$__conf"
  fi
  if grep -H -n "^$__opt$__sep" "$__conf" > /dev/null ; then
    _debug OK
    if [[ "$__val" == *"&"* ]] ; then
      __val="$(echo $__val | sed 's/&/\\&/g')"
    fi
    text="$(cat $__conf)"
    echo -n "$text" | sed "s|^$__opt$__sep.*$|$__opt$__sep$__val$__end|" > "$__conf"
  else
    _debug APP
    echo "$__opt$__sep$__val$__end" >> "$__conf"
  fi
  _debug "$(grep -H -n "^$__opt$__sep" $__conf)"
}

# Detect profile file if not specified as environment variable
_detect_profile() {
  if [ -n "$PROFILE" -a -f "$PROFILE" ]; then
    echo "$PROFILE"
    return
  fi

  local DETECTED_PROFILE
  DETECTED_PROFILE=''
  local SHELLTYPE
  SHELLTYPE="$(basename "/$SHELL")"

  if [ "$SHELLTYPE" = "bash" ]; then
    if [ -f "$HOME/.bashrc" ]; then
      DETECTED_PROFILE="$HOME/.bashrc"
    elif [ -f "$HOME/.bash_profile" ]; then
      DETECTED_PROFILE="$HOME/.bash_profile"
    fi
  elif [ "$SHELLTYPE" = "zsh" ]; then
    DETECTED_PROFILE="$HOME/.zshrc"
  fi

  if [ -z "$DETECTED_PROFILE" ]; then
    if [ -f "$HOME/.profile" ]; then
      DETECTED_PROFILE="$HOME/.profile"
    elif [ -f "$HOME/.bashrc" ]; then
      DETECTED_PROFILE="$HOME/.bashrc"
    elif [ -f "$HOME/.bash_profile" ]; then
      DETECTED_PROFILE="$HOME/.bash_profile"
    elif [ -f "$HOME/.zshrc" ]; then
      DETECTED_PROFILE="$HOME/.zshrc"
    fi
  fi

  if [ ! -z "$DETECTED_PROFILE" ]; then
    echo "$DETECTED_PROFILE"
  fi
}

list() {
  ls -l $CONFPATH/*.conf
}

showhelp() {
  _info "Usage: buildnginx|install|add|addssl|list"
}

if [ -z "$1" ] ; then
  showhelp
else
  "$@"
fi
