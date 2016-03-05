#!/usr/bin/env bash

DEFAULT_HOME="$HOME/.rpn"


if [ -z "$RPN_HOME" ] ; then
  RPN_HOME="$DEFAULT_HOME"
fi

N_VER="1.9.12"

SBIN="/usr/sbin/nginx"
CACHE="/var/cache/nginx"
CONFPATH="/etc/nginx/conf.d"
SSLPATH="$CONFPATH/ssl"


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
  apt-get  install -y curl git  build-essential libc6 libpcre3 libpcre3-dev libpcrecpp0 libssl-dev zlib1g-dev lsb-base libgeoip-dev libgd2-xpm-dev libatomic-ops-dev libxml2-dev libxslt1-dev

  git clone https://github.com/yaoweibin/ngx_http_substitutions_filter_module.git

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
  --pid-path=/var/run/nginx.pid \
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
  --add-module=../ngx_http_substitutions_filter_module

  make
  
  mkdir -p "$$CACHE"
  mkdir -p "$CONFPATH"
  mkdir -p "$SSLPATH"
  
}



_installsystemd() {
  
echo "
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
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

install() {
  cd nginx-$N_VER
  
  make install
  cd ..
  
  useradd nginx
  
  chown -R nginx:nginx $CACHE
  
  
  _installsystemd
  cp nginx.conf  /etc/nginx/nginx.conf
  service nginx start 
  service nginx status
  
  mkdir -p "$RPN_HOME"
  cp  rpn.sh "$RPN_HOME/"
  cp  *.conf "$RPN_HOME/"
  
  PRF="$(_detect_profile)"
  
  if [ "$PRF" ] ; then
    _setopt "$PRF" "alias rpn=$RPN_HOME/rpn.sh"
  fi
  
}



add() {
  if [ -z "$1" ] ; then
    _err "Usage: addssl 'aa.com www.aa.com'  'http[s]://www.google.com'"
    return 1
  fi
  
  domainlist="$1"
  uphost="$2"

  
  maindomain="$(printf "$domainlist" | cut -d ' ' -f 1)"
  domainconf="$RPN_HOME/$maindomain.conf"
  cp $RPN_HOME/server.conf "$domainconf"
  
  _setopt "$domainconf" "    server_name" " " "$domainlist" ";"
  

  _setopt "$domainconf" "  		proxy_pass" " " "$uphost" ";"

  updomain="$(echo $uphost| cut -d : -f 2 | tr -d "/")"

  _setopt "$domainconf" "  		proxy_set_header Host" " " "$updomain" ";"
  
  _setopt "$domainconf" "		proxy_set_header Referert" " " "$uphost" ";"  
  
  mv "$domainconf" "$CONFPATH"
  service nginx reload


}

addssl() {
  if [ -z "$1" ] ; then
    _err "Usage: addssl 'aa.com www.aa.com'  'http[s]://www.google.com'  /path/to/aa.cer  /path/to/aa.key  /path/to/aa.ca"
    return 1
  fi
  
  domainlist="$1"
  uphost="$2"
  cert="$3"
  key="$4"
  ca="$5"
  
  maindomain="$(printf "$domainlist" | cut -d ' ' -f 1)"
  domainconf="$RPN_HOME/$maindomain.conf.ssl"
  cp $RPN_HOME/serverssl.conf "$domainconf"
  
  _setopt "$domainconf" "    server_name" " " "$domainlist" ";"
  
  cp "$cert" "$SSLPATH/maindomain.cer"
  cp "$key"  "$SSLPATH/maindomain.key"
  
  echo ""  >> "$SSLPATH/maindomain.cer"
  cat "$ca" "$SSLPATH/maindomain.cer"
  
  _setopt "$domainconf" "    ssl_certificate" " " "$SSLPATH/maindomain.cer" ";"
  _setopt "$domainconf" "    ssl_certificate_key" " " "$SSLPATH/maindomain.key" ";"
  
  _setopt "$domainconf" "  		proxy_pass" " " "$uphost" ";"

  updomain="$(echo $uphost| cut -d : -f 2 | tr -d "/")"

  _setopt "$domainconf" "  		proxy_set_header Host" " " "$updomain" ";"
  
  _setopt "$domainconf" "		proxy_set_header Referert" " " "$uphost" ";"  
  
  mv "$domainconf" "$CONFPATH"
  service nginx reload
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
    printf "$text" | sed "s|^$__opt$__sep.*$|$__opt$__sep$__val$__end|" > "$__conf"
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



showhelp() {
  _info "Usage: buildnginx|install|add"
}

if [ -z "$1" ] ; then
  showhelp
else
  "$@"
fi
