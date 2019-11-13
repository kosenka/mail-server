#!/bin/bash

#
# postfix-postfixadmin-dovecot-roundcube-httpd-let's encrypt-opendkim
#
# данный скрипт основан на "выжимке" из страниц
# https://serveradmin.ru/nastroyka-postfix-dovecot-centos-7/
# https://andreyex.ru/centos-7/bezopasnyj-apache-s-let-s-encrypt-na-centos-7/
# http://bozza.ru/art-170.html
# wget --no-check-certificate --no-cache --no-cookies https://raw.githubusercontent.com/kosenka/postfix-dovecot/master/setup.sh -O setup.sh && chmod u+x setup.sh
#

DOMAIN="***.ru"
MAIL_DOMAIN="mail."$DOMAIN

ROOT_DB_USER="root"
ROOT_DB_PASS="***"

POSTFIX_DB_USER="postfix"
POSTFIX_DB_NAME="postfix"
POSTFIX_DB_PASS="postfix"
POSTFIX_SETUP_PASS="***"
POSTFIX_ADMIN_NAME="root@"$DOMAIN
POSTFIX_ADMIN_PASS="***"

ROUNDCUBE_DB_USER="roundcube"
ROUNDCUBE_DB_NAME="roundcube"
ROUNDCUBE_DB_PASS="roundcube"

function installFirst {
yum install -y httpd php phpmyadmin mariadb mariadb-server php-imap dovecot dovecot-mysql dovecot-pigeonhole php-pear php-mcrypt php-intl php-ldap php-pear-Net-SMTP php-pear-Net-IDNA2 php-pear-Mail-Mime php-pear-Net-Sieve

echo -e "\e[92mGetting file phpMyAdmin.conf ...\e[39m"
wget --no-check-certificate --no-cache --no-cookies https://raw.githubusercontent.com/kosenka/postfix-dovecot/master/phpMyadmin.conf -O /etc/httpd/conf.d/phpMyAdmin.conf

sed -i 's/#ServerName www.example.com:80/ServerName '$MAIL_DOMAIN':80/g' /etc/httpd/conf/httpd.conf
sed -i 's/ServerAdmin root@localhost/ServerAdmin root@$DOMAIN/g' /etc/httpd/conf/httpd.conf

echo -e "\e[92mStoping/Starting services ...\e[39m"
systemctl stop postfix
systemctl start httpd
systemctl enable httpd
systemctl start mariadb
systemctl enable mariadb

/usr/bin/mysql_secure_installation

echo -e "\e[92mGetting and installing POSTFIXADMIN...\e[39m"
cd /usr/src
wget --no-check-certificate --no-cache --no-cookies https://sourceforge.net/projects/postfixadmin/files/postfixadmin/postfixadmin-3.0.2/postfixadmin-3.0.2.tar.gz/download -O postfixadmin-3.0.2.tar.gz 
tar -xvzf postfixadmin-3.0.2.tar.gz
rm -rf /var/www/html/postfixadmin
mv /usr/src/postfixadmin-3.0.2 /var/www/html/postfixadmin

touch /etc/httpd/conf.d/postfixadmin.conf
tee /etc/httpd/conf.d/postfixadmin.conf << END
Alias /postfixadmin /var/www/html/postfixadmin

<Directory /var/www/html/postfixadmin>
    AddDefaultCharset UTF-8
    Require all granted
</Directory>
END

chown -R apache. /var/www/html/postfixadmin/

systemctl restart httpd

echo -e "\e[92mSetuping POSTFIXADMIN ...\e[39m"
DOVEADM=$(whereis -b doveadm | grep doveadm: | awk '{print $2}')
echo '$CONF["configured"] = true;' >> /var/www/html/postfixadmin/config.inc.php
echo '$CONF["dovecotpw"] = "'$DOVEADM' pw";' >> /var/www/html/postfixadmin/config.inc.php
echo '$CONF["default_language"] = "ru";' >> /var/www/html/postfixadmin/config.inc.php
echo '$CONF["database_type"] = "mysqli";' >> /var/www/html/postfixadmin/config.inc.php
echo '$CONF["database_host"] = "localhost";' >> /var/www/html/postfixadmin/config.inc.php
echo '$CONF["database_user"] = "'$POSTFIX_DB_USER'";' >> /var/www/html/postfixadmin/config.inc.php
echo '$CONF["database_password"] = "'$POSTFIX_DB_PASS'";' >> /var/www/html/postfixadmin/config.inc.php
echo '$CONF["database_name"] = "'$POSTFIX_DB_NAME'";' >> /var/www/html/postfixadmin/config.inc.php
echo '$CONF["admin_email"] = "'$POSTFIX_ADMIN_NAME'";' >> /var/www/html/postfixadmin/config.inc.php
echo '$CONF["encrypt"] = "dovecot:CRAM-MD5";' >> /var/www/html/postfixadmin/config.inc.php
echo '$CONF["default_aliases"] = array ("abuse" => "root","hostmaster" => "root", "postmaster" => "root","webmaster" => "root");' >> /var/www/html/postfixadmin/config.inc.php
echo '$CONF["domain_path"] = "YES";' >> /var/www/html/postfixadmin/config.inc.php
echo '$CONF["domain_in_mailbox"] = "YES";' >> /var/www/html/postfixadmin/config.inc.php

echo -e "\e[92mCreating database for POSTFIXADMIN ...\e[39m"
mysql -u root -p$ROOT_DB_PASS<<MYSQL_SCRIPT
FLUSH PRIVILEGES;
DROP DATABASE IF EXISTS ${POSTFIX_DB_NAME};
CREATE DATABASE IF NOT EXISTS ${POSTFIX_DB_NAME} DEFAULT CHARACTER SET utf8;
CREATE USER '${POSTFIX_DB_USER}'@'localhost';
SET PASSWORD FOR '${POSTFIX_DB_USER}'@'localhost' = PASSWORD("${POSTFIX_DB_PASS}");
GRANT ALL PRIVILEGES ON ${POSTFIX_DB_NAME}.* TO '${POSTFIX_DB_USER}'@'localhost';
FLUSH PRIVILEGES;
MYSQL_SCRIPT

IP=$(hostname -I | awk '{print $1}')
RES=$(curl -v -X POST -d "form=setuppw&setup_password=$POSTFIX_SETUP_PASS&setup_password2=$POSTFIX_SETUP_PASS" http://$IP/postfixadmin/setup.php | grep -o '<pre>.*</pre>' | sed 's/\(<pre>\|<\/pre>\)//g')
echo $RES  >> /var/www/html/postfixadmin/config.inc.php
curl -v -X POST -d "form=createadmin&setup_password=$POSTFIX_SETUP_PASS&username=$POSTFIX_ADMIN_NAME&password=$POSTFIX_ADMIN_PASS&password2=$POSTFIX_ADMIN_PASS" http://$IP/postfixadmin/setup.php 

echo -e "\e[92mAdding domain '$DOMAIN' to POSTFIXADMIN ...\e[39m"
mysql -u $POSTFIX_DB_USER -p$POSTFIX_DB_PASS --database=$POSTFIX_DB_NAME<<MYSQL_SCRIPT
insert into domain (domain, aliases, mailboxes, maxquota, quota, transport, backupmx, active, created, modified) values ('${DOMAIN}', 0, 0, 10, 2048, 'virtual', 0, 1, NOW(), NOW());
MYSQL_SCRIPT

echo -e "\e[92mAdding email '$POSTFIX_ADMIN_NAME' to POSTFIXADMIN ...\e[39m"
CRAM_MD5="`${DOVEADM} pw -s CRAM-MD5 -p '${POSTFIX_ADMIN_PASS}'`"
MAILDIR=$DOMAIN"/"$POSTFIX_ADMIN_NAME"/"
LOCAL_PART=""
mysql -u $POSTFIX_DB_USER -p$POSTFIX_DB_PASS --database=$POSTFIX_DB_NAME<<MYSQL_SCRIPT
insert into mailbox (username, password, maildir, quota, local_part, domain, active, created, modified) values ('${POSTFIX_ADMIN_NAME}', '${CRAM_MD5}', '${MAILDIR}', 0, '${LOCAL_PART}', '${DOMAIN}', 1, NOW(), NOW());
insert into alias (address, goto, domain, created, modified, active) values ('${POSTFIX_ADMIN_NAME}', '${POSTFIX_ADMIN_NAME}', '${DOMAIN}', NOW(), NOW(), 1);
MYSQL_SCRIPT
}

function installPostfix {
echo -e "\e[92mConfiguring PostFix: main.cf ...\e[39m"

touch /etc/postfix/main.cf
tee -a /etc/postfix/main.cf << END
soft_bounce = no
queue_directory = /var/spool/postfix
command_directory = /usr/sbin
daemon_directory = /usr/libexec/postfix
data_directory = /var/lib/postfix
mail_owner = postfix

mydomain = ${DOMAIN}
myhostname = ${MAIL_DOMAIN}
myorigin = \$myhostname

inet_interfaces = all
inet_protocols = ipv4

mydestination = localhost.\$mydomain, localhost
unknown_local_recipient_reject_code = 550
mynetworks = 127.0.0.0/8

alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases

smtpd_banner = \$myhostname ESMTP

debug_peer_level = 2
# Строки с PATH и ddd должны быть с отступом в виде табуляции от начала строки
debugger_command =
         PATH=/bin:/usr/bin:/usr/local/bin:/usr/X11R6/bin
         ddd \$daemon_directory/\$process_name \$process_id & sleep 5

sendmail_path = /usr/sbin/sendmail.postfix
newaliases_path = /usr/bin/newaliases.postfix
mailq_path = /usr/bin/mailq.postfix
setgid_group = postdrop
html_directory = no
manpage_directory = /usr/share/man
sample_directory = /usr/share/doc/postfix-2.10.1/samples
readme_directory = /usr/share/doc/postfix-2.10.1/README_FILES

relay_domains = mysql:/etc/postfix/mysql/relay_domains.cf
virtual_alias_maps = mysql:/etc/postfix/mysql/virtual_alias_maps.cf,
 mysql:/etc/postfix/mysql/virtual_alias_domain_maps.cf
virtual_mailbox_domains = mysql:/etc/postfix/mysql/virtual_mailbox_domains.cf
virtual_mailbox_maps = mysql:/etc/postfix/mysql/virtual_mailbox_maps.cf

smtpd_discard_ehlo_keywords = etrn, silent-discard
smtpd_forbidden_commands = CONNECT GET POST
broken_sasl_auth_clients = yes
smtpd_delay_reject = yes
smtpd_helo_required = yes
smtp_always_send_ehlo = yes
disable_vrfy_command = yes

smtpd_helo_restrictions = permit_mynetworks,
 permit_sasl_authenticated,
 reject_non_fqdn_helo_hostname,
 reject_invalid_helo_hostname

smtpd_data_restrictions = permit_mynetworks,
 permit_sasl_authenticated,
 reject_unauth_pipelining,
 reject_multi_recipient_bounce,

smtpd_sender_restrictions = permit_mynetworks,
 permit_sasl_authenticated,
 reject_non_fqdn_sender,
 reject_unknown_sender_domain

smtpd_recipient_restrictions = reject_non_fqdn_recipient,
 reject_unknown_recipient_domain,
 reject_multi_recipient_bounce,
 permit_mynetworks,
 permit_sasl_authenticated,
 reject_unauth_destination,

smtp_tls_security_level = may
smtpd_tls_security_level = may
smtpd_tls_loglevel = 1
smtpd_tls_received_header = yes
smtpd_tls_session_cache_timeout = 3600s
smtp_tls_session_cache_database = btree:\$data_directory/smtp_tls_session_cache
smtpd_tls_key_file = /etc/postfix/certs/key.pem
smtpd_tls_cert_file = /etc/postfix/certs/cert.pem
tls_random_source = dev:/dev/urandom

# Ограничение максимального размера письма в байтах
message_size_limit = 20000000
smtpd_soft_error_limit = 10
smtpd_hard_error_limit = 15
smtpd_error_sleep_time = 20
anvil_rate_time_unit = 60s
smtpd_client_connection_count_limit = 20
smtpd_client_connection_rate_limit = 30
smtpd_client_message_rate_limit = 30
smtpd_client_event_limit_exceptions = 127.0.0.0/8
smtpd_client_connection_limit_exceptions = 127.0.0.0/8

maximal_queue_lifetime = 1d
bounce_queue_lifetime = 1d

smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/dovecot-auth

# Директория для хранения почты
virtual_mailbox_base = /mnt/mail
virtual_minimum_uid = 1000
virtual_uid_maps = static:1000
virtual_gid_maps = static:1000
virtual_transport = dovecot
dovecot_destination_recipient_limit = 1

sender_bcc_maps = hash:/etc/postfix/sender_bcc_maps
recipient_bcc_maps = hash:/etc/postfix/recipient_bcc_maps
END

rm -fr /etc/postfix/mysql 
mkdir /etc/postfix/mysql 
cd /etc/postfix/mysql

echo -e "\e[92mConfiguring PostFix: relay_domains.cf ...\e[39m"
touch relay_domains.cf
tee relay_domains.cf << END
hosts = localhost
user = ${POSTFIX_DB_USER}
password = ${POSTFIX_DB_PASS}
dbname = ${POSTFIX_DB_NAME}
query = SELECT domain FROM domain WHERE domain='%s' and backupmx = '1'
END

echo -e "\e[92mConfiguring PostFix: virtual_alias_domain_maps.cf ...\e[39m"
touch virtual_alias_domain_maps.cf
tee virtual_alias_domain_maps.cf << END
hosts = localhost
user = ${POSTFIX_DB_USER}
password = ${POSTFIX_DB_PASS}
dbname = ${POSTFIX_DB_NAME}
query = SELECT goto FROM alias,alias_domain WHERE alias_domain.alias_domain = '%d' and alias.address = CONCAT('%u', '@', alias_domain.target_domain) AND alias.active = 1
END

echo -e "\e[92mConfiguring PostFix: virtual_alias_maps.cf ...\e[39m"
touch virtual_alias_maps.cf
tee virtual_alias_maps.cf << END
hosts = localhost
user = ${POSTFIX_DB_USER}
password = ${POSTFIX_DB_PASS}
dbname = ${POSTFIX_DB_NAME}
query = SELECT goto FROM alias WHERE address='%s' AND active = '1'
END

echo -e "\e[92mConfiguring PostFix: virtual_mailbox_domains.cf ...\e[39m"
touch virtual_mailbox_domains.cf
tee virtual_mailbox_domains.cf << END
hosts = localhost
user = ${POSTFIX_DB_USER}
password = ${POSTFIX_DB_PASS}
dbname = ${POSTFIX_DB_NAME}
query = SELECT domain FROM domain WHERE domain='%s' AND backupmx = '0' AND active = '1'
END

echo -e "\e[92mConfiguring PostFix: virtual_mailbox_maps.cf ...\e[39m"
touch virtual_mailbox_maps.cf
tee virtual_mailbox_maps.cf << END
hosts = localhost
user = ${POSTFIX_DB_USER}
password = ${POSTFIX_DB_PASS}
dbname = ${POSTFIX_DB_NAME}
query = SELECT maildir FROM mailbox WHERE username='%s' AND active = '1'
END

echo -e "\e[92mConfiguring PostFix: /etc/postfix/master.cf ...\e[39m"
tee -a /etc/postfix/master.cf << END

submission inet n - n - - smtpd
 -o syslog_name=postfix/submission
 -o smtpd_tls_wrappermode=no
 -o smtpd_tls_security_level=encrypt
 -o smtpd_sasl_auth_enable=yes
 -o smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject
 -o smtpd_relay_restrictions=permit_mynetworks,permit_sasl_authenticated,defer_unauth_destination
 -o milter_macro_daemon_name=ORIGINATING

smtps inet n - n - - smtpd
 -o syslog_name=postfix/smtps
 -o smtpd_tls_wrappermode=yes
 -o smtpd_sasl_auth_enable=yes
 -o smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject
 -o smtpd_relay_restrictions=permit_mynetworks,permit_sasl_authenticated,defer_unauth_destination
 -o milter_macro_daemon_name=ORIGINATING

dovecot unix - n n - - pipe
 flags=DRhu user=vmail:vmail argv=/usr/libexec/dovecot/deliver -f \${sender} -d \${recipient}
END

echo -e "\e[92mConfiguring PostFix: certificates ...\e[39m"
mkdir /etc/postfix/certs
openssl req -new -x509 -days 3650 -nodes -out /etc/postfix/certs/cert.pem -keyout /etc/postfix/certs/key.pem

touch /etc/postfix/recipient_bcc_maps
touch /etc/postfix/sender_bcc_maps
postmap /etc/postfix/recipient_bcc_maps /etc/postfix/sender_bcc_maps

mkdir /etc/postfix/lists
cd /etc/postfix/lists && touch white_client_ip black_client_ip white_client black_client white_helo block_dsl mx_access

tee /etc/postfix/lists/white_client_ip << END
195.28.34.162 OK
141.197.4.160 OK
END

tee /etc/postfix/lists/black_client_ip << END
205.201.130.163 REJECT You IP are blacklisted!
198.2.129.162 REJECT You IP are blacklisted!
END

tee /etc/postfix/lists/white_client << END
# Принимать всю почту с домена яндекс
yandex.ru OK
# Разрешить конкретный ящик
spammer@mail.ru OK
END

tee /etc/postfix/lists/black_client << END
$DOMAIN 554 Stop spam from my name
# Блокировать всю почту с домена mail.ru
#mail.ru REJECT You domain are blacklisted!
# Блокировать конкретный ящик
spam@rambler.ru REJECT You e-mail are blacklisted!
END

tee /etc/postfix/lists/white_helo << END
# Могут попадаться вот такие адреса, которые не пройдут наши проверки
ka-s-ex01.itk.local     OK
exchange.elcom.local    OK
END

tee /etc/postfix/lists/block_dsl << END
/^dsl.*\..*\..*/i                               553 AUTO_DSL spam
/dsl.*\..*\..*/i                                553 AUTO_DSL1 spam
/[ax]dsl.*\..*\..*/i                            553 AUTO_XDSL spam
/client.*\..*\..*/i                             553 AUTO_CLIENT spam
/cable.*\..*\..*/i                              553 AUTO_CABLE spam
/pool.*\..*\..*/i                               553 AUTO_POOL spam
/dial.*\..*\..*/i                               553 AUTO_DIAL spam
/ppp.*\..*\..*/i                                553 AUTO_PPP spam
/dslam.*\..*\..*/i                              553 AUTO_DSLAM spam
/node.*\..*\..*/i                               553 AUTO_NODE spam
/([0-9]*-){3}[0-9]*(\..*){2,}/i                 553 SPAM_ip-add-rr-ess_networks
/([0-9]*\.){4}(.*\.){3,}.*/i                    553 SPAM_ip-add-rr-ess_networks
/.*\.pppool\..*/i                               553 SPAM_POOL
/[0-9]*-[0-9]*-[0-9]*-[0-9]*-tami\.tami\.pl/i   553 SPAM_POOL
/pool-[0-9]*-[0-9]*-[0-9]*-[0-9]*\..*/i         553 SPAM_POOL
/.*-[0-9]*-[0-9]*-[0-9]*-[0-9]*\.gtel.net.mx/i  553 SPAM_POOL
/dhcp.*\..*\..*/i                               553 SPAM_DHCP
END

tee /etc/postfix/lists/mx_access << END
127.0.0.1      DUNNO 
127.0.0.2      550 Domains not registered properly
0.0.0.0/8      REJECT Domain MX in broadcast network 
10.0.0.0/8     REJECT Domain MX in RFC 1918 private network 
127.0.0.0/8    REJECT Domain MX in loopback network 
169.254.0.0/16 REJECT Domain MX in link local network 
172.16.0.0/12  REJECT Domain MX in RFC 1918 private network 
192.0.2.0/24   REJECT Domain MX in TEST-NET network 
192.168.0.0/16 REJECT Domain MX in RFC 1918 private network 
224.0.0.0/4    REJECT Domain MX in class D multicast network 
240.0.0.0/5    REJECT Domain MX in class E reserved network 
248.0.0.0/5    REJECT Domain MX in reserved network
END

postmap touch white_client_ip black_client_ip white_client black_client white_helo block_dsl mx_access
}

function installDovecot {
echo -e "\e[92mConfiguring Dovecot: /etc/dovecot/dovecot.conf ...\e[39m"
tee /etc/dovecot/dovecot.conf << END
# Мы не используем специализированные файлы из поставки Dovecot из папки /etc/dovecot/conf.d/.
# Основная причина: отсутствие ясного руководства по их использованию. А также сравнительно небольшой
# размер всего конфига (все перед глазами, нет необходимости раскидывать по отдельным файлам).
#!include conf.d/*.conf

# Нет необходимости явно указывать imaps и pop3s - Dovecot 2.* по-умолчанию их включает.
protocols = imap pop3 sieve lmtp
listen = *

# Завершать все дочерние процессы, если завершен мастер-процесс
shutdown_clients = yes

mail_plugins = mailbox_alias acl

mail_uid = 1000
mail_gid = 1000

first_valid_uid = 1000
last_valid_uid = 1000

# Лог-файлы. Подробнее: http://wiki2.dovecot.org/Logging
log_path = /var/log/dovecot.log
info_log_path = /var/log/dovecot/info.log
debug_log_path = /var/log/dovecot/debug.log

# Отладка. Если все настроено, отключаем (no)
# http://maint.unona.ru/doc/dovecot2.shtml
mail_debug = yes
auth_verbose = yes
auth_debug = yes
auth_debug_passwords = yes

# SSL
ssl = required
ssl_cert = </etc/postfix/certs/cert.pem
ssl_key = </etc/postfix/certs/key.pem

ssl_protocols = TLSv1 TLSv1.1 TLSv1.2 !SSLv2 !SSLv3
verbose_ssl = no

ssl_cipher_list = ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA
ssl_dh_parameters_length = 2048
ssl_prefer_server_ciphers = yes

# Запрет аутентификации открытым текстом. yes - запретить, no - разрешить.
disable_plaintext_auth = yes

# Список разрешенных символов в имене пользователя.
auth_username_chars = abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.-_@

# Расположение и формат файлов почты (%d - домен, %n - имя пользователя).
mail_location = maildir:/mnt/mail/%d/%u/

# Если при аутентификации не указан домен, то добавить этот (в данном примере - пустой)
auth_default_realm = ${MAIL_DOMAIN}

# Доступные варианты аутентификации (PLAIN, DIGEST-MD5, CRAM-MD5...).
# Для того, чтобы иметь меньше головной боли ставьте PLAIN
auth_mechanisms = PLAIN LOGIN

# Одно из самых важных мест - предоставление сокетов для аутентификации пользователей.
# Если настроено неверно - ничего работать не будет!
service auth {
    # http://maint.unona.ru/doc/dovecot2.shtml
    # Указывает, что данный сокет будет использовать SMTP сервер для аутентификации.
    # Указывается пользователь, группа и права доступа к сокету. В данном случае это postfix
    # ("mail_owner = postfix" в файле /etc/postfix/main.cf).
    unix_listener /var/spool/postfix/private/auth {
	user = postfix
	group = postfix
	mode = 0666
    }
    unix_listener auth-master {
	user = vmail
	group = vmail
	mode = 0666
    }
    unix_listener auth-userdb {
	user = vmail
	group = vmail
	mode = 0660
   }
}

service lmtp {
 unix_listener /var/spool/postfix/private/dovecot-lmtp {
 user = postfix
 group = postfix
 mode = 0600
 }

 inet_listener lmtp {
 address = 127.0.0.1
 port = 24
 }
}

# Запрос параметров виртуальных почтовых пользователей
# (логин, пароль, домен, активный/неактивный и др.)
userdb {
    args = /etc/dovecot/dovecot-mysql.conf
    driver = sql
}
passdb {
    args = /etc/dovecot/dovecot-mysql.conf
    driver = sql
}

auth_master_user_separator = *
 
plugin {
 auth_socket_path = /var/run/dovecot/auth-master

 acl = vfile
 acl_shared_dict = file:/mnt/mail/shared-folders/shared-mailboxes.db
 sieve = /mnt/mail/sieve/%u.sieve
 mailbox_alias_old = Sent
 mailbox_alias_new = Sent Messages
 mailbox_alias_old2 = Sent
 mailbox_alias_new2 = Sent Items
}

protocol lda {
 mail_plugins = \$mail_plugins sieve
 auth_socket_path = /var/run/dovecot/auth-master
 deliver_log_format = mail from %f: msgid=%m %\$
 log_path = /var/log/dovecot/lda-errors.log
 info_log_path = /var/log/dovecot/lda-deliver.log
 lda_mailbox_autocreate = yes
 lda_mailbox_autosubscribe = yes
 postmaster_address = root
}

protocol lmtp {
 info_log_path = /var/log/dovecot/lmtp.log
 mail_plugins = quota sieve
 postmaster_address = postmaster
 lmtp_save_to_detail_mailbox = yes
 recipient_delimiter = +
}

protocol imap {
 mail_plugins = \$mail_plugins imap_acl
 imap_client_workarounds = tb-extra-mailbox-sep
 mail_max_userip_connections = 30
}

protocol pop3 {
 mail_plugins = \$mail_plugins
 pop3_client_workarounds = outlook-no-nuls oe-ns-eoh
 pop3_uidl_format = %08Xu%08Xv
 mail_max_userip_connections = 30
}

service imap-login {
 service_count = 1
 process_limit = 500
 }

service pop3-login {
 service_count = 1
 }

service managesieve-login {
 inet_listener sieve {
 port = 4190
 }
}

namespace {
 type = private
 separator = /
 prefix =
 inbox = yes

 mailbox Sent {
 auto = subscribe
 special_use = \Sent
 }
 mailbox "Sent Messages" {
 auto = no
 special_use = \Sent
 }
 mailbox "Sent Items" {
 auto = no
 special_use = \Sent
 }
 mailbox Drafts {
 auto = subscribe
 special_use = \Drafts
 }
 mailbox Trash {
 auto = subscribe
 special_use = \Trash
 }
 mailbox "Deleted Messages" {
 auto = no
 special_use = \Trash
 }
 mailbox Junk {
 auto = subscribe
 special_use = \Junk
 }
 mailbox Spam {
 auto = no
 special_use = \Junk
 }
 mailbox "Junk E-mail" {
 auto = no
 special_use = \Junk
 }
 mailbox Archive {
 auto = no
 special_use = \Archive
 }
 mailbox Archives {
 auto = no
 special_use = \Archive
 }
}

namespace {
 type = shared
 separator = /
 prefix = Shared/%%u/
 location = maildir:%%h:INDEX=%h/shared/%%u
 subscriptions = yes
 list = children
}
END

groupadd  -g 1000 vmail
useradd -d /mnt/mail/ -g 1000 -u 1000 vmail
chown vmail. /mnt/mail

touch /etc/dovecot/dovecot-mysql.conf
tee /etc/dovecot/dovecot-mysql.conf << END
driver = mysql
default_pass_scheme = CRAM-MD5
connect = host=127.0.0.1 dbname=${POSTFIX_DB_NAME} user=${POSTFIX_DB_USER} password=${POSTFIX_DB_PASS}
user_query = SELECT '/mnt/mail/%d/%u' as home, 'maildir:/mnt/mail/%d/%u' as mail, 1000 AS uid, 1000 AS gid, concat('*:bytes=', quota) AS quota_rule FROM mailbox WHERE username = '%u' AND active = '1'
password_query = SELECT username as user, password, '/mnt/mail/%d/%u' as userdb_home, 'maildir:/mnt/mail/%d/%u' as userdb_mail, 1000 as userdb_uid, 1000 as userdb_gid, concat('*:bytes=', quota) AS userdb_quota_rule FROM mailbox WHERE username = '%u' AND active = '1'
END

mkdir /var/log/dovecot
cd /var/log/dovecot && touch main.log info.log debug.log lda-errors.log lda-deliver.log lmtp.log
chown -R vmail:dovecot /var/log/dovecot

mkdir /mnt/mail/sieve && mkdir /mnt/mail/shared-folders
chown -R vmail. /mnt/mail

chown vmail. /var/run/dovecot/auth-master

systemctl restart postfix
systemctl start dovecot
systemctl enable dovecot
}

function installRoundcube() {
echo -e "\e[92mCreating database for RoundCube ...\e[39m"
mysql -u root -p${ROOT_DB_PASS}<<MYSQL_SCRIPT
FLUSH PRIVILEGES;
DROP DATABASE IF EXISTS ${ROUNDCUBE_DB_NAME};
CREATE DATABASE IF NOT EXISTS ${ROUNDCUBE_DB_NAME} DEFAULT CHARACTER SET utf8;
CREATE USER '${ROUNDCUBE_DB_USER}'@'localhost';
SET PASSWORD FOR '${ROUNDCUBE_DB_USER}'@'localhost' = PASSWORD("${ROUNDCUBE_DB_PASS}");
GRANT ALL PRIVILEGES ON ${ROUNDCUBE_DB_NAME}.* TO '$3'@'localhost';
FLUSH PRIVILEGES;
MYSQL_SCRIPT

echo -e "\e[92mInstalling RoundCube ...\e[39m"
cd /usr/src
wget --no-check-certificate --no-cache --no-cookies https://github.com/roundcube/roundcubemail/releases/download/1.2.9/roundcubemail-1.2.9-complete.tar.gz -O /usr/src/roundcubemail-1.2.9-complete.tar.gz
tar -xzvf roundcubemail-*
rm -fr /var/www/html/webmail
mv roundcubemail-1.2.9 /var/www/html/webmail

touch /var/www/html/webmail/config/config.inc.php
tee /var/www/html/webmail/config/config.inc.php << END
<?php
\$config['db_dsnw'] = 'mysql://${ROUNDCUBE_DB_USER}:${ROUNDCUBE_DB_PASS}@localhost/${ROUNDCUBE_DB_NAME}';
\$config['default_host'] = 'localhost';
\$config['support_url'] = '';
\$config['des_key'] = 'IP4KM2EcaqV5vaTY0IUmKytS';
\$config['plugins'] = array('acl', 'managesieve', 'userinfo', 'password');
\$config['language'] = 'ru_RU';
\$config['imap_auth_type'] = 'CRAM-MD5';
\$config['smtp_auth_type'] = 'CRAM-MD5';
\$config['!force_https'] = true;
\$config['!use_https'] = true;
END

mkdir /var/www/html/webmail/autodiscover
wget --no-check-certificate --no-cache --no-cookies https://raw.githubusercontent.com/kosenka/postfix-dovecot/master/autodiscover.xml -O /var/www/html/webmail/autodiscover/autodiscover.xml
sed -i 's/MAIL_DOMAIN/'$MAIL_DOMAIN'/g' /var/www/html/webmail/autodiscover/autodiscover.xml
sed -i 's/DOMAIN/'$DOMAIN'/g' /var/www/html/webmail/autodiscover/autodiscover.xml

chown -R apache. /var/www/html/webmail

sed -i 's/;date.timezone =/date.timezone = Europe\/Moscow/g' /etc/php.ini

echo -e "\e[92mInitializing database RoundCube ...\e[39m"
mysql -u root -p${ROOT_DB_PASS} --database=${ROUNDCUBE_DB_NAME} < /var/www/html/webmail/SQL/mysql.initial.sql
}

function installOpenDkim() {
echo -e "\e[92mInstalling OpenDkim ...\e[39m"

yum install -y opendkim

mkdir -p /etc/postfix/dkim && cd /etc/postfix/dkim
opendkim-genkey -D /etc/postfix/dkim/ -d ${DOMAIN} -s mail
mv mail.private ${MAIL_DOMAIN}.private
mv mail.txt ${MAIL_DOMAIN}.txt

touch keytable
tee keytable << END
mail._domainkey.${DOMAIN} ${DOMAIN}:mail:/etc/postfix/dkim/${MAIL_DOMAIN}.private
END

touch signingtable
tee signingtable << END
*@${DOMAIN} mail._domainkey.${DOMAIN}
END

chown root:opendkim *
chmod u=rw,g=r,o= *

touch /etc/opendkim.conf
tee /etc/opendkim.conf << END
AutoRestart Yes
AutoRestartRate 10/1h
PidFile /var/run/opendkim/opendkim.pid
Mode sv
Syslog yes
SyslogSuccess yes
LogWhy yes
UserID opendkim:opendkim
Socket inet:8891@localhost
Umask 022
Canonicalization relaxed/relaxed
Selector default
MinimumKeyBits 1024
KeyFile /etc/postfix/dkim/${MAIL_DOMAIN}.private
KeyTable /etc/postfix/dkim/keytable
SigningTable refile:/etc/postfix/dkim/signingtable
END

tee -a /etc/postfix/main.cf << END
#
smtpd_milters = inet:127.0.0.1:8891
non_smtpd_milters = $smtpd_milters
milter_default_action = accept
milter_protocol = 2
END

systemctl restart postfix
systemctl restart opendkim.service
systemctl enable opendkim.service

}

function installLetsEncrypt() {
echo -e "\e[92mInstalling Let's Encrypt ...\e[39m"

yum install -y mod_ssl openssl epel-release certbot

echo -e "\e[92mGenerating DHPARAM.PEM ...\e[39m"

openssl dhparam -out /etc/ssl/certs/dhparam.pem 4096

mkdir -p /var/lib/letsencrypt/.well-known
chgrp apache /var/lib/letsencrypt
chmod g+s /var/lib/letsencrypt

touch /etc/httpd/conf.d/letsencrypt.conf
tee /etc/httpd/conf.d/letsencrypt.conf << END
Alias /.well-known/acme-challenge/ "/var/lib/letsencrypt/.well-known/acme-challenge/"
<Directory "/var/lib/letsencrypt/">
    AllowOverride None
    Options MultiViews Indexes SymLinksIfOwnerMatch IncludesNoExec
    Require method GET POST OPTIONS
</Directory>
END

touch /etc/httpd/conf.d/ssl-params.conf
tee /etc/httpd/conf.d/ssl-params.conf << END
SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLHonorCipherOrder On
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
Header always set X-Frame-Options SAMEORIGIN;
Header always set X-Content-Type-Options nosniff
# Требует Apache >= 2.4
SSLCompression off
SSLUseStapling on
SSLStaplingCache "shmcb:logs/stapling-cache(150000)"
# Требует Apache >= 2.4.11
SSLSessionTickets Off
END

systemctl restart httpd

certbot certonly --agree-tos --email $POSTFIX_ADMIN_NAME --webroot -w /var/lib/letsencrypt/ -d $MAIL_DOMAIN

cat /etc/letsencrypt/live/$MAIL_DOMAIN/cert.pem /etc/ssl/certs/dhparam.pem >/etc/letsencrypt/live/$MAIL_DOMAIN/cert.dh.pem

touch /etc/httpd/conf.d/$MAIL_DOMAIN.conf
tee -a /etc/httpd/conf.d/$MAIL_DOMAIN.conf << END
<VirtualHost *:80> 
  ServerName $MAIL_DOMAIN
  Redirect permanent / https://$MAIL_DOMAIN/
</VirtualHost>

<VirtualHost *:443>
  ServerName $MAIL_DOMAIN

  <If "%{HTTP_HOST} == 'www.$MAIL_DOMAIN'">
    Redirect permanent / https://$MAIL_DOMAIN/
  </If>

  DocumentRoot /var/www/html/webmail
  ErrorLog /var/log/httpd/$MAIL_DOMAIN-error.log
  CustomLog /var/log/httpd/$MAIL_DOMAIN-access.log combined

  SSLEngine On
  SSLCertificateFile /etc/letsencrypt/live/$MAIL_DOMAIN/cert.dh.pem
  SSLCertificateKeyFile /etc/letsencrypt/live/$MAIL_DOMAIN/privkey.pem
  SSLCertificateChainFile /etc/letsencrypt/live/$MAIL_DOMAIN/chain.pem
</VirtualHost>
END

systemctl restart httpd

echo -e "\e[92mAdding certbot to crontab ...\e[39m"
crontab -l > mycron
echo '0 */12 * * * certbot renew --cert-name '$MAIL_DOMAIN' --renew-hook "cat /etc/letsencrypt/live/'$MAIL_DOMAIN'/cert.pem /etc/ssl/certs/dhparam.pem >/etc/letsencrypt/live/'$MAIL_DOMAIN'/cert.dh.pem && systemctl restart httpd"' >> mycron
crontab mycron
rm mycron

}

######## run ##############

SCRIPT_PATH="/root/iptables_rules.sh"
wget --no-check-certificate --no-cache --no-cookies https://raw.githubusercontent.com/kosenka/postfix-postfixadmin-dovecot-roundcube-httpd-let-s-encrypt-opendkim/master/iptables_rules.sh -O $SCRIPT_PATH
chmod u+x $SCRIPT_PATH

#installFirst
#installPostfix
#installDovecot
#installRoundcube 
#installOpenDkim
#installLetsEncrypt



