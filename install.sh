!#/bin/bash

DOMAIN="***.ru"
MAIL_DOMAIN="***.ru"

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

yum -y update
yum -y install httpd php phpmyadmin mariadb mariadb-server php-imap

cp /etc/httpd/conf.d/phpMyAdmin.conf /etc/httpd/conf.d/phpMyAdmin.conf.orig
wget --no-check-certificate --no-cache --no-cookies https://raw.githubusercontent.com/kosenka/postfix-dovecot/master/phpMyadmin.conf -O /etc/httpd/conf.d/phpMyAdmin.conf

systemctl start httpd
systemctl enable httpd
systemctl start mariadb
systemctl enable mariadb

/usr/bin/mysql_secure_installation

cd /usr/src
wget --no-check-certificate --no-cache --no-cookies https://sourceforge.net/projects/postfixadmin/files/postfixadmin/postfixadmin-3.0.2/postfixadmin-3.0.2.tar.gz/download -O postfixadmin-3.0.2.tar.gz 
tar -xvzf postfixadmin-3.0.2.tar.gz
rm -rf /var/www/html/postfixadmin
mv /usr/src/postfixadmin-3.0.2 /var/www/html/postfixadmin

chown -R apache. /var/www/html/postfixadmin/

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
CRAM_MD5="`$DOVEADM pw -s CRAM-MD5 -p $POSTFIX_ADMIN_PASS`"
MAILDIR=$DOMAIN"/"$POSTFIX_ADMIN_NAME"/"
LOCAL_PART=""
mysql -u $POSTFIX_DB_USER -p$POSTFIX_DB_PASS --database=$POSTFIX_DB_NAME<<MYSQL_SCRIPT
insert into mailbox (username, password, maildir, quota, local_part, domain, active, created, modified) values ('${POSTFIX_ADMIN_NAME}', '${CRAM_MD5}', '${MAILDIR}', 0, '${LOCAL_PART}', '${DOMAIN}', 1, NOW(), NOW());
insert into alias (address, goto, domain, created, modified, active) values ('${POSTFIX_ADMIN_NAME}', '${POSTFIX_ADMIN_NAME}', '${DOMAIN}', NOW(), NOW(), 1);
MYSQL_SCRIPT
}

echo -e "\e[92mConfiguring PostFix: main.cf ...\e[39m"

touch /etc/postfix/main.cf
tee /etc/postfix/main.cf << END
soft_bounce = no
queue_directory = /var/spool/postfix
command_directory = /usr/sbin
daemon_directory = /usr/libexec/postfix
data_directory = /var/lib/postfix
mail_owner = postfix

myhostname = $MAIL_DOMAIN
mydomain = $DOMAIN
myorigin = $myhostname

inet_interfaces = all
inet_protocols = ipv4

mydestination = localhost.$mydomain, localhost
unknown_local_recipient_reject_code = 550
mynetworks = 127.0.0.0/8

alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases

smtpd_banner = $myhostname ESMTP $mail_name

debug_peer_level = 2
# Строки с PATH и ddd должны быть с отступом в виде табуляции от начала строки
debugger_command =
         PATH=/bin:/usr/bin:/usr/local/bin:/usr/X11R6/bin
         ddd $daemon_directory/$process_name $process_id & sleep 5

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
smtp_tls_session_cache_database = btree:$data_directory/smtp_tls_session_cache
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
mkdir /etc/postfix/mysql && cd /etc/postfix/mysql

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

echo -e "\e[92mInstalling Dovecot ...\e[39m"
yum -y install dovecot dovecot-mysql dovecot-pigeonhole

echo -e "\e[92mConfiguring Dovecot: /etc/postfix/master.cf ...\e[39m"
tee /etc/postfix/master.cf << END
listen = * [::]

mail_plugins = mailbox_alias acl

protocols = imap pop3 sieve lmtp

mail_uid = 1000
mail_gid = 1000

first_valid_uid = 1000
last_valid_uid = 1000

mail_debug = yes
auth_verbose = yes
auth_debug = yes
auth_debug_passwords = yes

log_path = /var/log/dovecot/main.log
info_log_path = /var/log/dovecot/info.log
debug_log_path = /var/log/dovecot/debug.log

ssl_protocols = !SSLv2 !SSLv3
ssl = required
verbose_ssl = no
ssl_cert = </etc/postfix/certs/cert.pem
ssl_key = </etc/postfix/certs/key.pem

ssl_cipher_list = ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA
ssl_dh_parameters_length = 2048
ssl_prefer_server_ciphers = yes

disable_plaintext_auth = yes

mail_location = maildir:/mnt/mail/%d/%u/

auth_default_realm = ${DOMAIN}

auth_mechanisms = plain login cram-md5

service auth {
 unix_listener /var/spool/postfix/private/dovecot-auth {
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
 mail_plugins = $mail_plugins sieve
 auth_socket_path = /var/run/dovecot/auth-master
 deliver_log_format = mail from %f: msgid=%m %$
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
 mail_plugins = $mail_plugins imap_acl
 imap_client_workarounds = tb-extra-mailbox-sep
 mail_max_userip_connections = 30
}

protocol pop3 {
 mail_plugins = $mail_plugins
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

chown vmail. /var/run/dovecot/auth-master

systemctl restart postfix
systemctl start dovecot
systemctl enable dovecot
