#!/bin/bash

#
# https://serveradmin.ru/nastroyka-postfix-dovecot-centos-7/
#

DOMAIN = "argus-fito.ru"
MAIL_DOMAIN = "mail."$DOMAIN

yum install -y httpd php phpmyadmin mariadb mariadb-server php-imap
systemctl start httpd
systemctl enable httpd
systemctl start mariadb
systemctl enable mariadb
/usr/bin/mysql_secure_installation
cd /usr/src
wget https://downloads.sourceforge.net/project/postfixadmin/postfixadmin/postfixadmin-3.0.2/postfixadmin-3.0.2.tar.gz
tar -xvzf postfixadmin-*
mv /usr/src/postfixadmin-3.0.2 /var/www/html/postfixadmin
chown -R apache. /var/www/html/postfixadmin/
sed -i 's/$CONF['encrypt'] = 'md5crypt';/$CONF['encrypt'] = 'CRAM-MD5';/g' /var/www/html/postfixadmin/config.inc.php

