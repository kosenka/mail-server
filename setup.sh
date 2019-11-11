#!/bin/bash

#
# https://serveradmin.ru/nastroyka-postfix-dovecot-centos-7/
#

DOMAIN="argus-fito.ru"
MAIL_DOMAIN="mail."$DOMAIN

yum install -y httpd php phpmyadmin mariadb mariadb-server php-imap
sed -i 's/#ServerName www.example.com:80/ServerName '$MAIL_DOMAIN':80/g' /etc/httpd/conf/httpd.conf

systemctl start httpd
systemctl enable httpd
systemctl start mariadb
systemctl enable mariadb

/usr/bin/mysql_secure_installation

cd /usr/src
wget --no-check-certificate --no-cache --no-cookies https://sourceforge.net/projects/postfixadmin/files/postfixadmin/postfixadmin-3.0.2/postfixadmin-3.0.2.tar.gz/download -O postfixadmin-3.0.2.tar.gz 
tar -xvzf postfixadmin-3.0.2.tar.gz
mv /usr/src/postfixadmin-3.0.2 /var/www/html/postfixadmin
chown -R apache. /var/www/html/postfixadmin/
sed -i "s/'configured'] = false/'configured'] = true/g" /var/www/html/postfixadmin/config.inc.php
sed -i "s/= 'md5crypt'/= 'CRAM-MD5'/g" /var/www/html/postfixadmin/config.inc.php
