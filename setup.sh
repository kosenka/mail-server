#!/bin/bash

#
# https://serveradmin.ru/nastroyka-postfix-dovecot-centos-7/
#

DOMAIN="argus-fito.ru"
MAIL_DOMAIN="mail."$DOMAIN

DB_USER="root"
DB_PASS="GhI!2018"

POSTFIX_DB_USER="postfix"
POSTFIX_DB_NAME="postfix"
POSTFIX_DB_PASS="postfix"

yum install -y httpd php phpmyadmin mariadb mariadb-server php-imap
wget --no-check-certificate --no-cache --no-cookies https://raw.githubusercontent.com/kosenka/postfix-dovecot/master/phpMyadmin.conf -O /etc/httpd/conf.d/phpMyAdmin.conf

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
sed -i "s/database_user'] = 'postfix'/database_user'] = '$POSTFIX_DB_USER'/g" /var/www/html/postfixadmin/config.inc.php
sed -i "s/database_password'] = 'postfixadmin'/database_password'] = '$POSTFIX_DB_PASS'/g" /var/www/html/postfixadmin/config.inc.php
sed -i "s/database_name'] = 'postfix'/database_password'] = '$POSTFIX_DB_NAME'/g" /var/www/html/postfixadmin/config.inc.php

#create database for PostFix
mysql --user="$DB_USER" --password="DB_PASS" --execute="CREATE USER '$POSTFIX_DB_USER'@'%' IDENTIFIED BY '***';GRANT ALL PRIVILEGES ON *.* TO '$POSTFIX_DB_USER'@'%' IDENTIFIED BY '***' REQUIRE NONE WITH GRANT OPTION MAX_QUERIES_PER_HOUR 0 MAX_CONNECTIONS_PER_HOUR 0 MAX_UPDATES_PER_HOUR 0 MAX_USER_CONNECTIONS 0;CREATE DATABASE IF NOT EXISTS `$POSTFIX_DB_NAME`;GRANT ALL PRIVILEGES ON `$POSTFIX_DB_NAME`.* TO '$POSTFIX_DB_USER'@'%';"

