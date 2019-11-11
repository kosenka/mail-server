yum install httpd php phpmyadmin mariadb mariadb-server php-imap
systemctl start httpd
systemctl enable httpd
systemctl start mariadb
systemctl enable mariadb
/usr/bin/mysql_secure_installation
cd /usr/src
wget https://downloads.sourceforge.net/project/postfixadmin/postfixadmin/postfixadmin-3.0.2/postfixadmin-3.0.2.tar.gz
