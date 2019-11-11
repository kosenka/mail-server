yum install httpd php phpmyadmin mariadb mariadb-server php-imap
systemctl start httpd
systemctl enable httpd
systemctl start mariadb
systemctl enable mariadb
/usr/bin/mysql_secure_installation
