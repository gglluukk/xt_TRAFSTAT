# xt_TRAFSTAT

**xt_TRAFSTAT** is Linux kernel netfilter module to collect traffic statistic
 

## installation

**Note:** become root `sudo su -l` before applying commands below

### install needed packages

- for Debian run:

```
apt-get --yes install linux-headers-`uname -r` iptables-dev
```

### get, build and install trafstat 


- download trafstat:

```
wget http://gitlab.fbsvc.bz/gluker/xt_TRAFSTAT/-/archive/master/xt_TRAFSTAT-master.tar.gz
```

- unpack sources:

```
tar xzvf xt_TRAFSTAT-master.tar.gz 

```

- compile kernel module and netfilter shared library:

```
cd xt_TRAFSTAT-master
make install
```


## configure


### install and configure mysql as datastorage for trafstat

- set mysql password and preconfigure package

```
MYSQL_ROOT_PASSWORD="super-pass"
debconf-set-selections <<< \
"mysql-server mysql-server/root_password password $MYSQL_ROOT_PASSWORD"
debconf-set-selections <<< \
"mysql-server mysql-server/root_password_again password $MYSQL_ROOT_PASSWORD"

```

- install mysql with presets

```
apt-get --yes install mysql-server
```

- add to autostart

```
systemctl enable mysql

```

- allow LOAD DATA INFILE

```
cat >> /etc/mysql/my.cnf << EOF
[mysqld]
secure_file_priv = ""
EOF
```

- apply changes

```
service mysql restart
```

- create client config needed by scripts

```
cat > /root/.my.cnf << EOF
[client]
user        = root
password    = $MYSQL_ROOT_PASSWORD
[mysql]
database    = trafstat
prompt 	    = "\u@\h \d> "
EOF
```

- create database

```
mysql --defaults-file=/root/.my.cnf --database=mysql --execute "CREATE DATABASE trafstat"
```

### create rule to count traffic to host itself

```
for net in 142.0.198.24/29 173.0.146.0/24 173.0.153.0/24 ; do
  iptables -I INPUT -d $net -j TRAFSTAT --local-net $net \
    --local-tcp-ports 22,53,80,5665 --local-udp-ports none --max-entries 2000
  iptables -I OUTPUT -s $net -j TRAFSTAT --local-net $net \
    --local-tcp-ports 22,53,80,5665 --local-udp-ports none --max-entries 2000
done
```

### checking ports

```
netstat -apn --inet | grep LIST | grep '0.0.0.0:[0-9]'
netstat -apn --inet | grep LIST | grep '0.0.0.0:[0-9]' | \
awk '{ print $4; }' | sed -e 's|0.0.0.0:||' | sort -n | tr '\n' ','
```


### preparing crontab task to collect statistics every 5 minutes

```
cp misc/trafstat_dumper.sh /usr/local/bin/
cat >> /etc/crontab << EOF
*/5 *   * * *   root    /usr/local/bin/trafstat_dumper.sh >> /tmp/trafstat_dumper.log
EOF
```

### preparing crontab task to backup statistics every week

```
mkdir /var/trafstat/
chmod 770 /var/trafstat/
chown mysql:mysql /var/trafstat/
cp misc/trafstat_rotater.sh /etc/cron.weekly/
```

### installing script showing common statistics

```
cp misc/trafstat_show.sh /usr/local/bin/
```

### backup old firewall rules and saving new 

```
cp -fT --backup=t /etc/iptables/rules.v4 \
    /etc/iptables/rules.v4-`date +%Y-%m-%d_%H-%M`
iptables-save > /etc/iptables/rules.v4
```


