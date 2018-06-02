# xt_TRAFSTAT

**xt_TRAFSTAT** is Linux kernel netfilter module to collect traffic statistic
 

## installation

**Note:** become root `sudo su -l` before applying commands below

### install needed packages

- for Debian run:

```
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | \
    debconf-set-selections

echo iptables-persistent iptables-persistent/autosave_v6 boolean true | \
    debconf-set-selections

apt-get --yes install linux-headers-`uname -r` \
    iptables-dev iptables-persistent net-tools
```

### get, build and install xt_TRAFSTAT 


- download xt_TRAFSTAT:

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


### install and configure mysql as data storage 

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

- create table with protocols

```
mysql --defaults-file=/root/.my.cnf --database=trafstat < misc/protocols.sql
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


## enabling statistics

### set host

- finding out our IP-address or set it by your own:

```
HOST_IP=`ip route get 8.8.8.8 | \
head -1 | awk '{ print $7; }'`

echo "Host IP-address: $HOST_IP"
```

### set ports

- set TCP-ports being listened:

```
TCP_PORTS=`netstat -apn --inet | \
grep LIST | grep ^tcp | grep '0.0.0.0:[0-9]' | \
awk '{ print $4; }' | sed -e 's|0.0.0.0:||' | \
sort -n | tr '\n' ',' | sed -e 's|,$||'`

if ! echo $TCP_PORTS | grep [0-9] ; then \
TCP_PORTS="none" ; fi

```

- set UDP-ports being listened:

```
UDP_PORTS=`netstat -apn --inet | \
grep LIST | grep ^udp | grep '0.0.0.0:[0-9]' | \
awk '{ print $4; }' | sed -e 's|0.0.0.0:||' | \
sort -n | tr '\n' ',' | sed -e 's|,$||'`

if ! echo $UDP_PORTS | grep [0-9] ; then \
UDP_PORTS="none" ; fi
```

### set iptables' xt_TRAFSTAT rules

- for traffic in @INPUT:

```
iptables -I INPUT -d $HOST_IP -j TRAFSTAT \
--local-net $HOST_IP \
--local-tcp-ports $TCP_PORTS \
--local-udp-ports $UDP_PORTS
```

- for traffic out @OUTPUT:

```
iptables -I OUTPUT -s $HOST_IP -j TRAFSTAT \
--local-net $HOST_IP \
--local-tcp-ports $TCP_PORTS \
--local-udp-ports $UDP_PORTS
```

### backup old firewall rules and saving new 

```
cp -fT --backup=t /etc/iptables/rules.v4 \
    /etc/iptables/rules.v4-`date +%Y-%m-%d_%H-%M`
iptables-save > /etc/iptables/rules.v4
```
