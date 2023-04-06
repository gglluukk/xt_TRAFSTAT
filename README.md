# xt_TRAFSTAT

**xt_TRAFSTAT** is Linux kernel netfilter module to collect traffic statistic
 

## installation

**Note:** become root `sudo su -l` before applying commands below

### install needed packages

- **for Debian run:**

```
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | \
    debconf-set-selections

echo iptables-persistent iptables-persistent/autosave_v6 boolean true | \
    debconf-set-selections

apt-get --yes install build-essential linux-headers-`uname -r` \
    iptables-dev iptables-persistent net-tools cron
```

### get, build and install xt_TRAFSTAT 


- **download xt_TRAFSTAT:**

```
git clone https://gitlab.com/gluker/xt_TRAFSTAT.git
```

- **unpack sources:**

```
tar xzvf xt_TRAFSTAT-master.tar.gz 

```

- **compile kernel module and netfilter shared library:**

```
cd xt_TRAFSTAT-master
make install
```


## configure


### install and configure mariadb as data storage 

- **set mariadb password and preconfigure package:**

```
MYSQL_ROOT_PASSWORD="super-pass"
debconf-set-selections <<< \
"mysql-server mysql-server/root_password password $MYSQL_ROOT_PASSWORD"
debconf-set-selections <<< \
"mysql-server mysql-server/root_password_again password $MYSQL_ROOT_PASSWORD"

```

- **install mariadb with presets:**

```
apt-get --yes install mariadb-server
```

- **add to autostart:**

```
systemctl enable mariadb

```

- **allow `LOAD DATA INFILE`:**

```
cat >> /etc/mysql/my.cnf << EOF
[mysqld]
secure_file_priv = ""
EOF
```

- **apply changes:**

```
service mariadb restart
```

- **create client config needed by scripts:**

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

- **create database:**

```
mysql --defaults-file=/root/.my.cnf --database=mysql --execute "CREATE DATABASE trafstat"
```

- **create table `protocols`:**

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
cp misc/trafstat_rotater /etc/cron.weekly/
```

### installing script showing common statistics

```
cp misc/trafstat_show.sh /usr/local/bin/
```


## enabling statistics

### set host

- **finding out our IP-address or set HOST_IP manually:**

```
HOST_IP=`ip route get 8.8.8.8 | \
head -1 | awk '{ print $7; }'`

echo "Host IP-address: $HOST_IP"
```

### set ports

- **set TCP-ports being listened:**

```
TCP_PORTS=`netstat -apn --inet | grep -v 127.0.0.1 | \
grep LISTEN | grep ^tcp | awk '{ print $4; }' | \
sed -e 's|[0-9]*.[0-9]*.[0-9]*.[0-9]*:||' | \
sort -n | uniq | tr '\n' ',' | sed -e 's|,$||'`

if ! echo $TCP_PORTS | grep [0-9] ; then TCP_PORTS="none" ; fi

```

- **set UDP-ports being listened:**

```
UDP_PORTS=`netstat -apn --inet | grep -v 127.0.0.1 | \
grep -v ESTABLISHED | grep ^udp | awk '{ print $4; }' | \
sed -e 's|[0-9]*.[0-9]*.[0-9]*.[0-9]*:||' | \
sort -n | uniq | tr '\n' ',' | sed -e 's|,$||'`

if ! echo $UDP_PORTS | grep [0-9] ; then UDP_PORTS="none" ; fi
```

### set iptables' xt_TRAFSTAT rules

- **incoming traffic to host:**

```
iptables -I INPUT -d $HOST_IP -j TRAFSTAT \
--local-net $HOST_IP \
--local-tcp-ports $TCP_PORTS \
--local-udp-ports $UDP_PORTS
```

- **outgoing traffic from host:**

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


## how it works

### read list of options

`iptables -j TRAFSTAT -h`

### collect data

- **incoming traffic to host:**

IPTables' rule in `INPUT` chain of filter table with **destination** equals to IP-range of host, assuming your IP-address/range is A.B.C.D/X: 

```
iptables -I INPUT -d A.B.C.D/X -j TRAFSTAT --local-net A.B.C.D/X
```

- **outgoing traffic from host:**

IPTables' rule in `OUTPUT` chain of filter table with **source** equals to IP-range of host, assuming your IP-address/range is A.B.C.D/X: 

```
iptables -I OUTPUT -s A.B.C.D/X -j TRAFSTAT --local-net A.B.C.D/X
```

- **incoming NAT traffic from WAN to LAN:**

IPTables' rule in `FORWARD` chain of filter table with **destination** equals to LAN's IP-range, assuming LAN IP-range is A.B.C.D/X: 

```
iptables -I FORWARD -d A.B.C.D/X -j TRAFSTAT --local-net A.B.C.D/X
```

- **outgoing NAT traffic from LAN to WAN:**

IPTables' rule in `FORWARD` chain of filter table with **source** equals to LAN's IP-range, assuming LAN IP-range is A.B.C.D/X: 

```
iptables -I FORWARD -s A.B.C.D/X -j TRAFSTAT --local-net A.B.C.D/X
```

- **specify ports:**

By default xt_TRAFSTAT saves statistics by IP protocols, not by ports. You could define what specific by port(s) statistics you need by using options:

```
  --local-tcp-ports {all|none|port[,port,port]}
    statistics on all, none* or any 32 local TCP ports
  --local-udp-ports {all|none|port[,port,port]}
    statistics on all, none* or any 32 local UDP ports
  --remote-tcp-ports {all|none|port[,port,port]}
    statistics on all, none* or any 32 remote TCP ports
  --remote-udp-ports {all|none|port[,port,port]}
    statistics on all, none* or any 32 remote UDP ports
```

If you specify `all` for ports' option statistics will carry ports' number for all ports. If ports is `none` or port isn't in specified list it will be 0.


### read statistics

- **statistics storage:**
 
xt_TRAFSTAT creates special `/proc/trafstat/` entry with filename related to IP-range defined by `--local-net` option, assuming IP-range is A.B.C.D/X:

```
/proc/trafstat/A.B.C.D_X
```

- **file format:**

File format is CSV (Comma-Separated Values) ready to be injected into database in form, example:

```
17,3232235891,3232235777,123,0,6,7,351,660,0

where:
17            - protocol id
3232235891    - local IP-address
3232235777    - remote IP-address
123           - local port (see ports for UDP/TCP)
0             - remote port (see ports for UDP/TCP)
6             - local packets' count
7             - remote packets' count
351           - local bytes' count
660           - remote bytes' count
0             - TCP packets with SYN-flag count 
```

- **read storage:**

You can read storage in `/proc/trafstat/` in any time's interval. As soon as you read it statistics in storage is nulled.


