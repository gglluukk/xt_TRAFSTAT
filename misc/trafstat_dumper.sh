#!/bin/bash

SQLEXEC='mysql --defaults-file=/root/.my.cnf --database=trafstat -e '
TIMEFORMAT='%3R'


function create_table {
    $SQLEXEC "
CREATE TABLE IF NOT EXISTS trafstat_${1} (
  _traf_id int(10) unsigned NOT NULL AUTO_INCREMENT,
  protocol tinyint(3) unsigned DEFAULT '0',
  local_ip int(10) unsigned DEFAULT '0',
  remote_ip int(10) unsigned DEFAULT '0',
  local_port mediumint(8) unsigned DEFAULT '0',
  remote_port mediumint(8) unsigned DEFAULT '0',
  local_pkt int(10) unsigned DEFAULT '0',
  remote_pkt int(10) unsigned DEFAULT '0',
  local_data bigint(20) unsigned DEFAULT '0',
  remote_data bigint(20) unsigned DEFAULT '0',
  syn_count int(10) unsigned NOT NULL DEFAULT '0',
  timestamp timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (_traf_id),
  KEY protocol (protocol),
  KEY local_ip (local_ip),
  KEY remote_ip (remote_ip),
  KEY local_port (local_port),
  KEY remote_port (remote_port),
  KEY timestamp (timestamp)
) ENGINE=MyISAM
    "
}


for i in /proc/trafstat/* ; do
    file=`basename $i`
    table=`echo $file | tr '.' '_'`
    
    create_table $table
    
    TMPFILE="/tmp/trafstat_${file}"

    (echo -n "`date +%m-%d_%H-%M` query run "  
     time $SQLEXEC "
LOAD DATA INFILE '/proc/trafstat/${file}'
INTO TABLE trafstat_${table} FIELDS TERMINATED BY ','
(protocol, local_ip, remote_ip, local_port, remote_port,
local_pkt, remote_pkt, local_data, remote_data, syn_count)
        " ) &>> $TMPFILE

done

