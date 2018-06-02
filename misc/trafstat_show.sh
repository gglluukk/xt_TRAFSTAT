#!/bin/bash
#    FORMAT(COUNT(DISTINCT(t.local_ip + t.remote_ip)), 0) AS IPs, 

SQLEXEC='mysql --defaults-file=/root/.my.cnf --database=trafstat -e '

if [ ! $1 ] ; then
    count=0
    usage="Usage: `basename $0` <trafstat table> [limit entries]"
    tables="Tables: "

    for table in `$SQLEXEC 'SHOW TABLES LIKE "trafstat_%"' | \
            grep ^trafstat_` ; do
        ((count++))
        tables+="$table "
    done

    if ((count != 1)) ; then
        echo $usage
        echo $tables
        exit
    fi
else
    table=$1
fi


if [ $2 ]; then
    LIMIT="ORDER BY t.timestamp DESC LIMIT $2"
fi


$SQLEXEC "
SELECT 
    CONCAT(CONCAT(p.protocol_name, '/'), t.protocol) AS proto, 
    CONCAT(CONCAT(FORMAT(SUM(t.local_data)/1024/1024, 3), ' / '), 
                  FORMAT(SUM(t.remote_data)/1024/1024, 3)) AS 'local/remote Mb',
    CONCAT(CONCAT(FORMAT(SUM(t.local_pkt), 0), ' / '),
                  FORMAT(SUM(t.remote_pkt), 0)) AS 'local/remote pkts',
    DATE_FORMAT(t.timestamp, '%m-%d %k:%i') AS 'mon-d h:min'
FROM
    ${table} AS t, 
    protocols AS p
WHERE
    t.protocol = p.protocol_num
GROUP BY
    t.timestamp,
    t.protocol
$LIMIT
"

