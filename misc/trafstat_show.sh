#!/bin/bash
#    FORMAT(COUNT(DISTINCT(t.local_ip + t.remote_ip)), 0) AS IPs, 

if [ $1 ]; then
    LIMIT="ORDER BY t.timestamp DESC LIMIT $1"
fi

mysql trafstat -e "
SELECT 
    CONCAT(CONCAT(p.protocol_name, '/'), t.protocol) AS proto, 
    CONCAT(CONCAT(FORMAT(SUM(t.local_data)/1024/1024, 3), ' / '), 
                  FORMAT(SUM(t.remote_data)/1024/1024, 3)) AS 'local/remote Mb',
    CONCAT(CONCAT(FORMAT(SUM(t.local_pkt), 0), ' / '),
                  FORMAT(SUM(t.remote_pkt), 0)) AS 'local/remote pkts',
    DATE_FORMAT(t.timestamp, '%m-%d %k:%i') AS 'mon-d h:min'
FROM
    trafstat AS t, 
    protocols AS p
WHERE
    t.protocol = p.protocol_num
GROUP BY
    t.timestamp,
    t.protocol
$LIMIT
"

