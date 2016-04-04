#!/bin/sh

SQLEXEC='mysql --defaults-file=/root/.my.cnf --database=trafstat -e '

for table in `$SQLEXEC 'SHOW TABLES LIKE "trafstat_%"' | grep ^trafstat_` ; do
    current_date=`date +%Y_%m_%d-%H:%M`

    $SQLEXEC \
            "
            LOCK TABLES ${table} WRITE;

            SELECT * 
            FROM ${table}
            INTO OUTFILE '/var/trafstat/${table}_${current_date}';

            UNLOCK TABLES;

            TRUNCATE TABLE ${table};
            " 

    gzip /var/trafstat/${table}_${current_date}

done

