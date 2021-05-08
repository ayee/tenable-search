
Tenable-search project implements a search index of assets and vulnerabilities extracted from Tenable.io

### Source code structure
- tenable_search : Python code to be run as a Python client continuously to download assets and vulnerabilities from Tenable bulk object download APIs, and write/index them into a Postgres database

- Tenable-search project uses [docker-compose](https://docs.docker.com/compose/) to construct 2 Docker containers: `postgres-docker` for hosting the Postgres database and the other `pytenable-client-docker` for the Python client

- `postgres_data` folder is the data volume of `postgres-docker`

- `data` folder has various files of sample asset and vulnerability data in JSON format, used for development and unit testing

- `tenable_search/test_tenable_search.py` has all of the test cases, which can also be used to execute actions such as populate database with mock assets and get physical size of database

### Database
Default implementation uses Postgres JSONB column to store and index JSON objects to allow fast search queries.
#### Assets table
id - The UUID of the asset. Use this value as the unique key for the asset.  This value is extracted from the asset JSON 
jdoc - Asset JSON objects
#### Vulns table
 
#### Generate mock data
Run [`test_populate_100k_assets`](tenable_search/test_tenable_search.py) testcase to populate mock assets and vulnerabilities

### Scheduled 
The periodic export and indexing job can be scheduled with 2 trigger types: 
interval: use when you want to run the job at fixed intervals of time
cron: use when you want to run the job periodically at certain time(s) of day

### Asset Retrieval and Update
Set up a schedule to execute asset update
For the first time ever run, execute TenableIO.exports.assets 
```
>>> assets = tio.exports.assets()
>>> for asset in assets:
...     write(asset, db)
```
Once initial assets export complete, this program will pause and resume on a schedule set with parameter `com.forescout.tenable-search.asset-update-period`
When this program is resumed, it will query 
```
>>> import time
>>> last_update = int(time.time()) - asset_update_period
>>> for asset in tio.exports.assets(updated_at=last_update):
...     update(asset, db)
```
#### Questions to Tenable
1. What asset timestamp field, `updated_at` or `last_seen`, correspond to export filter `updated_at`?
2. Are the asset objects returned by pyTenable and exports API ordered by any fields, updated_at?

### How to build
This project uses [docker-compose](https://docs.docker.com/compose/) to containerize and separate a Postgres database instance and the Python runtime with TenableSearch and pyTenable code.  This makes it easier to adapt the project to different storage types.

Run this to build dockers

    docker-compose build
        
Run this bring up database docker

    docker-compose up
        
To connect to Postgres database with `psql` client

    docker exec -it tenable-search_postgres_1 psql -U admin
    
If database schema is changed, you'll have to delete the data directory completely and rebuild

    docker-compose down
    rm -fr postgres_data
    docker-compose build
    docker-compose up
    
### Other Useful Postgres Commands
Listing databases

    \l

Connect to tenable objects table

    \c tenable
    
List tables with command

    \dt 
    
Toggle timing 

    \timing
  
Use this to bulk load from JSON file into JSONB column

    \copy assets (jdoc) from 'data/assets.json'
   
Retrieve an asset by IPv4.  The JSONB operator `@>` checks if 
`jdoc`JSON object contains the JSON ipv4 key with the specified value at the top level.  Not that this works array of multiple IPv4 values.  That means the query would return an asset with the `ipv4` element being an array of values like this `["145.14.140.28", "25.150.68.229"]`
```sql
SELECT * FROM assets 
    WHERE jdoc @> '{"ipv4": ["25.150.68.229"]}'
```
Retrieve an asset matched by any of multiple attributes.  
```sql
SELECT jdoc->>'id' FROM assets 
    WHERE jdoc @> '{"ipv4": ["25.150.68.229"]}' 
    OR jdoc @> '{"fqdn": ["tnxlphzmyv"]}';
```
Once an asset has been identified, all vulnerabilities of the asset can be retrieved like this:
```postgresql
select substring(jdoc->'scan'->>'uuid',1,8), substring(jdoc->'plugin'->>'name',1,10), jdoc->'scan'->>'completed_at' from vulns 
    where jdoc->'asset' @> '{"uuid":"f7c9b98d-626f-47f3-87f3-8428043fccf2"}';
```

Here's a query to join `scans` and `vulns` tables on scan UUID
```sql
select s.jdoc->>'name', s.jdoc->>'policy_id', v.jdoc->'scan'->>'uuid', substring(v.jdoc->'plugin'->>'name',1,10) 
    from vulns v join scans s 
    on v.jdoc->'scan'->>'uuid' = s.jdoc->>'uuid';
```
Because `scan` only has policy_id but not other policy details, we might need a query to join `policies` table
```sql
select 
    s.jdoc->>'name' as scan_name, 
    s.jdoc->>'policy_id' as policy_id, 
    p.jdoc->>'name' as policy_name, 
    substring(v.jdoc->'plugin'->>'name',1,10) as plugin_name
from vulns v 
    join scans s on v.jdoc->'scan'->>'uuid' = s.jdoc->>'uuid'
    join policies p on s.jdoc->>'policy_id' = p.jdoc->>'id';
```
Expected output:
```text
                     scan_name                      | policy_id |          policy_name           | plugin_name 
----------------------------------------------------+-----------+--------------------------------+-------------
 fs_Basic Network Scan - DNS_TEST1618448104.75151   | 2773      | Basic Network Scan - DNS       | RPC Servic
 fs_Basic Network Scan - DNS_TEST1618448104.75151   | 2773      | Basic Network Scan - DNS       | Common Pla
 fs_Basic Network Scan - DNS_TEST1618448104.75151   | 2773      | Basic Network Scan - DNS       | RPC Servic
 fs_Basic Network Scan - DNS_TEST1618448104.75151   | 2773      | Basic Network Scan - DNS       | OS Identif
```


Delete a single asset matching the asset UUID
```sql
DELETE FROM assets 
    WHERE jdoc->>'id' IN ('a3ff9398-0270-4e20-a0b9-6c98d9d1a53f');
```
Delete 10000 assets matching randomly chosen UUIDs.
This query takes about 360ms on 350K rows table.  Excluding scan time, the deletion takes about 300ms
```sql
DELETE FROM assets WHERE jdoc->>'id' IN 
    (SELECT jdoc->>'id' FROM assets 
        OFFSET floor(random()*(SELECT count(*) FROM assets)) 
        LIMIT 10000);
```
    
