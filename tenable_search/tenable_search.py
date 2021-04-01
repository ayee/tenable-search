import json, logging, time, uuid, yaml, pkg_resources, string
import random, socket, struct

import psycopg2, psycopg2.extensions
from psycopg2 import OperationalError
from psycopg2.extras import LoggingConnection, LoggingCursor, Json
from tenable.io import TenableIO

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class TenableSearch:
    '''
    Class abstraction of all objects retrieved from Tenable.io
    '''
    conn = None
    tio = None

    def __init__(self, access, secret):
        # print(pkg_resources.resource_stream(__name__, 'settings.yml'))
        with pkg_resources.resource_stream(__name__, r'settings.yml') as file:
            properties = yaml.full_load(file)
        self.tio = TenableIO(properties['access_key'], properties['secret_key'])
        self.conn = self.create_connection(**properties)

    def create_connection(self, db_name, db_user, db_password, db_host, db_port):
        ''' Create postgres connection with psycopg2
        :param db_name: name of database
        :param db_user:
        :param db_password:
        :param db_host:
        :param db_port:
        :return:
        '''
        conn = None
        try:
            conn = psycopg2.connect(
                # connection_factory=MyLoggingConnection,
                database=db_name,
                user=db_user,
                password=db_password,
                host=db_host,
                port=db_port,
            )
            # conn.initialize(logger)
            print("Connection to PostgreSQL DB successful")
        except OperationalError as e:
            print("The error '{}' occurred".format(e))
        return conn


    def execute_read_query(self, query):
        import time
        start = time.time()

        cursor = self.conn.cursor()
        result = None
        try:
            cursor.execute(query)
            result = cursor.fetchall()
            end = time.time()
            logger.info("Query [{}] took {}".format(query, end - start))
            return result
        except OperationalError as e:
            logger("The error '{}' occurred".format(e))


    def populate_assets(self, size=None):
        '''
        Download and populate assets to db
        :return:
        '''
        import time
        start = time.time()
        cursor = self.conn.cursor()
        if size is not None:
            # if size specified, populate with random mock assets
            # TODO: enhance with bulk loading
            # https://gist.github.com/revbucket/ccecce8b9f3971077354de307ee680c2
            with pkg_resources.resource_stream(__name__, 'asset_sample.json') as f:
                asset = json.loads(f.read())
            for i in range(size):
                asset['id'] = str(uuid.uuid4())
                asset['ipv4'] = [socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
                                 for i in range(random.randint(1, 3))]
                asset['last_scan_target'] = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
                asset['fqdn'] = [''.join(random.choice(string.ascii_lowercase) for i in range(10))]
                cursor.execute("INSERT INTO assets (jdoc) VALUES (%s)", (json.dumps(asset),))
            end = time.time()
            logger.info('{} randomly generated mock assets populated'.format(size))
            logger.info("Asset population completed in {}s".format(end - start))
        else:
            for asset in self.tio.assets.list():
                cursor.execute("INSERT INTO assets (jdoc) VALUES (%s)", (json.dumps(asset),))

        self.conn.commit()


    def count_assets(self):
        result = self.execute_read_query("SELECT COUNT (*) FROM assets")
        return result[0][0]


    def write_assets(self, outfile):
        '''
        Export assets and save them in a file
        :param outfile:
        :return:
        '''
        # store all assets into a file, one json each line
        with open('../data/assets.json', 'a') as outfile:
            for asset in self.tio.assets.list():
                json.dump(asset, outfile)
                outfile.write('\n')


    def delete_all_assets(self):
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM assets')
        self.conn.commit()


    def reset_database(self):
        '''
        Drop and recreate database.  All data will be lost
        :return:
        '''
        with self.conn as cursor:
            cursor.execute(open("../postgres-docker/init.sql", "r").read())


    def get_size(self):
        '''
        Get disk storage of Tenable result search index
        :return: size in bytes
        '''
        cursor = self.conn.cursor()
        cursor.execute(
            '''
            SELECT 
                CASE WHEN pg_catalog.has_database_privilege(d.datname, 'CONNECT')
                    THEN pg_catalog.pg_size_pretty(pg_catalog.pg_database_size(d.datname))
                    ELSE 'No Access'
                END as Size
            FROM pg_catalog.pg_database d WHERE d.datname = 'tenable'
            '''
        )
        return cursor.fetchall()[0][0]

    def retrieve_assets(self):
        '''
        Retrieve all assets from Tenable.io API and load them in search index
        :return:
        '''
        for asset in tio.assets.list():
            json.dump(asset, outfile)
            outfile.write('\n')


    def search_asset(self, **kwargs):
        '''
        Find assets where keys and values match as passed with parameters
        e.g. search_asset(conn, id='3a7efde2-7106-495a-acb7-3157c56dec41')
        search_asset(conn, id='3a7efde2-7106-495a-acb7-3157c56dec41', has_agent=True)
        :param kwargs:
        :return: list of assets (as dicts), empty list if nothing found
        '''
        query = '''SELECT * FROM assets WHERE jdoc @> %s''' % Json(kwargs)
        result = self.execute_read_query(query)
        return result


def populate_assets(conn, size):
    '''
    Populate with mock asset data
    :param conn:
    :param size:
    :return:
    '''
    # TODO: enhance with bulk loading https://gist.github.com/revbucket/ccecce8b9f3971077354de307ee680c2
    # autocommit_orig = conn.autocommit
    # conn.autocommit = True
    cursor = conn.cursor()

    asset = {"id": "b4df99b1-e06e-4aca-af12-5e09afcbfc00",
             "has_agent": False, "last_seen": "2019-08-21T23:57:31.118Z",
             "last_scan_target": "192.168.1.125",
             "sources": [{"name": "NESSUS_SCAN", "first_seen": "2019-08-21T23:57:31.118Z",
                          "last_seen": "2019-08-21T23:57:31.118Z"}],
             "ipv4": ["192.168.1.125"], "ipv6": [], "fqdn": [], "netbios_name": [],
             "operating_system": [], "agent_name": [], "aws_ec2_name": [],
             "security_protection_level": None, "security_protections": [], "mac_address": []}


    for i in range(size):
        asset['id'] = str(uuid.uuid4())
        cursor.execute("INSERT INTO asset (asset_data) VALUES (%s)", (json.dumps(asset),))

    conn.commit()
    # conn.autocommit = autocommit_orig

def write_assets(outfile):
    '''
    Export assets and save them in a file
    :param outfile:
    :return:
    '''

    # assets = tio.exports.assets()
    # asset = assets.next()
    # vuls = tio.exports.vulns()
    # store all assets into a file, one json each line
    with open('../data/assets.json', 'a') as outfile:
        for asset in tio.assets.list():
            json.dump(asset, outfile)
            outfile.write('\n')


def insert_asset_orm(conn, asset):
    '''
    Insert asset using sqlalchemy orm
    :param conn:
    :return:
    '''
    m = sqlalchemy.MetaData()
    asset_table = sqlalchemy.Table('asset', m,
                                   sqlalchemy.Column('id', sqlalchemy.Integer, primary_key=True),
                                   sqlalchemy.Column('asset_data', JSONB))
    conn.execute(
        asset_table.insert(),
        asset_data = asset
    )


# MyLoggingCursor simply sets self.timestamp at start of each query
class MyLoggingCursor(LoggingCursor):
    def execute(self, query, vars=None):
        self.timestamp = time.time()
        return super(MyLoggingCursor, self).execute(query, vars)

    def callproc(self, procname, vars=None):
        self.timestamp = time.time()
        return super(MyLoggingCursor, self).callproc(procname, vars)


# MyLogging Connection:
#   a) calls MyLoggingCursor rather than the default
#   b) adds resulting execution (+ transport) time via filter()
class MyLoggingConnection(LoggingConnection):
    def filter(self, msg, curs):
        return "   %d ms".format(int((time.time() - curs.timestamp) * 1000))

    def cursor(self, *args, **kwargs):
        kwargs.setdefault('cursor_factory', MyLoggingCursor)
        return LoggingConnection.cursor(self, *args, **kwargs)












def search_asset(conn, **kwargs):
    '''
    Find assets where keys and values match as passed with parameters
    e.g. search_asset(conn, id='3a7efde2-7106-495a-acb7-3157c56dec41')
    search_asset(conn, id='3a7efde2-7106-495a-acb7-3157c56dec41', has_agent=True)

    :param conn:
    :param kwargs:
    :return: list of assets (as dicts), empty list if nothing found
    '''
    query = '''SELECT * FROM asset WHERE asset_data @> %s''' % Json(kwargs)
    return execute_read_query(conn, query)


# def search_asset(conn, id):
#     from psycopg2.extras import Json
#     cursor = conn.cursor()
#     # query = cursor.mogrify("SELECT * FROM asset WHERE asset_data @> %s", ({"id": "f5854291-b248-4487-a3f0-08727767f8e2"},))
#     print(execute_read_query(conn, '''SELECT * FROM asset WHERE asset_data @> %s''' % Json({"id": id})))
#     return None

def find_largest_databases(conn):
    cursor = conn.cursor()
    cursor.execute(
        '''
        SELECT d.datname as Name,  pg_catalog.pg_get_userbyid(d.datdba) as Owner,
    CASE WHEN pg_catalog.has_database_privilege(d.datname, 'CONNECT')
        THEN pg_catalog.pg_size_pretty(pg_catalog.pg_database_size(d.datname))
        ELSE 'No Access'
    END as Size
FROM pg_catalog.pg_database d
    order by
    CASE WHEN pg_catalog.has_database_privilege(d.datname, 'CONNECT')
        THEN pg_catalog.pg_database_size(d.datname)
        ELSE NULL
    END desc -- nulls first
    LIMIT 20
        '''
    )
    return cursor.fetchall()


# def main():
#     conn = create_connection("tenable", "admin", "secret", "postgres", "5432")
#     print("Asset count = {}".format(count_asset(conn)))
#     populate_assets(conn, 100000)
#     print("Stuffed to {} assets".format(count_asset(conn)))
#     search_asset(conn, 0)
#
#
# if __name__ == "__main__":
#     main()

