import json, logging, time, uuid, yaml, pkg_resources, string
import random, socket, struct, os, argparse
from datetime import datetime, timezone
import psycopg2, psycopg2.extensions
from psycopg2 import OperationalError, sql
from psycopg2.extras import LoggingConnection, LoggingCursor, Json
from tenable.io import TenableIO
from apscheduler.schedulers.background import BackgroundScheduler

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

from functools import wraps
def timeit(func):
    @wraps(func)
    def _time_it(*args, **kwargs):
        start = time.perf_counter()
        try:
            return func(*args, **kwargs)
        finally:
            end_ = time.perf_counter() - start
            logger.info(f"{func.__name__} total exec time={end_ * 1000:.2f}ms {'['+str(args[1])+']' if len(args)>1 else ''} ")
    return _time_it


class TenableSearch:
    '''
    Class abstraction of all objects retrieved from Tenable.io
    '''
    conn = None
    tio = None
    # timestamp at which the last export was executed,
    # 0 if export has never been executed
    checkpoint = 0

    def __init__(self, access, secret):
        with pkg_resources.resource_stream(__name__, r'settings.yml') as file:
            properties = yaml.full_load(file)
        self.tio = TenableIO(properties['access_key'], properties['secret_key'])
        self.conn = self.create_connection(**properties)
        self.checkpoint = self.execute_read_query("select max(checkpoint) from export_jobs where job_end is not null")

    # def create_connection(self, db_name, db_user, db_password, db_host, db_port):
    def create_connection(selfs, **kwargs):
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
                database=kwargs['db_name'],
                user=kwargs['db_user'],
                password=kwargs['db_password'],
                host=kwargs['db_host'],
                port=kwargs['db_port'],
            )
            conn.autocommit = False
            # conn.initialize(logger)
            logger.info("Connection to PostgreSQL DB successful")
        except OperationalError as e:
            print("The error '{}' occurred".format(e))
        return conn

    @timeit
    def execute_read_query(self, query):
        cursor = self.conn.cursor()
        result = None
        try:
            cursor.execute(query)
            result = cursor.fetchall()
            # logger.info("Query [{}] took {}".format(query, end - start))
            return result
        except OperationalError as e:
            logger.error("The error '{}' occurred".format(e))

    @timeit
    def populate_assets(self, size=None, vuln_asset_ratio=2):
        """Populate mock assets and vulnerabilities to databa"""
        cursor = self.conn.cursor()
        if size is not None:
            # if size specified, populate with random mock assets
            # TODO: enhance with bulk loading
            # https://gist.github.com/revbucket/ccecce8b9f3971077354de307ee680c2
            with pkg_resources.resource_stream(__name__, 'asset_sample.json') as f:
                asset = json.loads(f.read())
            with pkg_resources.resource_stream(__name__, 'vuln_sample.json') as f:
                vuln = json.loads(f.read())
            for i in range(size):
                asset_uuid = str(uuid.uuid4())
                asset_ips = [socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
                                 for i in range(random.randint(1, 3))]
                asset_fqdn = [''.join(random.choice(string.ascii_lowercase) for i in range(10))]
                asset['id'] = asset_uuid
                asset['ipv4'] = asset_ips
                asset['fqdn'] = asset_fqdn
                asset['last_scan_target'] = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))

                cursor.execute("INSERT INTO assets (jdoc) VALUES (%s)", (json.dumps(asset),))

                vuln['asset']['uuid'] = asset_uuid
                vuln['asset']['fqdn'] = asset_fqdn
                vuln['asset']['ipv4'] = asset_ips[0]

                for j in range(vuln_asset_ratio):
                    cursor.execute("INSERT INTO vulns (jdoc) VALUES (%s)", (json.dumps(vuln),))

            logger.info('Populated {} mock assets and {} vulnerabilities in database'.format(size, size*vuln_asset_ratio))
        else:
            for asset in self.tio.assets.list():
                cursor.execute("INSERT INTO assets (jdoc) VALUES (%s)", (json.dumps(asset),))

        self.conn.commit()

    def count_assets(self):
        result = self.execute_read_query("SELECT COUNT (*) FROM assets")
        return result[0][0]

    def count_vulns(self):
        result = self.execute_read_query("SELECT COUNT (*) FROM vulns")
        return result[0][0]

    def write_assets_to_file(self, outfile):
        """
        Save assets in a file
        :param outfile:
        :return:
        """
        # store all assets into a file, one json each line
        with open('../data/assets.json', 'a') as outfile:
            for asset in self.tio.assets.list():
                json.dump(asset, outfile)
                outfile.write('\n')

    def delete_all_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM assets')
        cursor.execute('DELETE FROM vulns')
        cursor.execute('DELETE FROM export_jobs')

        # Run full vacuum to clear up database
        old_isolation_level = self.conn.isolation_level
        self.conn.set_isolation_level(0)
        cursor = self.conn.cursor()
        cursor.execute("VACUUM FULL")
        self.conn.commit()
        self.conn.set_isolation_level(old_isolation_level)

    def reset_database(self):
        """
        Drop and recreate database.  All data will be lost
        :return:
        """
        cursor = self.conn.cursor()
        cursor.execute(open("../postgres-docker/init.sql", "r").read())
        self.conn.commit()

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

    def search_asset(self, **kwargs):
        """
        Find assets where keys and values match as passed with parameters
        e.g. search_asset(conn, id='3a7efde2-7106-495a-acb7-3157c56dec41')
        search_asset(conn, id='3a7efde2-7106-495a-acb7-3157c56dec41', has_agent=True)
        :param kwargs:
        :return: list of assets (as dicts), empty list if nothing found
        """
        query = '''SELECT * FROM assets WHERE jdoc @> %s''' % Json(kwargs)
        result = self.execute_read_query(query)
        return result

    def export_all(self):
        '''
        Export and index all objects
        :return:
        '''
        # if tables are not empty, error out
        logger.info('Initializing assets export')
        self.insert_objects('assets', self.tio.exports.assets())
        self.insert_objects('vulns', self.tio.exports.vulns())
        self.insert_objects('scans', self.tio.scans.list())
        self.insert_objects('policies', self.tio.policies.list())

    def run_export_job(self):
        """
        Run scheduled job to export Tenable.io API objects and index them
        :return:
        """
        # self.checkpoint = self.execute_read_query("select max(checkpoint) from export_jobs where job_end is not null")
        cursor = self.conn.cursor()
        t = datetime.now(timezone.utc)
        logger.info(f"Running tenable export job at {t}")
        cursor.execute("INSERT INTO export_jobs (job_start) VALUES (TIMESTAMP %s) RETURNING id", [t])
        id = cursor.fetchone()[0]
        if self.checkpoint == 0:
            logger.info('No checkpoint found, exporting all objects... ')
            self.export_all()
        else:
            # last_period = int(time.time()) - 604800
            self.insert_objects('assets', self.tio.exports.assets(created_at=self.checkpoint))
            self.update_objects('assets', self.tio.exports.assets(updated_at=self.checkpoint))
            self.delete_objects('assets', self.tio.exports.assets(deleted_at=self.checkpoint))
            self.delete_objects('assets', self.tio.exports.assets(terminated_at=self.checkpoint))

        cursor.execute('UPDATE export_jobs SET job_end = TIMESTAMP %s WHERE id = %s', [datetime.now(timezone.utc), id])
        self.conn.commit()
        logger.info('Update assets and vulns, time is: %s' % datetime.now())

    def insert_objects(self, table, objects):
        cursor = self.conn.cursor()
        count = 0
        start = time.time()
        for obj in objects:
            count += 1;
            cursor.execute(sql.SQL("INSERT INTO {} (jdoc) VALUES (%s)")
                           .format(sql.Identifier(table)), (json.dumps(obj), ))
            if count % 100 == 0:
                logger.info("{} {} exported and indexed...".format(count, table))
        self.conn.commit()
        logger.info("{} {} exported and indexed, took {}s".format(count, table, time.time()-start))

    def update_objects(self, table, objects):
        cursor = self.conn.cursor()
        count = 0
        start = time.time()
        for obj in objects:
            count += 1;
            cursor.execute("UPDATE %s SET jdoc = %s WHERE id = %s", (table, json.dumps(obj), obj['id']))
            if count % 100 == 0:
                logger.info("{} {}'s updated in database...".format(count, table))
        self.conn.commit()
        logger.info("{} {}'s updated, took {}s".format(count, table, time.time()-start))



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



if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Launch indexing Tenable assets and vulnerabilities',
        add_help=False
    )
    parser.add_argument('-h', '--db_host', type=str, help='database host', default='postgres')
    parser.add_argument('-d', '--db_name', type=str, help='database name', default='tenable',)
    parser.add_argument('-p', '--db_port', type=int, help='database port', default=5432)
    parser.add_argument('-u', '--db_user', type=str, help='database username', default='admin')
    parser.add_argument('-w', '--db_password', type=str, help='database password', default='secret')
    parser.add_argument('-a', '--access_key', type=str, help='Tenable.io access key')
    parser.add_argument('-s', '--secret_key', type=str, help='Tenable.io secret key')
    parser.add_argument('-c', '--cron', type=str, help='Schedule with cron job string')
    parser.add_argument('-i', '--interval', type=str, help='Schedule with interval string')

    args = vars(parser.parse_args())

    search = TenableSearch(access=args['access_key'], secret=args['secret_key'])
    scheduler = BackgroundScheduler()
    scheduler.add_job(search.run_export_job, 'interval', seconds=10)
    scheduler.start()
    print('Press Ctrl+{0} to exit'.format('Break' if os.name == 'nt' else 'C'))
