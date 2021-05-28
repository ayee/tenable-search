import json, logging, time, uuid, yaml, pkg_resources, string
import random, socket, struct, os, argparse
from datetime import datetime, timezone
import psycopg2, psycopg2.extensions
from psycopg2 import OperationalError, sql
from psycopg2.extras import LoggingConnection, LoggingCursor, Json
from tenable.io import TenableIO
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.blocking import BlockingScheduler

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
            logger.info(f"{func.__name__} "
                        f"{'['+str(args[1])+']' if len(args)>1 else ''} "
                        f"total exec time={end_ * 1000:.2f}ms")
    return _time_it


class TenableSearch:
    """
    Class abstraction of all objects retrieved from Tenable.io
    """
    conn = None
    tio = None
    # timestamp at which the last export was executed,
    # 0 if export has never been executed
    checkpoint = 0

    def __init__(self, properties):
        self.tio = TenableIO(properties['access_key'], properties['secret_key'])
        self.conn = self.create_connection(**properties)
        logger.info('Database connection created')

    # def create_connection(self, db_name, db_user, db_password, db_host, db_port):
    @staticmethod
    def create_connection(**kwargs):
        """
        Create Postgres connection using psycopg2
        :return: connection
        """
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
            self.conn.commit()
            result = cursor.fetchall()
            logger.info("Query [{}] executed successfully with result {}".format(query, result))
            return result
        except OperationalError as e:
            logger.error(f"The error '{e}' occurred")

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
        table_list = {'assets', 'vulns', 'scans', 'policies', 'export_jobs'}
        for t in table_list:
            cursor.execute(f'DELETE FROM {t}')
            self.conn.commit()

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
        """
        Get disk storage of Tenable result search index
        :return: size in bytes
        """
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT 
                CASE WHEN pg_catalog.has_database_privilege(d.datname, 'CONNECT')
                    THEN pg_catalog.pg_size_pretty(pg_catalog.pg_database_size(d.datname))
                    ELSE 'No Access'
                END as Size
            FROM pg_catalog.pg_database d WHERE d.datname = 'tenable'
            """
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
        query = "SELECT * FROM assets WHERE jdoc @> %s" % Json(kwargs)
        result = self.execute_read_query(query)
        return result

    def export_initial(self):
        """
        Delete all objects in tenable database including jobs data
        Export and index all objects
        :return:
        """
        self.delete_all_tables()
        # if tables are not empty, error out
        logger.info('Exporting assets and vulns')
        self.insert_objects('assets', self.tio.exports.assets())
        self.insert_objects('vulns', self.tio.exports.vulns())
        logger.info('Exporting scans and policies')
        self.insert_objects('scans', self.tio.scans.list())
        self.insert_objects('policies', self.tio.policies.list())

    @timeit
    def run_export_job(self):
        """
        Run scheduled job to export Tenable.io API objects and index them
        :return:
        """
        start = datetime.now(timezone.utc)
        logger.info(f"Starting export job at {start}")

        result = self.execute_read_query("select max(checkpoint) from export_jobs where job_end is not null")
        self.checkpoint = 0 if result[0][0] is None else result[0][0]

        if self.checkpoint == 0:

            logger.info('No existing checking found, initializing Tenable export database...')
            self.export_initial()
        else:
            print(self.checkpoint)
            logger.info(
                'Checkpoint found: {}'.format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.checkpoint))))
            self.export_update()

        end = datetime.now(timezone.utc)
        logger.info(f"Logging in database completed export job at {end}")
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO export_jobs (job_start, job_end) VALUES (TIMESTAMP %s, TIMESTAMP %s)", [start, end])
        # cursor.execute('UPDATE export_jobs SET job_end = TIMESTAMP %s WHERE id = %s', [t, job_id])
        logger.info('Updated export_jobs record')
        self.conn.commit()

    @timeit
    def export_update(self):
        """
        Assume there are already objects previously stored in database, export
        newly created, updated, terminated, and deleted assets
        :return:
        """
        # insert assets created since checkpoint
        self.insert_objects('assets', self.tio.exports.assets(created_at=self.checkpoint))
        # update assets updated since checkpoint
        self.update_assets(self.tio.exports.assets(updated_at=self.checkpoint))
        # delete assets deleted and terminated since checkpoint
        self.delete_assets(self.tio.exports.assets(deleted_at=self.checkpoint))
        self.delete_assets(self.tio.exports.assets(terminated_at=self.checkpoint))
        # insert vulns found since checkpoint
        self.insert_objects('vulns', self.tio.exports.vulns(last_found=self.checkpoint))
        # delete vulns fixed since checkpoint
        self.delete_vulns(self.tio.exports.vulns(last_fixed=self.checkpoint))
        # remove and repopulate all scans
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM scans')
        self.insert_objects('scans', self.tio.scans.list())
        # remove and repopulate all policies
        cursor.execute('DELETE FROM policies')
        self.insert_objects('policies', self.tio.policies.list())


    @timeit
    def insert_objects(self, table, objects):
        query = "INSERT INTO {} (jdoc) VALUES (%s)"
        cursor = self.conn.cursor()
        count = 0
        for obj in objects:
            count += 1
            cursor.execute(sql.SQL(query).format(sql.Identifier(table)), (json.dumps(obj), ))
            if count % 100 == 0:
                logger.info("{} {} exported and indexed...".format(count, table))
        self.conn.commit()

    @timeit
    def update_assets(self, assets):
        s = "UPDATE assets SET jdoc = %s WHERE jdoc->>'id' = %s"
        cursor = self.conn.cursor()
        count = 0
        for obj in assets:
            count += 1
            print(obj)
            cursor.execute(s, (json.dumps(obj), obj['id']))
            if count % 100 == 0:
                logger.info(f"{count} assets updated in database...")
        self.conn.commit()

    @timeit
    def delete_vulns(self, vulns):
        query = "DELETE FROM vulns " \
                       "WHERE jdoc->'asset'->>'uuid' = %s AND " \
                       "jdoc->'scan'->>'uuid' = %s"
        cursor = self.conn.cursor()
        count = 0
        for v in vulns:
            count += 1
            cursor.execute(query, (v['asset']['uuid'], v['scan']['uuid']))
            if count % 100 == 0:
                logger.info("{} vulns deleted in database...".format(count))
        self.conn.commit()

    @timeit
    def delete_assets(self, assets):
        delete_query = "DELETE FROM assets " \
                       "WHERE jdoc->>'id' = %s"
        cursor = self.conn.cursor()
        count = 0
        for a in assets:
            count += 1
            cursor.execute(delete_query, (a['id']))
            if count % 100 == 0:
                logger.info("{} assets deleted in database...".format(count))
        self.conn.commit()


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

    properties = vars(parser.parse_args())

    if properties['access_key'] is None or properties['secret_key'] is None:
        # if no arguments passed, try load from settings file
        with pkg_resources.resource_stream(__name__, r'./settings.yml') as file:
            properties = yaml.full_load(file)
            logger.info(f'Loaded properties from settings.yml')

    search = TenableSearch(properties)
    scheduler = BlockingScheduler()
    scheduler.add_job(search.run_export_job, 'interval', seconds=10)
    scheduler.start()
    print('Press Ctrl+{0} to exit'.format('Break' if os.name == 'nt' else 'C'))
