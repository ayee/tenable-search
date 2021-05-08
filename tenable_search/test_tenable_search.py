import json
import time
from unittest import TestCase
import sys, os, logging
from datetime import datetime, timezone

print(sys.path)
print(os.listdir("/opt/project/tenable_search"))

import tenable_search

class TestTenableSearch(TestCase):
    _search = None

    def setUp(self):
        access_key = 'f4093b4d2601b8e9722999ed1fed28916e9f285fa116baa8118fee130ef62d67'
        secret_key = '9ed1f218605eceac2306768369a0cac0a951cd31ced8fc2f39dfb49c88c55d67'
        self._search = tenable_search.TenableSearch(access_key, secret_key)

    def test_count_assets(self):
        count = self._search.count_assets()
        self.assertGreaterEqual(count, 0, "No assets")

    def test_populate_assets(self):
        count1 = self._search.count_assets()
        self._search.populate_assets(10)
        count2 = self._search.count_assets()
        self.assertGreaterEqual(count2, count1, 'More assets populated')

    def test_populate_100k_assets(self):
        # cm = self.assertLogs(logging.getLogger('tenable_search'), level='INFO')
        n = 5000
        count1 = self._search.count_assets()
        self._search.populate_assets(n)
        count2 = self._search.count_assets()
        # self.assertEqual(cm.output, ['INFO:tenable_search:100000 randomly generated mock assets populated'])
        self.assertEqual(count2, count1+n, "Failed to populate {} assets".format(n))

    def test_delete_all_tables(self):
        self._search.delete_all_tables()
        self.assertEqual(self._search.count_assets(), 0, "Failed to delete all assets")
        self.assertEqual(self._search.count_vulns(), 0, "Failed to delete all vulns")
        # self.assertLessEqual(self._search.get_size(), 10000)

    def test_search_asset(self):
        # retrieve a random asset
        res1 = self._search.execute_read_query("SELECT * FROM assets OFFSET floor(random()*1000) LIMIT 1")
        ip = res1[0][1]['ipv4'][0]
        res2 = self._search.search_asset(ipv4 = [ip])
        self.assertEqual(res1, res2, "Failed to retrieve asset with ipv4")

    def test_delete_n_assets(self):
        # retrieve n random assets
        n = 1000
        table_size = self._search.execute_read_query("SELECT COUNT(*) FROM assets")
        res1 = self._search.execute_read_query("SELECT * FROM assets OFFSET floor(random()*{}) LIMIT {}".format(table_size[0][0], n))
        for a in res1:
            id = a[1]['id']
            res2 = self._search.search_asset(id = id)

    def test_search_asset_by_fqdn(self):
        res1 = self._search.execute_read_query(
            "SELECT * FROM assets WHERE jdoc -> 'fqdn' <> '[]'::jsonb OFFSET floor(random()*100000) LIMIT 1;"
        )
        fqdn = res1[0][1]['fqdn'][0]
        res2 = self._search.search_asset(fqdn = [fqdn])

        # test another one with 2 fqdns
        # res1 = self._search.execute_read_query(
        #     "SELECT * FROM assets WHERE jdoc -> 'fqdn' <> '[]'::jsonb OFFSET floor(random()*100000) LIMIT 1;"
        # )

    def test_export_vulns(self):
        for vuln in self._search.tio.exports.vulns(severity=['critical']):
            print(json.dumps(vuln))

    def test_export_terminated_assets(self):
        for asset in self._search.tio.exports.assets(is_terminated=True):
            print(json.dumps(asset))

    def test_export_deleted_assets(self):
        for asset in self._search.tio.exports.assets(is_deleted=True):
            print(json.dumps(asset))

    def test_export_assets_created_since(self):
        since = 6048000 # 10 weeks
        count = 0
        for asset in self._search.tio.exports.assets(created_at = int(time.time()) - since):
            print(asset)
            count += 1
        print("{} assets created during last {} seconds".format(count, since))

    def test_export_assets_updated_since(self):
        since = 6048000 # 10 weeks
        count = 0
        for asset in self._search.tio.exports.assets(updated_at = int(time.time()) - since):
            print(asset)
            count += 1
        print("{} assets updated during last {} seconds".format(count, since))

    def test_export_assets_created_and_updated(self):
        since = 6048000 # 10 weeks
        created = []
        updated = []
        for asset in self._search.tio.exports.assets(created_at = int(time.time()) - since):
            created += [asset['id']]
        print("{} assets created during last {}".format(len(created), str(datetime.timedelta(seconds=since))))
        for asset in self._search.tio.exports.assets(updated_at = int(time.time()) - since):
            updated += [asset['id']]
        print("{} assets updated during last {}".format(len(updated), str(datetime.timedelta(seconds=since))))
        print("{} assets created but not updated during last {}"
              .format(len(set(created) - set(updated))))
        print("{} assets updated but not created".format(len(set(updated) - set(created))))

    def test_export_assets_deleted_or_terminated(self):
        since = 6048000 # 10 weeks
        deleted = []
        terminated = []
        for asset in self._search.tio.exports.assets(deleted_at = int(time.time()) - since):
            deleted += [asset['id']]
        print("{} assets deleted during last {}".format(len(deleted), str(datetime.timedelta(seconds=since))))
        for asset in self._search.tio.exports.assets(terminated_at = int(time.time()) - since):
            terminated += [asset['id']]
        print("{} assets terminated during last {}".format(len(terminated), str(datetime.timedelta(seconds=since))))
        print("{} assets deleted but not terminated during last {}"
              .format(len(set(deleted) - set(terminated)), str(datetime.timedelta(seconds=since))))
        print("{} assets terminated but not deleted"
              .format(len(set(terminated) - set(deleted))))

    def test_run_export_job(self):
        self._search.checkpoint = 0
        self._search.run_export_job()

    def test_get_tenable_database_size(self):
        db_size = self._search.get_size()
        print("Tenable database size = {}".format(db_size))

    def test_insert_export_job(self):
        cursor = self._search.conn.cursor()
        cursor.execute("INSERT INTO export_jobs (job_start) VALUES (TIMESTAMP %s) RETURNING id", [datetime.now(timezone.utc)])
        id = cursor.fetchone()[0]
        time.sleep(5)
        cursor.execute('UPDATE export_jobs SET job_end = TIMESTAMP %s WHERE id = %s', [datetime.now(timezone.utc), id])
        self._search.conn.commit()

    def test_export_scan_list(self):
        for scan in self._search.tio.scans.list():
            print(scan)







