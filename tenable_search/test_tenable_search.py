from unittest import TestCase
import sys, os, logging

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

    def test_delete_all_assets(self):
        self._search.delete_all_assets()
        self.assertEqual(self._search.count_assets(), 0, "Failed to delete all assets")

    def test_search_asset(self):
        # retrieve a random asset
        res1 = self._search.execute_read_query("SELECT * FROM assets OFFSET floor(random()*100000) LIMIT 1")
        ip = res1[0][1]['ipv4'][0]
        res2 = self._search.search_asset(ipv4 = [ip])
        self.assertEqual(res1, res2, "Failed to retrieve asset with ipv4")

    def test_delete_n_assets_by_id(self):
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

    def test_get_tenable_database_size(self):
        db_size = self._search.get_size()
        print("Tenable database size = {}".format(db_size))




