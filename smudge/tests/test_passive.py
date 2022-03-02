import unittest
import pathlib as pl
import sqlite3

from smudge import passive_data


class passive_data_testcase(unittest.TestCase):
    def test_setup_db_1(self):
        '''UT to ensure DB file gets created.'''
        passive_data.setup_db()
        path = pl.Path('signature.db')
        self.assertTrue(path.is_file())

    def test_setup_db_5(self):
        '''UT to ensure signatures table was created.'''
        con = sqlite3.connect('signature.db')
        cur = con.cursor()
        list_of_tables = cur.execute("""SELECT name FROM sqlite_master WHERE type='table'AND name='signatures'; """).fetchall()
        self.assertTrue(('signatures',) in list_of_tables)

    def test_test_github_con_1(self):
        '''UT to ensure Github connection test is successful.'''
        self.assertTrue(passive_data.test_github_con())