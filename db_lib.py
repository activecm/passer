#!/usr/bin/env python3
"""Test library for sqlite storage."""
#All other functions call setup_db automatically if the dbfile doesn't exist, so you don't need to call that by hand.

__version__ = '0.2.2'

__author__ = 'David Quartarolo'
__copyright__ = 'Copyright 2022, David Quartarolo'
__credits__ = ['David Quartarolo', 'William Stearns']
__email__ = 'david@activecountermeasures.com'
__license__ = 'WTFPL'
__maintainer__ = 'David Quartarolo'
__status__ = 'Development'				#Prototype, Development or Production


import sqlite3
import os
import sys
import json
import hashlib
import string
from xmlrpc.client import Boolean
from typing import Any


sqlite_timeout = 20					#Default timeout, in seconds, can have fractions.  Without it, timeout is 5.
paranoid = True						#Run some additional checks

def sha256_sum(raw_object) -> str:
    """Creates a hex format sha256 hash/checksum of the given string/bytes object."""

    digest = ''

    if isinstance(raw_object, str):
        digest = hashlib.sha256(raw_object.encode('ascii')).hexdigest()
    elif isinstance(raw_object, bytes):
        digest = hashlib.sha256(raw_object).hexdigest()
    else:
        sys.stderr.write('Unrecognized object type to be sha256 hashed: ' + str(type(raw_object)))
        sys.stderr.flush()

    return digest


def is_sha256_sum(possible_hash_string: str) -> Boolean:
    """Check if the string is valid hex.  Not that it won't correctly handle strings starting with 0x."""

    return len(possible_hash_string) == 64 and all(c in string.hexdigits for c in possible_hash_string)


def setup_db(dbfile: str) -> Boolean:
    '''Create Sqlite3 DB with all required tables.'''
    if dbfile:						#If dbfile is None, don't try to create it.
        if not os.path.exists(dbfile):
            with open(dbfile, 'x', encoding='utf8'):
                pass
            conn = sqlite3.connect(dbfile, timeout=sqlite_timeout)
            # Create Signatures Table
            conn.execute('''CREATE TABLE "main" (
            "KEY_STR"    TEXT UNIQUE,
            "JSON_STR" TEXT,
            PRIMARY KEY("KEY_STR")
            );''')
            db_cur = conn.cursor()
            db_cur.execute('PRAGMA journal_mode=wal')	#https://pupli.net/2020/09/sqlite-wal-mode-in-python/
            conn.close()
    return True


def insert_key(dbfile: str, key_str: str, value_obj: Any) -> Boolean:
    '''Inserts key_str and its associates python object into database
    serializing the object on the way in.'''
    #This will add a new row if the key isn't there, and replace the existing value if it is.
    modified_rows = 0
    already_inserted = False
    if dbfile:						#If dbfile is None, don't do anything.
        if not os.path.exists(dbfile):
            setup_db(dbfile)
        value_str = json.dumps(value_obj)
        existing_value = select_key(dbfile, key_str)
        if existing_value and value_str in existing_value:
            already_inserted = True
            #sys.stderr.write(' ')
            #sys.stderr.flush()
        else:
            with sqlite3.connect(dbfile, timeout=sqlite_timeout) as conn:
                #It appears from https://www.sqlitetutorial.net/sqlite-replace-statement/ that the following will correctly insert (if not there) or replace (if there).
                modified_rows = conn.execute("REPLACE INTO main (KEY_STR, JSON_STR) values (?, ?)", (key_str, value_str)).rowcount
                conn.commit()
    return already_inserted or (modified_rows >= 1)


def insert_key_large_value(dbfile: str, large_dbfile: str, key_str: str, value_obj: Any) -> Boolean:
    '''Inserts key_str and its associates python object into database
    serializing the object on the way in.'''
    #This will add a new row if the key isn't there, and replace the existing value if it is.
    #This places the (key: sha256sum(value)) in dbfile, and (sha256sum(value): value) in large_dbfile

    if dbfile and large_dbfile:				#If dbfile or large_dbfile are None, don't do anything.
        value_sum = sha256_sum(value_obj)
        if paranoid:
            #Automatically compare the existing value_str in the database - if any - to this new value and warn if different.
            existing_value = select_key(large_dbfile, value_sum)
            if existing_value is None:
                existing_value = []
            if value_obj not in existing_value:
                sys.stderr.write('db_lib.py: existing large object in database does not match new object: sha256 hash collision.\n')
                sys.stderr.write(large_dbfile + '\n')
                sys.stderr.write(value_sum + '\n')
                sys.stderr.write(value_obj + '\n')
                sys.stderr.write(existing_value + '\n')
                sys.stderr.flush()
        success1 = insert_key(large_dbfile, value_sum, [value_obj])
        success2 = insert_key(dbfile, key_str, [value_sum])
    return success1 and success2


def delete_key(dbfile: str, key_str: str) -> Boolean:
    '''Delete row with key_str and associated object from database.'''
    modified_rows = 0
    if dbfile:						#If dbfile is None, don't do anything.
        if not os.path.exists(dbfile):
            setup_db(dbfile)
        with sqlite3.connect(dbfile, timeout=sqlite_timeout) as conn:
            modified_rows = conn.execute("DELETE FROM main WHERE KEY_STR=?", (key_str,)).rowcount
            conn.commit()
    return modified_rows >= 1


def select_key(dbfile: str, key_str: str):
    '''Searches for key_str from database. If the key_str is found,
    the obj is unserialized and returned as the original type of that value.'''
    value_obj = None
    if dbfile:						#If dbfile is None, don't do anything.
        if not os.path.exists(dbfile):
            setup_db(dbfile)
        with sqlite3.connect("file:" + dbfile + "?mode=ro", uri=True, timeout=sqlite_timeout) as conn:
            entry_cursor = conn.execute("SELECT JSON_STR FROM main WHERE KEY_STR=?", [key_str])
            entry = entry_cursor.fetchall()
            if len(entry) > 0:
                value_obj = json.loads(entry[0][0])

    return value_obj


def select_key_large_value(dbfile: str, large_dbfile: str, key_str: str):
    '''Searches for key_str from database. If the key_str is found,
    the obj is unserialized and returned as the original type of that value.'''
    #This automatically gets the sha256sum from dbfile and then uses that to get the original value from large_dbfile.

    large_result_list = []
    if dbfile and large_dbfile:				#If dbfile or large_dbfile are None, don't do anything.
        sum_list = select_key(dbfile, key_str)

        if sum_list:
            for one_sum in sum_list:
                one_large = select_key(large_dbfile, one_sum)
                if one_large is not None:
                    large_result_list.append(one_large[0])

    return large_result_list


def select_all(dbfile: str, return_values: Boolean = True) -> list:
    '''Returns all entries from database.  Optional parameter return_values decides whether key, value or just key comes back in the list.'''
    entries = []
    if dbfile:						#If dbfile is None, don't do anything.
        if not os.path.exists(dbfile):
            setup_db(dbfile)
        with sqlite3.connect("file:" + dbfile + "?mode=ro", uri=True, timeout=sqlite_timeout) as conn:
            if return_values:
                entry = conn.execute("SELECT KEY_STR, JSON_STR FROM main",)
            else:
                entry = conn.execute("SELECT KEY_STR FROM main",)
            entries = entry.fetchall()

    return entries


def should_add(dbfile: str, key_str: str, existing_list: list, new_value: str) -> Boolean:
    '''Make a decision about whether we should add a new value to an existing list.'''

    if "empty_list" not in should_add.__dict__:
        should_add.empty_list = [None for j in range(30)]

    decision = True
    #Don't add a country code (like "JP") to the ip_locations database if there's already an entry there that starts with that country code (like "JP;Japan/Tokyo/Tokyo")
    if dbfile.endswith( ('ip_locationss.sqlite3') ) and len(existing_list) > 0 and len(new_value) == 2:
        for one_exist in existing_list:
            if one_exist.startswith(new_value + ';'):
                decision = False

    #0.0.0.0 is a valid key_str for some record types ("DO,0.0.0.0,reputation,...", )
    if key_str in ('', '0000:0000:0000:0000:0000:0000:0000:0000'):
        decision = False
    elif key_str in ('127.0.0.1', '0000:0000:0000:0000:0000:0000:0000:0001') and new_value != 'localhost':
        decision = False
    elif new_value in ('', '0.0.0.0', '0000:0000:0000:0000:0000:0000:0000:0000'):
        decision = False
    elif new_value == should_add.empty_list:
        decision = False

    #Add valid character checks

    return decision


def add_to_db_list(dbfile: str, key_str: str, new_value: str):
    """Inside the given database, add the new_value to the list for key_str and write it back if changed."""
    #Assumes the Value part of the database record is a list
    #Because we're doing a read-modify-update on dbfile[key_str], we have to put an exclusive transaction around the read-modify-write
    #so we don't get two writers writing to the same record (which is very likely to happen!).
    #This also means we have to pull in the two SQL commands (SELECT and REPLACE) under a single sqlite3.connect so we can have a transaction around both.

    already_inserted = False
    existing_list = None
    modified_rows = 0

    if dbfile:						#If dbfile is None, don't do anything.
        if not os.path.exists(dbfile):
            setup_db(dbfile)

        current_val_list = select_key(dbfile, key_str)	#Perform an early (read-only) check to see if the value is already in; if so, skip.  THIS ASSUMES that removals are unlikely.
        if current_val_list and new_value in current_val_list:
            already_inserted = True
        else:
            with sqlite3.connect(dbfile, timeout=sqlite_timeout) as conn:

                conn.execute("BEGIN EXCLUSIVE TRANSACTION")
                entry_cursor = conn.execute("SELECT JSON_STR FROM main WHERE KEY_STR=?", [key_str])
                entry = entry_cursor.fetchall()
                if len(entry) > 0:
                    existing_list = json.loads(entry[0][0])

                if existing_list is None:
                    existing_list = []
                if new_value not in existing_list and should_add(dbfile, key_str, existing_list, new_value):
                    existing_list.append(new_value)
                    modified_rows = conn.execute("REPLACE INTO main (KEY_STR, JSON_STR) values (?, ?)", (key_str, json.dumps(existing_list))).rowcount
                else:
                    already_inserted = True
                    #sys.stderr.write(' ')
                    #sys.stderr.flush()
                conn.commit()

    return already_inserted or (modified_rows >= 1)


def add_to_db_list_large_value(dbfile: str, large_dbfile: str, key_str: str, new_value: str):
    """Inside the given database, add the new_value to the list for key_str and write it back if changed."""
    #Assumes you've already initialized the dbfile.
    #Also assumes the Value part of the database record is a list

    if dbfile and large_dbfile:
        value_sum = sha256_sum(new_value)
        success2 = insert_key(large_dbfile, value_sum, [new_value])
        success1 = add_to_db_list(dbfile, key_str, value_sum)
        valsequal = False
        retrieved_object = select_key_large_value(dbfile, large_dbfile, key_str)
        for one_retrieved in retrieved_object:
            if new_value == one_retrieved:
                valsequal = True
        if valsequal is False:
            sys.stderr.write("Mismatch in add_to_db_list_large_value\n")
            sys.stderr.write(str(key_str) + "\n")
            sys.stderr.write(str(new_value) + "\n")
            sys.stderr.write(str(value_sum) + "\n")
            sys.stderr.write(str(retrieved_object) + "\n")
            sys.stderr.flush()
            sys.exit(1)

    return valsequal and success1 and success2


def db_lib_main():
    "Just an example of possible use."
    test_db = 'database.db'
    setup_db(test_db)
    insert_key(test_db, '10.0.0.1', ['a.net', 'b.net', 'activecountermeasures.net'])
    insert_key(test_db, '10.0.0.0', [])
    insert_key(test_db, '10.0.0.0', ['replaced_hostname.example.net'])
    insert_key(test_db, '10.0.0.255', ['about_to_be_deleted.example.net'])
    delete_key(test_db, '10.0.0.255')
    print('==== 10.0.0.1')
    ip = select_key(test_db, '10.0.0.1')
    if ip:
        print(ip)

    print('==== Raw dump')
    print(select_all(test_db))		#This works (returns a list of tuples)

    print('==== One line per record')
    for one_row in select_all(test_db):
        print(one_row)


if __name__ == '__main__':
    db_lib_main()
