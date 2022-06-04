#!/usr/bin/env python3
"""Test library for sqlite storage."""
#All other functions call setup_db automatically if the dbfile doesn't exist, so you don't need to call that by hand.
#Most functions have "dbfiles" as the first parameter.  This can be a string with the database filename or a
#list of string filenames, in which case dbfiles[0] is the only one that can be written and created - the rest are
#read-only and will not be created if not already there.

__version__ = '0.3.1'

__author__ = 'David Quartarolo'
__copyright__ = 'Copyright 2022, David Quartarolo'
__credits__ = ['David Quartarolo', 'William Stearns']
__email__ = 'david@activecountermeasures.com'
__license__ = 'WTFPL'					#http://www.wtfpl.net/
__maintainer__ = 'William Stearns'
__status__ = 'Development'				#Prototype, Development or Production


import hashlib
import json
import os
import sqlite3
import string
import sys
import time
from typing import Any, Union
from xmlrpc.client import Boolean

sqlite_timeout = 20					#Default timeout, in seconds, can have fractions.  Without it, timeout is 5.
paranoid = True						#Run some additional checks
verbose_status = True					#Show some additional status output on stderr
#Note: maximum time between forced flushes is set to 600 in both buffer_merges and buffer_delete_vals

def sha256_sum(raw_object) -> str:
    """Creates a hex format sha256 hash/checksum of the given string/bytes object."""

    digest: str = ''

    if isinstance(raw_object, str):
        digest = hashlib.sha256(raw_object.encode('ascii', errors='ignore')).hexdigest()
    elif isinstance(raw_object, bytes):
        digest = hashlib.sha256(raw_object).hexdigest()
    else:
        sys.stderr.write('Unrecognized object type to be sha256 hashed: ' + str(type(raw_object)))
        sys.stderr.flush()

    return digest


def is_sha256_sum(possible_hash_string: str) -> Boolean:
    """Check if the string is valid hex.  Not that it won't correctly handle strings starting with 0x."""

    return len(possible_hash_string) == 64 and all(c in string.hexdigits for c in possible_hash_string)


def setup_db(dbfiles: Union[str, list]) -> Boolean:
    '''Create Sqlite3 DB with all required tables.'''
    #If dbfiles is a list, we will only create and set up dbfiles[0], the sole writeable database file.

    success: Boolean = True

    if not dbfiles:
        dbfile: str = ''
    elif isinstance(dbfiles, (list, tuple)):
        dbfile = dbfiles[0]
    else:
        dbfile = dbfiles

    if dbfile:						#If dbfile is None, don't try to create it.
        if not os.path.exists(dbfile):
            try:
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
            except:
                success = False
    return success


def insert_key(dbfiles: Union[str, list], key_str: str, value_obj: Any) -> Boolean:
    '''Inserts key_str and its associates python object into database
    serializing the object on the way in.'''
    #This will add a new row if the key isn't there, and replace the existing value if it is.

    if not dbfiles:
        dbfile: str = ''
    elif isinstance(dbfiles, (list, tuple)):
        dbfile = dbfiles[0]
    else:
        dbfile = dbfiles

    modified_rows = 0
    already_inserted = False
    if dbfile:						#If dbfile is None, don't do anything.
        if not os.path.exists(dbfile):
            setup_db(dbfile)
        value_str = json.dumps(value_obj)
        existing_value = select_key(dbfile, key_str)	#Note: no locking required around this select...replace block as we're totally replacing the existing value below.
        if existing_value and value_str in existing_value:
            already_inserted = True
            #if verbose_status:
            #    sys.stderr.write(' ')
            #    sys.stderr.flush()
        else:
            with sqlite3.connect(dbfile, timeout=sqlite_timeout) as conn:
                #It appears from https://www.sqlitetutorial.net/sqlite-replace-statement/ that the following will correctly insert (if not there) or replace (if there).
                modified_rows = conn.execute("REPLACE INTO main (KEY_STR, JSON_STR) values (?, ?)", (key_str, value_str)).rowcount
                conn.commit()
    return already_inserted or (modified_rows >= 1)


def insert_key_large_value(dbfiles: Union[str, list], large_dbfiles: Union[str, list], key_str: str, value_obj: Any) -> Boolean:
    '''Inserts key_str and its associates python object into database
    serializing the object on the way in.'''
    #This will add a new row if the key isn't there, and replace the existing value if it is.
    #This places the (key: sha256sum(value)) in dbfile, and (sha256sum(value): value) in large_dbfile

    if not dbfiles:
        dbfile: str = ''
    elif isinstance(dbfiles, (list, tuple)):
        dbfile = dbfiles[0]
    else:
        dbfile = dbfiles
    if not large_dbfiles:
        large_dbfile: str = ''
    elif isinstance(large_dbfiles, (list, tuple)):
        large_dbfile = large_dbfiles[0]
    else:
        large_dbfile = large_dbfiles

    if dbfile and large_dbfile:				#If dbfile or large_dbfile are None, don't do anything.
        value_sum = sha256_sum(value_obj)
        if paranoid:
            #Automatically compare the existing value_str in the database - if any - to this new value and warn if different.
            existing_value = select_key(large_dbfile, value_sum)
            if existing_value is None or existing_value == []:
                existing_value = []
            elif value_obj not in existing_value:
                sys.stderr.write('db_lib.py: existing large object in database does not match new object: sha256 hash collision.\n')
                sys.stderr.write(large_dbfile + '\n')
                sys.stderr.write(value_sum + '\n')
                sys.stderr.write(value_obj + '\n')
                sys.stderr.write(str(existing_value) + '\n')
                sys.stderr.flush()
        success1 = insert_key(large_dbfile, value_sum, [value_obj])	#We don't pass down the _lists_ of dbfiles/large_dbfiles as we can only write to the first.
        success2 = insert_key(dbfile, key_str, [value_sum])
    return success1 and success2


def delete_key(dbfiles: Union[str, list], key_str: str) -> Boolean:
    '''Delete row with key_str and associated object from database.'''

    if not dbfiles:
        dbfile: str = ''
    elif isinstance(dbfiles, (list, tuple)):
        dbfile = dbfiles[0]
    else:
        dbfile = dbfiles

    modified_rows = 0
    if dbfile:						#If dbfile is None, don't do anything.
        if not os.path.exists(dbfile):
            setup_db(dbfile)
        with sqlite3.connect(dbfile, timeout=sqlite_timeout) as conn:
            modified_rows = conn.execute("DELETE FROM main WHERE KEY_STR=?", (key_str,)).rowcount
            conn.commit()
    return modified_rows >= 1


def select_key(dbfiles: Union[str, list], key_str: str):
    '''Searches for key_str from database. If the key_str is found,
    the obj is unserialized and returned as the original type of that value.'''
    #Note: this returns all values from all databases (both the sole read-write database
    #at position 0 and the remaining read-only databases.)

    value_obj: list = []

    if not dbfiles:
        dbfile_list: list = []
    elif isinstance(dbfiles, (list, tuple)):
        dbfile_list = dbfiles
    else:
        dbfile_list = [dbfiles]

    if dbfile_list and dbfile_list[0]:
        if not os.path.exists(dbfile_list[0]):
            setup_db(dbfile_list[0])

    for dbfile in dbfile_list:
        if dbfile:						#If dbfile is None, don't do anything.
            with sqlite3.connect("file:" + dbfile + "?mode=ro", uri=True, timeout=sqlite_timeout) as conn:
                entry_cursor = conn.execute("SELECT JSON_STR FROM main WHERE KEY_STR=?", [key_str])
                entry = entry_cursor.fetchall()
                if len(entry) > 0:
                    new_objects = json.loads(entry[0][0])
                    #First [0] is the first row returned (which should be the only row returned as keys are unique.)
                    #Second [0] is the first column (JSON_STR, which is also the only column requested.)
                    #The reply will generally be a list, though possibly empty or None.
                    if new_objects:
                        if isinstance(new_objects, (list, tuple)):
                            for new_obj in new_objects:
                                if new_obj not in value_obj:
                                    value_obj.append(new_obj)
                        else:
                            value_obj.append(new_objects)

    return value_obj


def select_key_large_value(dbfiles: Union[str, list], large_dbfiles: Union[str, list], key_str: str):
    '''Searches for key_str from database. If the key_str is found,
    the obj is unserialized and returned as the original type of that value.'''
    #This automatically gets the sha256sum from dbfile and then uses that to get the original value from large_dbfile.

    large_result_list = []
    if dbfiles and large_dbfiles:			#If dbfile or large_dbfile are None, don't do anything.
        sum_list = select_key(dbfiles, key_str)

        if sum_list:
            for one_sum in sum_list:
                one_large = select_key(large_dbfiles, one_sum)
                if one_large is not None:
                    large_result_list.append(one_large[0])

    return large_result_list


def select_all(dbfiles: Union[str, list], return_values: Boolean = True) -> list:
    '''Returns all entries from database.  Optional parameter return_values decides whether key, value or just key comes back in the list.'''
    #We store in all_entries if return_values is True, we store in all_keys if return_values is False.
    all_entries: dict = {}			#Dictionary that holds key, value(list) pairs.  Converted to a list of tuples on the way out.
    all_keys: list = []				#List that stores just keys.

    if not dbfiles:
        dbfile_list: list = []
    elif isinstance(dbfiles, (list, tuple)):
        dbfile_list = dbfiles
    else:
        dbfile_list = [dbfiles]

    if dbfile_list and dbfile_list[0]:
        if not os.path.exists(dbfile_list[0]):
            setup_db(dbfile_list[0])

    for dbfile in dbfile_list:
        if dbfile:						#If dbfile is None, don't do anything.
            with sqlite3.connect("file:" + dbfile + "?mode=ro", uri=True, timeout=sqlite_timeout) as conn:
                if return_values:
                    entry = conn.execute("SELECT KEY_STR, JSON_STR FROM main",)
                    thisdb_entries = entry.fetchall()
                    #thisdb_entries is a list of tuples, each of which is a (key, value_list).

                    for one_entry in thisdb_entries:
                        #one_entry is a 2 item tuple, first is the key, second is a list of all associates values
                        if one_entry[0] in all_entries:
                            #merge all values (one_entry[1]) into all_entries[one_entry[0]]
                            for one_val in one_entry[1]:
                                if one_val not in all_entries[one_entry[0]]:
                                    all_entries[one_entry[0]].append(one_val)
                        else:
                            all_entries[one_entry[0]] = one_entry[1]
                else:
                    entry = conn.execute("SELECT KEY_STR FROM main",)
                    thisdb_entries = entry.fetchall()
                    #thisdb_entries is a list of tuples, each of which is a (key, ).

                    for one_entry in thisdb_entries:
                        #one_entry is a 1 item tuple, the only item is the key
                        if one_entry[0] not in all_keys:
                            all_keys.append(one_entry[0])

    if return_values:
        return list(all_entries.items())	#Convert to a list of tuples on the way out
    else:
        return all_keys				#Return a list of just keys



def should_add(dbfiles: Union[str, list], key_str: str, existing_list: list, new_value: str) -> Boolean:
    '''Make a decision about whether we should add a new value to an existing list.'''

    if "empty_list" not in should_add.__dict__:
        should_add.empty_list = [None for j in range(30)]

    if not dbfiles:
        dbfile_list: list = []
    elif isinstance(dbfiles, (list, tuple)):
        dbfile_list = dbfiles
    else:
        dbfile_list = [dbfiles]

    decision = True
    #Don't add a country code (like "JP") to the ip_locations database if there's already an entry there that starts with that country code (like "JP;Japan/Tokyo/Tokyo")
    #todo: look for ip_locations and sqlite3 in the filename somewhere, not necessarily at the end
    #Note: this handles the case where the longer geoip string is already there
    #and we're considering adding the 2 character country code, but not the case where the 2 character
    #country code is already there and we're adding the longer string.
    for dbfile in dbfile_list:
        if dbfile.endswith( ('ip_locations.sqlite3') ) and len(existing_list) > 0 and len(new_value) == 2:
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


def add_to_db_list(dbfiles: Union[str, list], key_str: str, new_value: str) -> Boolean:
    """Inside the given database, add the new_value to the list for key_str and write it back if changed."""
    #Assumes the Value part of the database record is a list
    #Because we're doing a read-modify-update on dbfile[key_str], we have to put an exclusive transaction around the read-modify-write
    #so we don't get two writers writing to the same record (which is very likely to happen!).
    #This also means we have to pull in the two SQL commands (SELECT and REPLACE) under a single sqlite3.connect so we can have a transaction around both.

    already_inserted = False
    existing_list = None
    modified_rows = 0

    if not dbfiles:
        dbfile: str = ''
    elif isinstance(dbfiles, (list, tuple)):
        dbfile = dbfiles[0]
    else:
        dbfile = dbfiles

    if dbfile:						#If dbfile is None, don't do anything.
        if not os.path.exists(dbfile):
            setup_db(dbfile)

        #todo: remove this
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
                    #if verbose_status:
                    #    sys.stderr.write(' ')
                    #    sys.stderr.flush()
                conn.commit()

    return already_inserted or (modified_rows >= 1)


#Deprecated - use add_to_db_dict instead
def add_to_db_multiple_lists(dbfiles: Union[str, list], key_value_list: list) -> Boolean:		# pylint: disable=too-many-branches
    """Inside the given database, process multiple key/value lists/tuples.  For each value, add it to the existing list if not already there."""
    #key_value_list is in this form:
    #[
    #    [key1, [value1, value2, value3...]],
    #    [key2, [value4]],
    #    [key3, [value5, value6]]
    #]
    #This code will also accept
    #    (key2, value4),
    #instead of
    #    (key2, [value4]),
    #
    #This approach allows us to commit a large number of writes without requiring a full database rewrite for every key-value pair (which appears to be the case for sqlite3.
    #The total number of tuples handed in this way should be limited; while some number greater than 1 will reduce total writes,
    #the more lines there are the longer the database is held with an exclusive lock, perhaps leading to locking out other users.
    #Perhaps some number between 10 and 1000, then sleeping a small fraction of a second and doing it again.

    any_changes_made: Boolean = False
    modified_rows: int = 0

    existing_cache: dict = {}				#This holds key-value pairs which 1) are pulled out of the database, 2) have new values appended, and 3) are written back just before we release the lock.

    if not dbfiles:
        dbfile: str = ''
    elif isinstance(dbfiles, (list, tuple)):
        dbfile = dbfiles[0]
    else:
        dbfile = dbfiles

    if dbfile:						#If dbfile is None, don't do anything.
        if not os.path.exists(dbfile):
            setup_db(dbfile)

        with sqlite3.connect(dbfile, timeout=sqlite_timeout) as conn:
            #We need to protect with an exclusive transaction...commit pair so that no changes can happen to the existing_lists while we pull in all these changes.
            conn.execute("BEGIN EXCLUSIVE TRANSACTION")

            #Process each key/value pair in key_value_list.
            for addition_tuple in key_value_list:
                addition_key = addition_tuple[0]
                #If this key is in the database, we pull its existing values back (or assign an empty list if not)
                if addition_key not in existing_cache:
                    existing_cache[addition_key] = []
                    entry_cursor = conn.execute("SELECT JSON_STR FROM main WHERE KEY_STR=?", [addition_key])
                    entry = entry_cursor.fetchall()
                    if len(entry) > 0:
                        existing_cache[addition_key] = json.loads(entry[0][0])

                #Now that we have the existing entries for that key, we add new entries provided by key_value_list.
                if isinstance(addition_tuple[1], (list, tuple)):
                    for new_value in addition_tuple[1]:	#addition_tuple[1] is the list/tuple of new values to add.
                        if new_value not in existing_cache[addition_key] and should_add(dbfile, addition_key, existing_cache[addition_key], new_value):
                            existing_cache[addition_key].append(new_value)
                            any_changes_made = True
                else:						#Since it's not a list or tuple, we assume it's a single value to process
                    new_value = addition_tuple[1]		#addition_tuple[1] is the sole new value to add.
                    if new_value not in existing_cache[addition_key] and should_add(dbfile, addition_key, existing_cache[addition_key], new_value):
                        existing_cache[addition_key].append(new_value)
                        any_changes_made = True

            #Only write back existing blocks at the last moment.  (Future: only write the changed ones.)
            if any_changes_made:
                for one_key in existing_cache:			# pylint: disable=consider-using-dict-items
                    #Ideally we'd use conn.executemany and feed it existing_cache.items() , but we need the existing_lists converted by json.dumps, so I don't think we can.
                    modified_rows += conn.execute("REPLACE INTO main (KEY_STR, JSON_STR) values (?, ?)", (one_key, json.dumps(existing_cache[one_key]))).rowcount
                    if verbose_status:
                        sys.stderr.write('.')
            else:
                if verbose_status:
                    sys.stderr.write(' ')

            conn.commit()
            if verbose_status:
                #sys.stderr.write(' Done.\n')
                sys.stderr.flush()

    return (not any_changes_made) or (modified_rows >= 1)




def add_to_db_dict(dbfiles: Union[str, list], key_value_dict: dict) -> Boolean:		# pylint: disable=too-many-branches
    """Inside the given database, process multiple key/value lists/tuples.  For each value, add it to the existing list if not already there."""
    #key_value_list is in this form:
    #{
    #    key1: [value1, value2, value3...],
    #    key2: [value4],
    #    key3: [value5, value6]
    #}
    #
    #This approach allows us to commit a large number of writes without requiring a full database rewrite for every key-value pair (which appears to be the case for sqlite3.
    #The total number of tuples handed in this way should be limited; while some number greater than 1 will reduce total writes,
    #the more lines there are the longer the database is held with an exclusive lock, perhaps leading to locking out other users.
    #Perhaps some number between 10 and 1000, then sleeping a small fraction of a second and doing it again.

    any_changes_made: Boolean = False
    modified_rows: int = 0

    existing_cache: dict = {}				#This holds key-value pairs which 1) are pulled out of the database, 2) have new values appended, and 3) are written back just before we release the lock.

    if not dbfiles:
        dbfile: str = ''
    elif isinstance(dbfiles, (list, tuple)):
        dbfile = dbfiles[0]
    else:
        dbfile = dbfiles

    if dbfile:						#If dbfile is None, don't do anything.
        if not os.path.exists(dbfile):
            setup_db(dbfile)

        with sqlite3.connect(dbfile, timeout=sqlite_timeout) as conn:
            #We need to protect with an exclusive transaction...commit pair so that no changes can happen to the existing_lists while we pull in all these changes.
            conn.execute("BEGIN EXCLUSIVE TRANSACTION")

            #Process each key/value pair in key_value_dict.
            for addition_key in key_value_dict:
                #If this key is in the database, we pull its existing values back (or assign an empty list if not)
                if addition_key not in existing_cache:
                    existing_cache[addition_key] = []
                    entry_cursor = conn.execute("SELECT JSON_STR FROM main WHERE KEY_STR=?", [addition_key])
                    entry = entry_cursor.fetchall()
                    if len(entry) > 0:
                        existing_cache[addition_key] = json.loads(entry[0][0])

                #Now that we have the existing entries for that key, we add new entries provided by key_value_list.
                if isinstance(key_value_dict[addition_key], list):
                    for new_value in key_value_dict[addition_key]:	#key_value_dict[addition_key] is the list of new values to add.
                        if new_value not in existing_cache[addition_key] and should_add(dbfile, addition_key, existing_cache[addition_key], new_value):
                            existing_cache[addition_key].append(new_value)
                            any_changes_made = True
                else:							#Since it's not a list, we assume it's a single value to process
                    new_value = key_value_dict[addition_key]		#key_value_dict[addition_key] is the sole new value to add.
                    if new_value not in existing_cache[addition_key] and should_add(dbfile, addition_key, existing_cache[addition_key], new_value):
                        existing_cache[addition_key].append(new_value)
                        any_changes_made = True

            #Only write back existing blocks at the last moment.  (Future: only write the changed ones.)
            if any_changes_made:
                for one_key in existing_cache:			# pylint: disable=consider-using-dict-items
                    #Ideally we'd use conn.executemany and feed it existing_cache.items() , but we need the existing_lists converted by json.dumps, so I don't think we can.
                    modified_rows += conn.execute("REPLACE INTO main (KEY_STR, JSON_STR) values (?, ?)", (one_key, json.dumps(existing_cache[one_key]))).rowcount
                    if verbose_status:
                        sys.stderr.write('.')
            else:
                if verbose_status:
                    sys.stderr.write(' ')

            conn.commit()
            if verbose_status:
                #sys.stderr.write(' Done.\n')
                sys.stderr.flush()

    return (not any_changes_made) or (modified_rows >= 1)


def buffer_merges(dbfiles: Union[str, list], key_str: str, new_values: list, max_adds: int) -> Boolean:
    """Buffer up writes that will eventually get merged into their respective databases.
    You _must_ call this with buffer_merges('', '', [], 0) to flush any remaining writes before shutting down."""

    if 'last_flush' not in buffer_merges.__dict__:
        buffer_merges.last_flush = time.time()		#We set "last_flush" to now when we first enter this function.  Used to make sure nothing stays around forever.

    if 'additions' not in buffer_merges.__dict__:
        buffer_merges.additions = {}			#Key is the database file, value is a list of queued writes for that database::
        #{"dbfile1":
        #  [
        #    [key1, [value1, value2, value3...]],
        #    [key2, [value4]],
        #    [key3, [value5, value6]]
        #  ]
        #}

    success = True

    if not dbfiles:
        dbfile: str = ''
    elif isinstance(dbfiles, (list, tuple)):
        dbfile = dbfiles[0]
    else:
        dbfile = dbfiles

    if dbfile and new_values:				#We don't check for an empty key_str as it's technically legal to have "" as a key.
        if not os.path.exists(dbfile):
            setup_db(dbfile)
        if isinstance(new_values, (list, tuple)):
            new_values_list = new_values
        else:
            new_values_list = [new_values]
        #First, add any new values to the "additions" structure.
        if dbfile not in buffer_merges.additions:
            buffer_merges.additions[dbfile] = [ [key_str, new_values_list] ]
        else:
            found_key = None
            for x in range(len(buffer_merges.additions[dbfile])):
                if buffer_merges.additions[dbfile][x][0] == key_str:
                    found_key = x
                    break
            if found_key is None:
                #Add a new line with the new values
                #found_key = len(buffer_merges.additions[dbfile])	#This is technically where the new entry will be appended to, but we don't need found_key to append to the list.
                buffer_merges.additions[dbfile].append([key_str, new_values_list])
            else:
                #Merge new values into buffer_merges.additions[dbfile][found_key]
                for one_val in new_values_list:
                    if one_val not in buffer_merges.additions[dbfile][found_key][1]:
                        buffer_merges.additions[dbfile][found_key][1].append(one_val)

    if time.time() - buffer_merges.last_flush > 600:	#Note; this forces a flush the _first time we're called_ more than 10 minutes since the last.  This does not force writes until we get called!
        force_flush = True
        buffer_merges.last_flush = time.time()
    else:
        force_flush = False

    for one_db in buffer_merges.additions:		# pylint: disable=consider-using-dict-items
        if force_flush or len(buffer_merges.additions[one_db]) >= max_adds:		#Push out if too many items in queue for this database or it's been over 10 minutes since the last full flush
            success = success and add_to_db_multiple_lists(one_db, buffer_merges.additions[one_db])
            buffer_merges.additions[one_db] = []

    return success


def remove_from_db_multiple_lists(dbfiles: Union[str, list], key_value_list: list) -> Boolean:		# pylint: disable=too-many-branches
    """Inside the given database, process multiple key/value lists/tuples.  For each value, remove it from the existing list if there."""
    #key_value_list is in this form:
    #[
    #    [key1, [value1, value2, value3...]],
    #    [key2, [value4]],
    #    [key3, [value5, value6]]
    #]
    #This code will also accept
    #    (key2, value4),
    #instead of
    #    (key2, [value4]),
    #
    #This approach allows us to commit a large number of writes without requiring a full database rewrite for every key-value pair (which appears to be the case for sqlite3.
    #The total number of tuples handed in this way should be limited; while some number greater than 1 will reduce total writes,
    #the more lines there are the longer the database is held with an exclusive lock, perhaps leading to locking out other users.
    #Perhaps some number between 10 and 1000, then sleeping a small fraction of a second and doing it again.

    any_changes_made = False
    modified_rows = 0

    existing_cache: dict = {}				#This holds key-value pairs which 1) are pulled out of the database, 2) may have values removed, and 3) are written back just before we release the lock.

    if not dbfiles:
        dbfile: str = ''
    elif isinstance(dbfiles, (list, tuple)):
        dbfile = dbfiles[0]
    else:
        dbfile = dbfiles

    if dbfile:						#If dbfile is None, don't do anything.
        if not os.path.exists(dbfile):
            setup_db(dbfile)

        with sqlite3.connect(dbfile, timeout=sqlite_timeout) as conn:
            #We need to protect with an exclusive transaction...commit pair so that no changes can happen to the existing_lists while we pull in all these changes.
            conn.execute("BEGIN EXCLUSIVE TRANSACTION")

            #Process each key/value pair in key_value_list.
            for removal_tuple in key_value_list:
                removal_key = removal_tuple[0]
                #If this key is in the database, we pull its existing values back (or assign an empty list if not)
                if removal_key not in existing_cache:
                    existing_cache[removal_key] = []
                    entry_cursor = conn.execute("SELECT JSON_STR FROM main WHERE KEY_STR=?", [removal_key])
                    entry = entry_cursor.fetchall()
                    if len(entry) > 0:
                        existing_cache[removal_key] = json.loads(entry[0][0])

                #Now that we have the existing entries for that key, we remove all entries provided by key_value_list.
                if isinstance(removal_tuple[1], (list, tuple)):
                    for del_value in removal_tuple[1]:	#removal_tuple[1] is the list/tuple of new values to remove.
                        while del_value in existing_cache[removal_key]:
                            existing_cache[removal_key].remove(del_value)
                            any_changes_made = True
                else:						#Since it's not a list or tuple, we assume it's a single value to process
                    del_value = removal_tuple[1]		#removal_tuple[1] is the sole new value to remove.
                    while del_value in existing_cache[removal_key]:
                        existing_cache[removal_key].remove(del_value)
                        any_changes_made = True

            #Only write back existing blocks at the last moment.  (Future: only write the changed ones.)
            if any_changes_made:
                for one_key in existing_cache:		# pylint: disable=consider-using-dict-items
                    #Ideally we'd use conn.executemany and feed it existing_cache.items() , but we need the existing_lists converted by jsson.dumps, so I don't think we can.
                    if existing_cache[one_key] == []:
                        modified_rows += conn.execute("DELETE FROM main WHERE KEY_STR=?", (one_key,)).rowcount
                        if verbose_status:
                            sys.stderr.write('d')
                    else:
                        modified_rows += conn.execute("REPLACE INTO main (KEY_STR, JSON_STR) values (?, ?)", (one_key, json.dumps(existing_cache[one_key]))).rowcount
                        if verbose_status:
                            sys.stderr.write('.')
            else:
                if verbose_status:
                    sys.stderr.write(' ')

            conn.commit()
            if verbose_status:
                #sys.stderr.write(' Done.\n')
                sys.stderr.flush()

    return (not any_changes_made) or (modified_rows >= 1)


def buffer_delete_vals(dbfiles: Union[str, list], key_str: str, delete_values: list, max_dels: int) -> Boolean:
    """Buffer up values that will eventually get removed from their respective databases.
    You _must_ call this with buffer_delete_vals('', '', [], 0) to flush any remaining writes before shutting down."""

    if 'last_flush' not in buffer_delete_vals.__dict__:
        buffer_delete_vals.last_flush = time.time()		#We set "last_flush" to now when we first enter this function.  Used to make sure nothing stays around forever.

    if 'removals' not in buffer_delete_vals.__dict__:
        buffer_delete_vals.removals = {}			#Key is the database file, value is a list of queued writes for that database::
        #{"dbfile1":
        #  [
        #    [key1, [value1, value2, value3...]],
        #    [key2, [value4]],
        #    [key3, [value5, value6]]
        #  ]
        #}

    success = True

    if not dbfiles:
        dbfile: str = ''
    elif isinstance(dbfiles, (list, tuple)):
        dbfile = dbfiles[0]
    else:
        dbfile = dbfiles

    if dbfile and delete_values:				#We don't check for an empty key_str as it's technically legal to have "" as a key.
        if not os.path.exists(dbfile):
            setup_db(dbfile)
        if isinstance(delete_values, (list, tuple)):
            delete_values_list = delete_values
        else:
            delete_values_list = [delete_values]
        #First, add any deletion values to the "removals" structure.
        if dbfile not in buffer_delete_vals.removals:
            buffer_delete_vals.removals[dbfile] = [ [key_str, delete_values_list] ]
        else:
            found_key = None
            for x in range(len(buffer_delete_vals.removals[dbfile])):
                if buffer_delete_vals.removals[dbfile][x][0] == key_str:
                    found_key = x
                    break
            if found_key is None:
                #Add a new line with the new values
                #found_key = len(buffer_delete_vals.removals[dbfile])	#This is technically where the new entry will be appended to, but we don't need found_key to append to the list.
                buffer_delete_vals.removals[dbfile].append([key_str, delete_values_list])
            else:
                #Merge new values into buffer_delete_vals.removals[dbfile][found_key]
                for one_val in delete_values_list:
                    if one_val not in buffer_delete_vals.removals[dbfile][found_key][1]:
                        buffer_delete_vals.removals[dbfile][found_key][1].append(one_val)

    if time.time() - buffer_delete_vals.last_flush > 600:	#Note; this forces a flush the _first time we're called_ more than 10 minutes since the last.  This does not force writes until we get called!
        force_flush = True
        buffer_delete_vals.last_flush = time.time()
    else:
        force_flush = False

    for one_db in buffer_delete_vals.removals:			# pylint: disable=consider-using-dict-items
        if force_flush or len(buffer_delete_vals.removals[one_db]) >= max_dels:
            success = success and remove_from_db_multiple_lists(one_db, buffer_delete_vals.removals[one_db])
            buffer_delete_vals.removals[one_db] = []

    return success


def add_to_db_list_large_value(dbfiles: Union[str, list], large_dbfiles: Union[str, list], key_str: str, new_value: str, max_adds: int) -> Boolean:
    """Inside the given database, add the new_value to the list for key_str and write it back if changed."""
    #Assumes you've already initialized the dbfile.
    #Also assumes the Value part of the database record is a list

    if not dbfiles:
        dbfile: str = ''
    elif isinstance(dbfiles, (list, tuple)):
        dbfile = dbfiles[0]
    else:
        dbfile = dbfiles
    if not large_dbfiles:
        large_dbfile: str = ''
    elif isinstance(large_dbfiles, (list, tuple)):
        large_dbfile = large_dbfiles[0]
    else:
        large_dbfile = large_dbfiles

    if dbfile and large_dbfile:
        if not os.path.exists(dbfile):
            setup_db(dbfile)
        if not os.path.exists(large_dbfile):
            setup_db(large_dbfile)
        value_sum = sha256_sum(new_value)
        #Old approach that added one item at a time to 2 databases
        #success2 = insert_key(large_dbfile, value_sum, [new_value])
        #success1 = add_to_db_list(dbfile, key_str, value_sum)
        #New approach that buffers up writes
        success2 = buffer_merges(large_dbfile, value_sum, [new_value], max_adds)
        success1 = buffer_merges(dbfile, key_str, [value_sum], max_adds)
        #We can't do the following; the writes may not yet have made it out to disk as they're being buffered.
        #if paranoid:
        #    valsequal = False
        #    retrieved_object = select_key_large_value(dbfile, large_dbfile, key_str)
        #    for one_retrieved in retrieved_object:
        #        if new_value == one_retrieved:
        #            valsequal = True
        #    if valsequal is False:
        #        sys.stderr.write("Mismatch in add_to_db_list_large_value\n")
        #        sys.stderr.write(str(key_str) + "\n")
        #        sys.stderr.write(str(new_value) + "\n")
        #        sys.stderr.write(str(value_sum) + "\n")
        #        sys.stderr.write(str(retrieved_object) + "\n")
        #        sys.stderr.flush()
        #        sys.exit(1)
        #else:
        valsequal = True

    return valsequal and success1 and success2
