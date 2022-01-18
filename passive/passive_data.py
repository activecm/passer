from os.path import exists
import sqlite3



class passive_data:

    @staticmethod
    def create_con():
        '''Create Database Connection'''
        return sqlite3.connect('signature.db')


    @staticmethod
    def setup_db():
        '''Create Sqlite3 DB with all required tables'''
        if exists('signature.db'):
            pass
        else:
            with open('signature.db', 'x') as fp:
                pass
            conn = sqlite3.connect('signature.db')
            # Create Signature Table
            conn.execute('''CREATE TABLE "author" (
    	    "id"	INTEGER NOT NULL UNIQUE,
    	    "name"	TEXT NOT NULL,
    	    "email"	TEXT,
    	    "github"	TEXT,
    	    PRIMARY KEY("id" AUTOINCREMENT)
            )''')
            #Create Device Table
            conn.execute('''CREATE TABLE "device" (
    	    "id"	INTEGER NOT NULL UNIQUE,
    	    "type"	TEXT NOT NULL,
    	    "vendor"	TEXT,
    	    "url"	TEXT,
    	    PRIMARY KEY("id" AUTOINCREMENT)
            )''')
            #Create OS Table
            conn.execute('''CREATE TABLE "os" (
    	    "id"	INTEGER NOT NULL,
    	    "name"	TEXT,
    	    "version"	TEXT,
    	    "class"	TEXT,
    	    "vendor"	TEXT,
    	    "url"	TEXT,
    	    PRIMARY KEY("id" AUTOINCREMENT)
            )''')
            # Create Signatures Table
            conn.execute('''CREATE TABLE "signatures" (
	        "id"	INTEGER NOT NULL UNIQUE,
	        "acid"	INTEGER UNIQUE,
	        "tcp_flag"	TEXT,
	        "ver"	TEXT NOT NULL,
	        "ittl"	INTEGER,
	        "olen"	INTEGER,
	        "mss"	TEXT,
	        "wsize"	TEXT,
	        "scale"	TEXT,
	        "olayout"	TEXT,
	        "quirks"	TEXT,
	        "pclass"	TEXT,
	        "comments"	TEXT,
	        "os_id"	INTEGER,
	        "device_id"	INTEGER,
	        "author_id"	INTEGER,
	        FOREIGN KEY("os_id") REFERENCES "os"("id"),
	        FOREIGN KEY("author_id") REFERENCES "author"("id"),
	        FOREIGN KEY("device_id") REFERENCES "device"("id"),
	        PRIMARY KEY("id" AUTOINCREMENT)
            );''')
            conn.close()
        return True

    @staticmethod
    def author_insert(conn, name, email, github):
        '''Insert Statement for the Author Table'''
        entry = conn.execute('SELECT id FROM author WHERE (name=? AND email=?)', (name, email))
        entry = entry.fetchone()
        if entry is None:
            author_id = conn.execute("insert into author (name, email, github) values (?, ?, ?)", (name, email, github))
            conn.commit()
            author_id = author_id.lastrowid
        else:
            author_id = entry[0]
        return author_id

    @staticmethod
    def os_insert(conn, name, version, os_class, vendor, url):
        '''Insert Statement for the OS Table'''
        entry = conn.execute('SELECT id FROM os WHERE (name=? AND version=? AND class=? AND vendor=?', (name, version, os_class, vendor))
        entry = entry.fetchone()
        if entry is None:
            os_id = conn.execute("insert into os (name, version, class, vendor, url) values (?, ?, ?, ?, ?)", (name, version, os_class, vendor, url))
            conn.commit()
            os_id = os_id.lastrowid
        else:
            os_id = entry[0]
        return os_id

    @staticmethod
    def device_insert(conn, device_type, vendor, url):
        '''Insert Statement for the Device Table'''
        entry = conn.execute('SELECT id FROM device WHERE (type=? AND vendor=? AND url=?', (device_type, vendor, url))
        entry = entry.fetchone()
        if entry is None:
            device_id = conn.execute("insert into device (type, vendor, url) values (?, ?, ?)",(device_type, vendor, url))
            conn.commit()
            device_id = device_id.lastrowid
        else:
            device_id = entry[0]
        return device_id

    @staticmethod
    def signature_insert(conn, acid, tcp_flag, ver, ittl, olen, mss, wsize, scale, olayout, quirks, pclass, comments, os_id, device_id, author_id):
        '''Insert Statement for the Signature Table'''
        entry = conn.execute('SELECT id FROM signatures WHERE (acid=?)', (acid))
        entry = entry.fetchone()
        if entry is None:
            conn.execute("insert into signatures (acid, tcp_flag, ver, ittl, olen, mss, wsize, scale, olayout, quirks, pclass, comments, os_id, device_id, author_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (acid, tcp_flag, ver, ittl, olen, mss, wsize, scale, olayout, quirks, pclass, comments, os_id, device_id, author_id))
        conn.commit()
        return True
