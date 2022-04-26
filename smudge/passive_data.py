from os.path import exists
import sqlite3
import urllib.request



class passive_data:
    """
    A class filled with static methods that interacts with the sqlite database.
    """

    @staticmethod
    def test_github_con():
        '''Tests Internet Connection to Github.com'''
        test_result = urllib.request.urlopen("https://www.github.com").getcode()
        if test_result == 200:
            return True
        else:
            return False

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
            # Create Signatures Table
            conn.execute('''CREATE TABLE "signatures" (
	        "id"	INTEGER NOT NULL UNIQUE,
	        "acid"	INTEGER UNIQUE,
	        "platform"  TEXT,
            "tcp_flag"	TEXT,
	        "version"	TEXT NOT NULL,
	        "ittl"	TEXT,
	        "olen"	TEXT,
	        "mss"	TEXT,
	        "wsize"	TEXT,
	        "scale"	TEXT,
	        "olayout"	TEXT,
	        "quirks"	TEXT,
	        "pclass"	TEXT,
	        "comments"	TEXT,
	        PRIMARY KEY("id" AUTOINCREMENT)
            );''')
            conn.close()
        return True

    @staticmethod
    def signature_insert(conn, sig_obj):
        '''Insert Statement for the Signature Table.'''
        entry = conn.execute('SELECT id FROM signatures WHERE (acid=?)', (sig_obj.sig_acid,))
        entry = entry.fetchone()
        if entry is None:
            conn.execute("insert into signatures (acid, platform, tcp_flag, version, ittl, olen, mss, wsize, scale, olayout, quirks, pclass, comments) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (sig_obj.sig_acid, sig_obj.platform, sig_obj.sig_tcp_flag, sig_obj.version, sig_obj.ittl, sig_obj.olen, sig_obj.mss, sig_obj.wsize, sig_obj.scale, sig_obj.olayout, sig_obj.quirks, sig_obj.pclass, sig_obj.sig_comments))
            conn.commit()
        return True



class pull_data:
    """
    A class that contains a method that:
        * Loads a json file from github into memory.
        * Dumps the json into the sqlite database.

    The use of class methods is used so that class variables can be overrided for testing.
    ...

    Class Variables
    ----------
    url : str
        URL of raw json file that contains TCP Signatures.
    """

    import json
    import urllib.request
    url = "https://raw.githubusercontent.com/activecm/tcp-sig-json/testing-data/tcp-sig.json"

    @classmethod
    def import_data(cls):
        """Imports TCP Signatures from raw JSON file hosted on Github."""
        with cls.urllib.request.urlopen(cls.url) as f:
            data = cls.json.load(f)
            return data



class tcp_sig:
    """
    Data mapping class that takes a TCP Signature object and inserts it into the sqlite database.
    """

    def __init__(self, tcp_sig_obj):
        self.sig_acid = tcp_sig_obj['acid']
        self.platform = tcp_sig_obj['platform']
        self.sig_tcp_flag = tcp_sig_obj['tcp_flag']
        self.sig_comments = tcp_sig_obj['comments']
        self.signature = dict(zip(['version', 'ittl', 'olen', 'mss', 'wsize', 'scale', 'olayout', 'quirks', 'pclass'], tcp_sig_obj['tcp_sig'].split(':')))
        self.version = self.signature['version']
        self.ittl = self.signature['ittl']
        self.olen = self.signature['olen']
        self.mss = self.signature['mss']
        self.wsize = self.signature['wsize']
        self.scale = self.signature['scale']
        self.olayout = self.signature['olayout']
        self.quirks = self.signature['quirks']
        self.pclass = self.signature['pclass']

    @property
    def qstring(self):
        qstring = "{ver}:{ittl}:{olen}:{mss}:{wsize}:{scale}:{olayout}:{quirk}:{pclass}".format(ver=self.version, ittl=self.ittl, olen=self.olen, mss=self.mss, wsize=self.wsize, scale=self.scale, olayout=self.olayout, quirk=self.quirks, pclass=self.pclass)
        return qstring

    def __str__(self):
        return self.qstring

