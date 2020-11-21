import pandas as pd
from numpy import sum
import sys


class Options:
    def __init__(self):
        self.type = ''
        self.ip = ''
        self.state = ''
        self.port = ''
        self.ippref = False
        self.protocol = ''
        self.ip_version = 0  # 0 == any
        self.des = ''

    def reset(self):
        self.type = ''
        self.ip = ''
        self.state = ''
        self.port = ''
        self.ippref = False
        self.protocol = ''
        self.ip_version = 0
        self.des = ''


# TODO: implement buffering for large files?
def load(filename):
    df = pd.read_csv(filename, names=['Type', 'IPAddress', 'Port/info', 'State', 'description'],
                     header=None, error_bad_lines=False)
    op = (df.State.values == 'open').sum()
    warnings = (df['description'].str.startswith('Warning')).sum()
    suspicious = (df.State.values == 'suspicious').sum()
    n = len(pd.unique(df['IPAddress']))
    print(len(df), "records,", n, "distinct addresses,", op, "open ports", suspicious, "suspicious entries,", warnings,
          "warnings")
    return df


# shows every entry in the dataframe as a string. Output can be a lot...
def show_all(dframe):
    pd.reset_option('max_columns')
    sys.stdout.flush()
    if len(dframe) == 0:  # faster than the builtin .empty function
        print("Nothing to see here :)")
        return
    df_string = dframe.to_string(index=False)
    print(df_string)


def show(dframe):
    if len(dframe) == 0:  # faster than the builtin .empty function
        print("Nothing to see here :)")
        return

    warnings = (dframe['description'].str.startswith('Warning')).sum()
    suspicious = (dframe.State.values == 'suspicious').sum()
    n = len(pd.unique(dframe['IPAddress']))
    print(len(dframe), "records,", n, "distinct addresses,", suspicious, "suspicious entries,", warnings, "warnings")

    print(dframe)


def wraper_function(dframe, options):
    if options.state != '':
        dframe = dframe.loc[dframe['State'] == options.state]

    if options.port != '':
        dframe = dframe[dframe['Port/info'].str.contains(options.port, na=False)]

    if options.ip_version == 6:
        dframe = dframe[dframe['IPAddress'].str.contains(':', na=False)]
    elif options.ip_version == 4:
        dframe = dframe[~dframe['IPAddress'].str.contains(':', na=False)]

    if options.type != '':
        dframe = dframe[dframe['Type'] == (options.type.upper())]

    if options.ippref:
        dframe = dframe[dframe['IPAddress'].str.startswith(options.ip, na=False)]
    elif options.ip != '':
        dframe = dframe[dframe['IPAddress'] == options.ip]

    if options.des != '':
        dframe = dframe[dframe['description'].str.contains(options.des, na=False)]

    return dframe

# TODO: add sorting and exporting
if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Passer analytics tool.')
    parser.add_argument('-i', '--logfile', help='file to ingest', required=True, default='', nargs=1)
    (parsed, unparsed) = parser.parse_known_args()
    cl_args = vars(parsed)
    df = load(cl_args['logfile'][0])
    opts = Options()
    while True:
        command = (input('>')).lower()
        if command[:6] == 'filter':
            rol = (command[6:]).split()
            for item in rol:
                if item[:5] == 'type=':
                    opts.type = (item[5:]).upper()
                if item[:5] == 'port=':
                    opts.port = (item[5:]).upper()
                if item[:6] == 'state=':
                    opts.state = item[6:]
                if item[:4] == 'ipv=':
                    opts.ip_version = int(item[4:])
                if item[:3] == 'ip=':
                    opts.ip = item[3:]
                if item[:7] == 'ippref=':
                    if item[7] == 't':
                        opts.ippref = True
                    else:
                        opts.ippref = False
                if item[:12] == 'description=':
                    opts.des = item[12:]
        elif command[:8] == 'show-all':
            ndf = wraper_function(df, opts)
            show_all(ndf)
        elif command[:4] == 'show':
            ndf = wraper_function(df, opts)
            show(ndf)
        elif command == 'reset':
            opts.reset()
        elif command == 'quit':
            exit(0)
        else:
            print("Unrecognised command")
