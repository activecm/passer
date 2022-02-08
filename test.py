from passive_fingerprinting.passive_data import passive_data
from passive_fingerprinting.passive_data import pull_data
from passive_fingerprinting.passive_data import tcp_sig

# Create Sqlite DB
passive_data.setup_db()

# Create DB  Connection
conn = passive_data.create_con()

# Pull data from Github Ram JSON if Github is resolvable.
if passive_data.test_github_con():
    tcp_sig_data = pull_data.import_data()

    # Iterate over JSON Objects
    for i in tcp_sig_data['signature_list']:
        try:
            signature = tcp_sig(i)
            author_id = passive_data.author_insert(conn, signature.author, signature.author_email, signature.author_github)
            print(author_id)
            os_id = passive_data.os_insert(conn, signature.os_name, signature.os_version, signature.os_class, signature.os_vendor, signature.os_url)
            print(os_id)
            device_id = passive_data.device_insert(conn, signature.device_type, signature.device_vendor, signature.device_url)
            print(device_id)
            passive_data.signature_insert(conn, signature.sig_acid, signature.sig_tcp_flag, signature.signature['ver'], signature.signature['ittl'], signature.signature['olen'], signature.signature['mss'], signature.signature['wsize'], signature.signature['scale'], signature.signature['olayout'], signature.signature['quirks'], signature.signature['pclass'], signature.sig_comments, os_id, device_id, author_id)
        except Exception as e:
            print(e)

