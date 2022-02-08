class quirk:
    """
    Creates quirks - comma-delimited properties and quirks observed in IP or TCP headers.
        If a signature scoped to both IPv4 and IPv6 contains quirks valid
            for just one of these protocols, such quirks will be ignored for
            on packets using the other protocol. For example, any combination
            of 'df', 'id+', and 'id-' is always matched by any IPv6 packet.
    """

    def __init__(self, p):
        self.p = p
        self.df = self.set_df()
        self.id_plus = self.set_id_plus()
        self.id_minus = self.set_id_minus()
        self.ecn = self.set_ecn()
        self.zero_plus = self.set_zero_plus()
        self.flow = self.set_flow()
        self.seq_minus = self.set_seq_minus()
        self.ack_plus = self.set_ack_plus()
        self.ack_minus = self.set_ack_minus()
        self.urtr_plus = self.set_uptr_plus()
        self.urgf_plus = self.set_urgf_plus()
        self.ts1_minus = self.set_ts1_minus()
        self.ts2_plus = self.set_ts2_plus()
        self.opt_plus = self.set_opt_plus()
        self.exws = self.set_exws()
        self.bad = self.set_bad()

    def set_df(self):
        '''Sets df attribute based on flag - "don't fragment" set (probably PMTUD); ignored for IPv6.'''
        df = False
        if 'DF' in self.p['IP'].flags:
            df = True
        return df

    def set_id_plus(self):
        '''Sets id+ attribute based on flag and IPID - DF set but IPID non-zero; ignored for IPv6.'''
        id_plus = False
        if self.p['IP'].flags =='DF' and self.p['IP'].id != 0:
            id_plus = True
        return id_plus

    def set_id_minus(self):
        '''Sets id- attribute based on flag and IPID - DF not set but IPID is zero; ignored for IPv6.'''
        id_minus = False
        if self.p['IP'].flags =='DF' and self.p['IP'].id == 0:
            id_minus = True
        return id_minus

    def set_ecn(self):
        '''Sets ecn attribute - explicit congestion notification support.'''
        ecn = False
        if 'E' in self.p['TCP'].flag:
            ecn = True
        return ecn

    def set_zero_plus(self):
        '''Sets 0+ Attribute -  "must be zero" field not zero; ignored for IPv6.'''
        zero_plus = False
        if self.p.reserved != 0:
            zero_plus = True
        return False

    def set_flow(self):
        '''Sets flow Attribute - non-zero IPv6 flow ID; ignored for IPv4.'''
        #TODO IPv6 support
        return False

    def set_seq_minus(self):
        '''Sets seq- attribute - sequence number is zero.'''
        seq_minus = False
        if self.p['TCP'].seq == 0:
            seq_minus = True
        return seq_minus

    def set_ack_plus(self):
        '''Sets ack+ - ACK number is non-zero, but ACK flag not set.'''
        ack_plus = False
        if self.p['TCP'].ack != 0:
            ack_plus = True
        return ack_plus

    def set_ack_minus(self):
        '''Sets ack- - ACK number is zero, but ACK flag set.'''
        ack_minus = False
        if self.p['TCP'].ack == 0:
            ack_minus = True
        return ack_minus

    def set_uptr_plus(self):
        '''Sets uptr+ attribute - URG pointer is non-zero, but URG flag not set.'''
        uptr_plus = False
        return uptr_plus

    def set_urgf_plus(self):
        '''Sets urgf+ attribute - URG flag used.'''
        urgf_plus = False
        if 'URG' in self.p['IP'].flags:
            urgf_plus = True
        return urgf_plus

    def set_pushf_plus(self):
        '''Sets pushf+ attribute - PUSH flag used.'''
        if 'PUSH' in self.p['IP'].flags:
            pushf_plus = True
        return pushf_plus

    def set_ts1_minus(self):
        '''Sets ts1- attribute - own timestamp specified as zero.'''
        ts1_minus = False
        return ts1_minus

    def set_ts2_plus(self):
        '''Sets ts2+ attribute - non-zero peer timestamp on initial SYN.'''
        ts2_plus = False
        return ts2_plus

    def set_opt_plus(self):
        '''Sets opt+ attribute - trailing non-zero data in options segment.'''
        opt_plus = False
        return opt_plus

    def set_exws(self):
        '''Sets exws attribute - excessive window scaling factor (> 14).'''
        exws = False
        return exws

    def set_bad(self):
        '''Sets bad attribute - malformed TCP options.'''
        bad = False
        return bad

