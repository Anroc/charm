import datetime

from charm.schemes.abenc.abenc_maabe_cd16 import RDABE
from charm.test.benchmark.wrappers.MAABEBenchmarkWrapper import *


class DABE_Wrapper(MAABEBenchmarkWrapper):
    def __init__(self):
        super().__init__()
        self.dabe = RDABE(self.group)
        self.apks = dict()
        self.asks = dict()
        self.users = dict()
        self.time = str(datetime.date(2018, 12, 2))

    def setup(self):
        self.gpp = self.dabe.setup()

    def authsetup(self, attributes, authority_id):
        self.asks[authority_id], self.apks[authority_id] = self.dabe.setupAuthority(self.gpp, attributes, authority_id)
        return 0

    def registerUser(self, user_id):
        self.users[user_id] = self.dabe.registerUser(user_id)
        self.users[user_id]['keys'] = None

    def keygen(self, attributes, user_id, as_authority_id):
        self.users[user_id]['keys'] = self.dabe.keygen(self.gpp, attributes, self.users[user_id],
                                                       self.asks[as_authority_id],
                                                       self.time, self.users[user_id]['keys'])
        return 0

    def encrypt(self, policy, message):
        self.ct = self.dabe.encrypt(self.gpp, policy, message, self.apks.values(), self.time)
        return 0

    def decrypt(self, user_id):
        m = self.dabe.decrypt(self.gpp, self.ct, self.users[user_id], self.users[user_id]['keys'], self.time)

        assert self.message == m
        return 0

    def getSizeOfUser(self, user_id):
        return dict_to_size(self.users[user_id])

    def getSizeOfAuth(self, auth_id):
        return dict_to_size(self.apks[auth_id]) + dict_to_size(self.asks[auth_id])

    def getSizeOfCT(self):
        return dict_to_size(self.ct)
