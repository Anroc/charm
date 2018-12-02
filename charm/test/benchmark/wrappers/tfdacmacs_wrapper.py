import time

from charm.schemes.abenc.abenc_tfdacmacs_ltxwc16 import TFDACMACS
from charm.test.benchmark.wrappers.MAABEBenchmarkWrapper import MAABEBenchmarkWrapper
from charm.test.benchmark.wrappers.MAABEBenchmarkWrapper import find_entity


class TFDACMACS_Wrapper(MAABEBenchmarkWrapper):

    def __init__(self):
        super().__init__()
        self.dac = TFDACMACS(groupObj=self.group)
        self.apks = list()
        self.asks = list()
        self.users = list()
        self.user_sks = list()

    def setup(self):
        start_time = time.time()
        self.gpp = self.dac.setup()
        end_time = time.time()
        return end_time - start_time

    def authsetup(self, attributes, authority_id):
        start = time.time()
        tf_attrs = dict()
        for attribute in attributes:
            tf_attrs[attribute] = list()
            tf_attrs[attribute].append('TRUE')
        end = time.time()

        apk, ask = self.dac.setupAuthority(self.gpp, authority_id, tf_attrs)
        self.apks.append(apk)
        self.asks.append(ask)

        return end - start

    def registerUser(self, user_id):
        user = self.dac.registerUser(self.gpp, user_id)

        user['secret_keys'] = dict()
        self.users.append(user)

    def keygen(self, attributes, user_id, as_authority_id):
        user, time1 = find_entity(self.users, user_id, "uid")
        ask, time2 = find_entity(self.asks, as_authority_id, "aid")
        apk, time3 = find_entity(self.asks, as_authority_id, "aid")

        user['secret_keys'] = self.dac.keygen(self.gpp, attributes, user, ask, apk, extend_sk=user['secret_keys'])

        return time1 + time2 + time3

    def encrypt(self, policy, message):
        self.ct = self.dac.encrypt(self.gpp, policy, message, self.apks)
        return 0

    def decrypt(self, user_id):
        user, time1 = find_entity(self.users, user_id, "uid")

        m = self.dac.decrypt(self.gpp, self.ct, user, user['secret_keys'], self.apks)

        assert self.message == m
