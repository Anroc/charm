import time

from charm.schemes.abenc.abenc_tfdacmacs_ltxwc16 import TFDACMACS
from charm.test.benchmark.wrappers.MAABEBenchmarkWrapper import *


class TFDACMACS_Wrapper(MAABEBenchmarkWrapper):

    def __init__(self):
        super().__init__()
        self.dac = TFDACMACS(groupObj=self.group)
        self.apks = dict()
        self.asks = dict()
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
        self.apks[apk['aid']] = apk
        self.asks[ask['aid']] = ask

        return end - start

    def registerUser(self, user_id):
        user = self.dac.registerUser(self.gpp, user_id)

        user['secret_keys'] = dict()
        self.users.append(user)

    def keygen(self, attributes, user_id, as_authority_id):
        user, time1 = find_entity(user_id, self.users, "uid")
        ask = self.asks[as_authority_id]
        apk = self.apks[as_authority_id]
        start = time.time()
        tf_attrs = [attribute + ":TRUE" for attribute in attributes]
        end = time.time()

        user['secret_keys'] = self.dac.keygen(self.gpp, tf_attrs, user, ask, apk, extend_sk=user['secret_keys'])

        return time1 + (end - start)

    def encrypt(self, policy, message):
        start = time.time()
        parts = policy.split(" and ")
        policy = " and ".join([part + ":TRUE" for part in parts])
        end = time.time()

        self.ct = self.dac.encrypt(self.gpp, policy, message, self.apks)
        return end - start

    def decrypt(self, user_id):
        user, time1 = find_entity(user_id, self.users, "uid")

        m = self.dac.decrypt(self.gpp, self.ct, user, user['secret_keys'], self.apks)

        assert self.message == m
        return time1

    def getSizeOfUser(self, user_id):
        return dict_to_size(find_entity(user_id, self.users, "uid"))

    def getSizeOfAuth(self, auth_id):
        return dict_to_size(self.apks[auth_id]) + dict_to_size(self.asks[auth_id])

    def getSizeOfCT(self):
        return dict_to_size(self.ct)
