from charm.schemes.abenc.abenc_dacmacs_yj14 import DACMACS
from charm.test.benchmark.wrappers.MAABEBenchmarkWrapper import *


class DACMACS_Wrapper(MAABEBenchmarkWrapper):
    def __init__(self):
        super().__init__()
        self.dac = DACMACS(self.group)
        self.authorities = dict()
        self.users = dict()


    def setup(self):
        self.gpp = self.dac.setup()

    def authsetup(self, attributes, authority_id):
        self.authorities[authority_id] = self.dac.setupAuthority(self.gpp, authority_id, attributes, self.authorities)
        return 0

    def registerUser(self, user_id):
        self.users[user_id] = dict()
        self.users[user_id]['authority_keys'] = None
        self.users[user_id]['secret_key'], self.users[user_id]['public_key'] = self.dac.registerUser(self.gpp)

    def keygen(self, attributes, user_id, as_authority_id):
        user, time1 = find_entity(self.users, user_id, "uid")
        authority = self.authorities[as_authority_id]

        for attribute in attributes:
            self.dac.keygen(self.gpp, authority, attribute, user['public_key'], self.users[user_id]['authority_keys'])
        return time1

    def encrypt(self, policy, message):
        # find first authority
        start = time.time()
        root = self.dac.util.createPolicy(policy)
        attribute = self.dac.util.getAttributeList(root)
        aid = attribute.split(".")[0]
        end = time.time()

        self.ct = self.dac.encrypt(self.gpp, policy, message, self.authorities[aid])

        return end - start

    def decrypt(self, user_id):
        user = self.users[user_id]

        tk = self.dac.generateTK(self.gpp, self.ct, user['authority_keys'], user['secret_key'][0])
        m = self.dac.decrypt(self.ct, tk, user['secret_key'][1])

        assert self.message == m
        return 0
