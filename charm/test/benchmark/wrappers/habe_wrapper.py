from charm.schemes.abenc.abenc_wlwg11 import CPabe_WLGW11
from charm.test.benchmark.wrappers.MAABEBenchmarkWrapper import *


class HABE_Wrapper(MAABEBenchmarkWrapper):
    def __init__(self):
        super().__init__()
        self.habe = CPabe_WLGW11(self.group)
        self.authorities = dict()
        self.users = dict()

    def setup(self):
        self.params, self.mk = self.habe.setup()

    def authsetup(self, attributes, authority_id):
        self.authorities[authority_id] = self.habe.createDM(self.params, self.mk, authority_id)
        return 0

    def registerUser(self, user_id):
        pass

    def keygen(self, attributes, user_id, as_authority_id):
        user_id = as_authority_id + "." + user_id
        mk = self.authorities[as_authority_id]
        self.users[user_id] = self.habe.keygen(self.params, mk, user_id, attributes)
        return 0

    def encrypt(self, policy, message):
        start = time.time()
        parts = policy.split(" and ")
        policy = " and ".join([part + "" for part in parts])
        end = time.time()

        self.ct = self.habe.encrypt(self.params, message, policy)
        return end - start

    def decrypt(self, user_id):
        start = time.time()
        uid = self._to_complete_user_id(user_id)
        end = time.time()
        m = self.habe.decrypt(self.params, self.users[uid], self.ct)

        assert self.message == m
        return end - start

    def _to_complete_user_id(self, user_id):
        for uid in self.users.keys():
            if uid.endswith(user_id):
                break
        else:
            raise Exception("No matching user found for given user_id")
        return uid

    def getSizeOfUser(self, user_id):
        return dict_to_size(self.users[self._to_complete_user_id(user_id)])

    def getSizeOfAuth(self, auth_id):
        return dict_to_size(self.authorities[auth_id])

    def getSizeOfCT(self):
        return dict_to_size(self.ct)
