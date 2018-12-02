'''
Hui Cui and Robert H. Deng

| From: Revocable and Decentralized Attribute-Based Encryption
| Published in:   The British Computer Society
| Available From: https://academic.oup.com/comjnl/article/59/8/1220/2595019
| Notes: indirect (time-based revocation) attributes can only exist uniquely per policy

* type:           ciphertext-policy attribute-based encryption (public key)
* setting:        Pairing

:Authors:   Marvin Petzolt
:Date:      12/2018
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import uuid, datetime
import numpy as np


class RDABE(object):

    def __init__(self, groupObj):
        self.util = SecretUtil(groupObj, verbose=False)
        self.group = groupObj

    def setup(self):
        return {
            'g': self.group.random(G1),
            'N': self.group.order(),
            'H_0': lambda x: self.group.hash(x, ZR),
            'H_1': lambda x: self.group.hash(x, G1)
        }

    def registerUser(self):
        return {
            'GID': str(uuid.uuid4())
        }

    def setupAuthority(self, GPP, attributes, aid):
        ask = {
            'aid': aid,
            'sk': dict()
        }
        apk = {
            'aid': aid,
            'pk': dict()
        }
        for i in attributes:
            assert i.split('.')[0] == aid, "Authority Setup: Attribute '%s' does not belong to authority '%s'." % (i, aid)
            ask['sk'][i] = dict()
            ask['sk'][i]['alpha'] = self.group.random(ZR)
            ask['sk'][i]['gamma'] = self.group.random(ZR)

            apk['pk'][i] = dict()
            apk['pk'][i]['alpha'] = pair(GPP['g'], GPP['g']) ** ask['sk'][i]['alpha']
            apk['pk'][i]['gamma'] = GPP['g'] ** ask['sk'][i]['gamma']
        return ask, apk

    def keygen(self, GPP, attributes, userObj, ask, time, sk=None):
        if sk is None:
            sk = dict()
        for i in attributes:
            assert i.split('.')[0] == ask['aid'], "Keygen: Attribute '%s' does not belong to authority '%s'." % (i, ask['aid'])
            sk[i] = GPP['g'] ** (ask['sk'][i]['alpha'] * GPP['H_0'](time)) \
                    * GPP['H_1'](userObj['GID'] + time) ** ask['sk'][i]['gamma']
        return sk

    def encrypt(self, GPP, policy_str, m, apks, time):
        root = self.util.createPolicy(policy_str)
        A, p = self.util.calculateLSSSMatrix(root)
        assert len(p) == len(frozenset(p)), "p is required to be Injective. (In an access polciy no attribute is used twice)"

        g = GPP['g']
        H_0 = GPP['H_0']
        n, l = A.shape
        s = self.group.random()
        v = np.array([self.group.random() for _ in range(0, l)])
        v[0] = s

        w = np.array([self.group.random() for _ in range(0, l)])
        w[0] = self.group.init(ZR, 0)

        C_0 = m * pair(g,g) ** s
        C_1, C_2, C_3 = list(), list(), list()

        for row, attribute in enumerate(p):
            assert "." in attribute, "Attribute should have the form 'aid.attr_name'"
            aid = attribute.split(".")[0]
            for apk in apks:
                if apk['aid'] == aid:
                    break
            else:
                raise Exception("No matching authority public key found for aid '%s' of attribute '%s'." % (aid, attribute))

            v_x = np.dot(A[row], v)
            w_x = np.dot(A[row], w)
            r = self.group.random()

            C_1.append(
                pair(g, g) ** v_x * apk['pk'][attribute]['alpha'] ** (H_0(time) * r)
            )
            C_2.append(g ** r)
            C_3.append(apk['pk'][attribute]['gamma'] ** r * g ** w_x)

        return {
            'A': A,
            'p': p,
            'C_0': C_0,
            'C_1': C_1,
            'C_2': C_2,
            'C_3': C_3
        }

    def decrypt(self, GPP, CT, userObj, sk, time):
        A, p = CT['A'], CT['p']
        attr_user = sk.keys()
        policy_A, attr_index = self.util.findMatchingLSSSRows(A, p, attr_user)

        current_time = GPP['H_1'](userObj['GID'] + time)
        k, c = self.util.solveLSSSMatrix(policy_A)

        res = self.group.init(ZR, 1)
        for i in range(0, len(c)):
            cipher_index = attr_index[k[i]][0]
            current_attr = p[cipher_index]

            inner = (CT['C_1'][cipher_index] * pair(current_time, CT['C_3'][cipher_index])) \
                   / (pair(sk[current_attr], CT['C_2'][cipher_index]))

            res *= inner ** self.group.init(ZR, int(c[i]))
        return CT['C_0'] / res



def basicTest():
    print("RUN basicTest")
    groupObj = PairingGroup('SS512')
    rdabe = RDABE(groupObj)

    GPP = rdabe.setup()

    ask, apk = rdabe.setupAuthority(GPP, ['TUBERLIN.A', 'TUBERLIN.B', 'TUBERLIN.C'], 'TUBERLIN')

    alice = rdabe.registerUser()

    time_str = str(datetime.date(2018, 12, 2))
    sk_alice = rdabe.keygen(GPP, ['TUBERLIN.A', 'TUBERLIN.B', 'TUBERLIN.C'], alice, ask, time_str)

    M = groupObj.random(GT)

    CT = rdabe.encrypt(GPP, "TUBERLIN.C or (TUBERLIN.A and TUBERLIN.B)", M, [ apk ], time_str)

    revocer_m = rdabe.decrypt(GPP, CT, alice, sk_alice, time_str)

    print("\n\nDecrypt...\n")
    print("Rec msg =>", revocer_m)
    print("msg =>", M)

    assert M == revocer_m, "FAILED Decryption: message is incorrect"
    print("Successful Decryption!!!")


def basicTest_multiAuthorities():
    print("RUN multi authority")
    groupObj = PairingGroup('SS512')
    rdabe = RDABE(groupObj)

    GPP = rdabe.setup()

    ask_tuberlin, apk_tuberlin = rdabe.setupAuthority(GPP, ['TUBERLIN.A', 'TUBERLIN.B'], 'TUBERLIN')
    ask_hpi, apk_hpi = rdabe.setupAuthority(GPP, ['HPI.A', 'HPI.B'], 'HPI')

    alice = rdabe.registerUser()

    time_str = str(datetime.date(2018, 12, 2))
    sk_alice = rdabe.keygen(GPP, ['TUBERLIN.A', 'TUBERLIN.B'], alice, ask_tuberlin, time_str)
    sk_alice = rdabe.keygen(GPP, ['HPI.A', 'HPI.B'], alice, ask_hpi, time_str, sk_alice)

    M = groupObj.random(GT)

    CT = rdabe.encrypt(GPP, "HPI.A or HPI.B (TUBERLIN.A and TUBERLIN.B)", M, [ apk_tuberlin, apk_hpi ], time_str)

    revocer_m = rdabe.decrypt(GPP, CT, alice, sk_alice, time_str)

    print("\n\nDecrypt...\n")
    print("Rec msg =>", revocer_m)
    print("msg =>", M)

    assert M == revocer_m, "FAILED Decryption: message is incorrect"
    print("Successful Decryption!!!")


def basicTest_indirectRevocation():
    print("RUN indirect revocation")
    groupObj = PairingGroup('SS512')
    rdabe = RDABE(groupObj)

    GPP = rdabe.setup()

    ask, apk = rdabe.setupAuthority(GPP, ['TUBERLIN.A', 'TUBERLIN.B', 'TUBERLIN.C'], 'TUBERLIN')

    alice = rdabe.registerUser()

    time_now = str(datetime.date(2018, 12, 2))
    sk_alice = rdabe.keygen(GPP, ['TUBERLIN.A', 'TUBERLIN.B', 'TUBERLIN.C'], alice, ask, time_now)

    M = groupObj.random(GT)

    CT = rdabe.encrypt(GPP, "TUBERLIN.C or (TUBERLIN.A and TUBERLIN.B)", M, [ apk ], time_now)

    time_future = str(datetime.date(2018, 12, 3))
    revocer_m = rdabe.decrypt(GPP, CT, alice, sk_alice, time_future)

    print("\n\nDecrypt...\n")
    print("Rec msg =>", revocer_m)
    print("msg =>", M)

    assert M != revocer_m, "FAILED Revocation: message is still correct"
    print("Successful Revocation!!!")


if __name__ == '__main__':
    basicTest()
    basicTest_multiAuthorities()
    basicTest_indirectRevocation()
