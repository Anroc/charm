'''
Zhen Liu and Duncan S. Wong (Pairing-based)

| From: " Practical Attribute-Based Encryption: Traitor Tracing, Revocation, and Large Universe".
| Published in: 2014
| Available from: https://eprint.iacr.org/2014/616
| Notes: java reference implementation available at https://github.com/TU-Berlin-SNET/jTR-ABE
| Security Assumption: standard model with selective adversaries
|
| type:           ciphertext-policy attribute-based encryption (public key)
| setting:        Pairing

:Authors:    Marvin Petzolt
:Date:            11/2018
'''
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output
import numpy as np
import uuid

# type annotations
pp_t = {'g': G1, 'h': G1, 'f_0': G1, 'f': [], 'G_0': G1, 'G': [], 'H_0': G1, 'H': [], 'E': [], 'Z': []}
mk_t = {'alpha': [], 'r': [], 'c': [], 'counter': int}
sk_t = {'i': int, 'j': int, 'S': [str], 'K': G1, 'K_tick': G1, 'K_ticktick': G1, 'K_dash': [G1], 'K_ij': [G1],
        'K_tick_ij': [G1]}
ct_t = {'C_tilde': GT, 'C': G1, 'Cy': G1, 'Cyp': G2}

debug = False



class CPabe_LW14(ABEnc):
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj

    # @Output(pp_t, mk_t)
    def setup(self):
        mk = group.random(ZR)
        P_0 = group.random(G1)
        P_0.initPP()
        Q_0 = mk * P_0
        params = {
            'P_0': P_0,
            'Q_0': Q_0,
            'H_1': lambda x : group.hash(x, type=G1),
            'H_2': lambda x : hash(str(x)),
            'H_A': lambda x : group.hash(x)
        }
        return params, {'mk': mk}

    """
    id: tu
    pk_next: com.berlin.tu
    pk: com.berlin
    """
    def createDM(self, params, mk, id, pk = None, sk = None, Q  = None):
        mk = mk['mk']

        assert type(id) == str
        if pk is None:
            assert "." not in id
            assert sk is None
            assert Q is None
            pk_next = id
        else:
            assert "." in id
            assert sk is not None
            assert Q is not None
            pk_next = pk + "." + id

        mk_next = group.random(ZR)
        if sk is None:
            sk = group.init(G1)
            assert sk + params['P_0'] == params['P_0']
        P_next = params['H_1'](pk_next)
        sk_next = sk + mk * P_next
        Q_next = mk_next * params['P_0']
        if Q is None:
            Q = params['Q_0']
        MK_next = {
            'mk': mk_next,
            'sk': sk_next,
            'Q_prev': Q,
            'Q': Q_next,
            'pk_prev': pk,
            'pk': pk_next,
            'id': id,
            'H_mk': lambda x : group.hash(x),
            'id_gen': lambda x : id + "." + x
        }
        return MK_next

    """
    id_u: {id}
    id_a: student
    pk_u: pk_dm + . + id_u --> com.berlin.tu.{id}
    pk_a: pk_dm + . + id_a --> com.berlin.tu.student
    S = attribute strings -->  [ 'student' ]
    """
    def createUser(self, params, mk_dm, id_u, S):
        pk_u = mk_dm['id_gen'](id_u)
        mk_u = params['H_A'](pk_u)
        sk_u = {
            'Q_tuple': mk_dm['Q_prev'],
            'sk': mk_dm['mk'] * mk_u * params['P_0'],
            'id': id_u
        }

        for s in S:
            pk_a = mk_dm['id_gen'](s)
            P_a = mk_dm['H_mk'](pk_a) * params['P_0']
            sk_ua = mk_dm['sk'] + mk_dm['mk'] * mk_u * P_a
            sk_u[s] = sk_ua
        return sk_u

    # @Input(pp_t, mk_t, [str])
    # @Output(sk_t)
    def keygen(self, pp, mk, id, S = None):
        if S is None:
            print("Creating domain master '%s'." % (id))
            return self.createDM(pp, mk, id)
        else:
            assert S is not None, "S is None. Can not create user."
            assert 'id' in mk, "User must be a member of a domain."
            print("Creating user'%s' in domain '%s." % (id, mk['id']))
            return self.createUser(pp, mk, id, S)

    # @Input(pp_t, GT, str)
    # @Output(ct_t)
    def encrypt(self, pp, M, policy_str):
        pass

    # @Input(pp_t, sk_t, ct_t)
    # @Output(GT)
    def decrypt(self, pp, sk, ct):
        pass

def main():
    groupObj = PairingGroup('SS512')

    cpabe = CPabe_LW14(groupObj)
    attrs = ['ONE', 'TWO', 'THREE']
    access_policy = '((four or three) and (three or one))'
    # access_policy = 'E and (((A and B) or (C and D)) or ((A or B) and (C or D)))'
    if debug:
        print("Attributes =>", attrs)
        print("Policy =>", access_policy)

    (params, mk) = cpabe.setup()

    mk_dm = cpabe.keygen(params, mk, "de")
    print("mk of DM :=>", mk_dm)

    sk_user = cpabe.keygen(params, mk_dm, "user1", attrs)
    print("sk of user :=>", sk_user)

    rand_msg = groupObj.random(GT)
    if debug: print("msg =>", rand_msg)
    ct = cpabe.encrypt(params, rand_msg, access_policy)
    if debug: print("\n\nCiphertext...\n")
    groupObj.debug(ct)

    rec_msg = cpabe.decrypt(params, sk_user, ct) # , msk = mk)

    if debug: print("\n\nDecrypt...\n")
    if debug: print("Rec msg =>", rec_msg)

    assert rand_msg == rec_msg, "FAILED Decryption: message is incorrect"
    if debug: print("Successful Decryption!!!")


if __name__ == "__main__":
    debug = True
    main()

