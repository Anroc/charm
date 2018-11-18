'''
Zhen Liu and Duncan S. Wong (Pairing-based)

| From: "Hierarchical attribute-based encryption and scalable user revocation for sharing data in cloud servers".
| Published in: 2010
| Available from: http://www.cs.sjtu.edu.cn/~guo-my/PDF/Journals/J03.pdf
| Notes: Policy must be present in DNF, e.g.: (a and b) or (b and c) or (c)
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

# type annotations
pp_t = {'g': G1, 'h': G1, 'f_0': G1, 'f': [], 'G_0': G1, 'G': [], 'H_0': G1, 'H': [], 'E': [], 'Z': []}
mk_t = {'alpha': [], 'r': [], 'c': [], 'counter': int}
sk_t = {'i': int, 'j': int, 'S': [str], 'K': G1, 'K_tick': G1, 'K_ticktick': G1, 'K_dash': [G1], 'K_ij': [G1],
        'K_tick_ij': [G1]}
ct_t = {'C_tilde': GT, 'C': G1, 'Cy': G1, 'Cyp': G2}

debug = False



class CPabe_LW10(ABEnc):
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
            'H_A': lambda x : group.hash(x),
            'P_1': None  # root DM , init later
        }
        return params, {'mk': mk}

    """
    id: tu
    pk_next: com.berlin.tu
    pk: com.berlin
    """
    def createDM(self, params, mk, id):
        mk_val = mk['mk']

        assert type(id) == str
        if 'id' not in mk:
            # first DM creation
            assert "." not in id
            pk_next = id
            sk = group.init(G1)
            assert sk + params['P_0'] == params['P_0']
            Q = [ params['Q_0'] ]
            pk = None
            root_dm = True
        else:
            assert "." in id
            sk = mk['sk']
            Q = mk['Q_prev_union_Q']
            pk = mk['pk']
            pk_next = pk + "." + id
            root_dm = False

        mk_next = group.random(ZR)
        P_next = params['H_1'](pk_next)
        sk_next = sk + mk_val * P_next
        Q_next = mk_next * params['P_0']
        Q = Q.copy()

        Q_list = Q.copy()
        Q_list.append(Q_next)
        MK_next = {
            'mk': mk_next,
            'sk': sk_next,
            'Q_prev': Q,
            'Q': Q_next,
            'Q_prev_union_Q': Q_list,
            'pk_prev': pk,
            'pk': pk_next,
            'id': id,
            'H_mk': lambda x : group.hash(x),
            'id_gen': lambda x : id + "." + x,
            'attrs': {
                # filled later
            }
        }
        if root_dm:
            params['P_1'] = P_next
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
            'mk': mk_dm['mk'] * mk_u * params['P_0'],
            'id': id_u,
            'pk_u': pk_u,
            'attrs': {}
        }

        for s in S:
            if mk_dm['id'] != s[:s.rfind(".")]:
                raise Exception("Attribute %s in not in the domain of %s." % (s, mk_dm['id']))
            v = group.random()
            pk_a = (v, mk_dm['pk'], s)
            mk_dm['attrs'][s] = v
            P_a = mk_dm['H_mk'](pk_a) * params['P_0']
            sk_ua = mk_dm['sk'] + mk_dm['mk'] * mk_u * P_a
            sk_u['attrs'][s] = sk_ua
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

    def extract_ancestor_dm(self, pk):
        return ".".join(pk.split(".")[:-1])

    def extract_complete_hirachy(self, pk):
        split = pk.split(".")
        return [ ".".join(split[:x]) for x in range(1, len(split)+1)]

    def assert_hirachical_attrs(self, a):
        assert "." in a, "Given attribute %s in not in hirachical form. Expected form 'rm.dm.attrName'"

    def lcm(self, l):
        from math import gcd
        lcm = l[0]
        for i in l[1:]:
            lcm = lcm * i / gcd(lcm, i)
        return int(lcm)

    # @Input(pp_t, GT, str)
    # @Output(ct_t)
    def encrypt(self, params, M, policy_str):
        a = util.to_dnf_matrix(policy_str)
        if debug:
            print(a)
        a_DM = list()
        N = len(a)
        n, t = list(), list()
        for i in range(0, N):
            n.append(len(a[i]))
            a_DM.append(list())
            for j in range(0, len(a[i])):
                self.assert_hirachical_attrs(a[i][j])
                a_DM[i].append(self.extract_ancestor_dm(a[i][j]))
            t.append(len(set(a_DM[i])) - 1)

        lcm = self.lcm(n)
        print("lcm of %s is %d" % (str(n), lcm))

        P = list()
        P_a = list()
        U = list()
        r = group.random()
        U_0 = r * params['P_0']
        for i in range(0, N):
            U.append(list())
            P.append(list())
            P_a.append(list())
            sum = group.init(G1, 0)
            for j in range(0, n[i]):
                P_a[i].append(params['H_A'](a[i][j]) * params['P_0'])
                sum += P_a[i][j]

                if j <= t[i]:
                    P[i].append(params['H_1'](a_DM[i][j]))
                if j != 0:
                    if j <= t[i]:
                        U[i].append(r * P[i][j])
                else:
                    # relaced later
                    U[i].append(None)
            U[i][0] = r * sum

        ct = {
            't': t,
            'n': n,
            'N': N,
            'U': U,
            'U_0': U_0,
            'A': a,
            'n_a': lcm,
            # change to M ^ params['H_2'](pair(params['Q_0'], r * lcm * params['P_1']
            'V': M * params['H_2'](pair(params['Q_0'], r * lcm * params['P_1']))
        }
        return ct

    # @Input(pp_t, sk_t, ct_t)
    # @Output(GT)
    def decrypt(self, params, sk_u, ct):
        user_attrs = sk_u['attrs'].keys()
        A = ct['A']

        for j, a in enumerate(A):
            if set(a).issubset(user_attrs):
                i = j
                break
        else:
            raise Exception("user does not satisfy policy")

        # we are only working with the i-th entry from now on
        sk_sum = group.init(G1, 0)
        for s in a:
            sk_sum += sk_u['attrs'][s]
        n_div = int(ct['n_a'] / ct['n'][i])

        upper = pair(ct['U_0'], n_div * sk_sum)
        lower1 = pair(sk_u['mk'], n_div * ct['U'][i][0])
        lower2 = group.init(ZR, 1)
        for j in range(1, ct['t'][i]):
            lower2 *= pair(ct['U'][i][j], ct['n_a'] * sk_u['Q_tuple'][j-1])

        restored_blinding = upper / (lower1 * lower2)
        # in paper this is done via xor
        return ct['V'] / params['H_2'](restored_blinding)



def main():
    groupObj = PairingGroup('SS512')

    cpabe = CPabe_LW10(groupObj)
    attrs = ['de.berlin.four', 'de.berlin.two', 'de.berlin.three']
    access_policy = '((de.four and de.berlin.three) or (de.berlin.three and de.berlin.two and de.berlin.four))'
    # access_policy = 'E and (((A and B) or (C and D)) or ((A or B) and (C or D)))'
    if debug:
        print("Attributes =>", attrs)
        print("Policy =>", access_policy)

    (params, mk) = cpabe.setup()

    mk_dm_de = cpabe.keygen(params, mk, "de")
    mk_dm_berlin = cpabe.keygen(params, mk_dm_de, "de.berlin")
    print("mk of DM :=>", mk_dm_de)

    sk_user = cpabe.keygen(params, mk_dm_berlin, "user1", attrs)
    print("sk of user :=>", sk_user)

    rand_msg = groupObj.random(GT)
    if debug: print("msg =>", rand_msg)
    ct = cpabe.encrypt(params, rand_msg, access_policy)
    if debug: print("\n\nCiphertext...\n")
    groupObj.debug(ct)

    rec_msg = cpabe.decrypt(params, sk_user, ct)

    if debug: print("\n\nDecrypt...\n")
    if debug: print("Rec msg =>", rec_msg)

    assert rand_msg == rec_msg, "FAILED Decryption: message is incorrect"
    if debug: print("Successful Decryption!!!")


if __name__ == "__main__":
    debug = True
    main()

