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
from functools import reduce

# type annotations
pp_t = {'g': G1, 'h': G1, 'f_0': G1, 'f': [], 'G_0': G1, 'G': [], 'H_0': G1, 'H': [], 'E': [], 'Z': []}
mk_t = {'alpha': [], 'r': [], 'c': [], 'counter': int}
sk_t = {'i': int, 'j': int, 'S': [str], 'K': G1, 'K_tick': G1, 'K_ticktick': G1, 'K_dash': [G1], 'K_ij': [G1],
        'K_tick_ij': [G1]}
ct_t = {'C_tilde': GT, 'C': G1, 'Cy': G1, 'Cyp': G2}

debug = False
NUM_USER_SQURT = 2


class CPabe_LW14(ABEnc):
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj

    @Output(pp_t, mk_t)
    def setup(self):
        g, h, f_0, G_0, H_0 = group.random(G1), group.random(G1), group.random(G1), group.random(G1), group.random(G1)
        f, alpha, r, z, c, E, G, Z, H = [None] * NUM_USER_SQURT, [None] * NUM_USER_SQURT, [None] * NUM_USER_SQURT, [
            None] * NUM_USER_SQURT, [None] * NUM_USER_SQURT, [None] * NUM_USER_SQURT, [None] * NUM_USER_SQURT, [
                                            None] * NUM_USER_SQURT, [None] * NUM_USER_SQURT

        g.initPP()
        for i in range(0, NUM_USER_SQURT):
            f[i] = group.random(G1)
            alpha[i], r[i], z[i], c[i] = group.random(ZR), group.random(ZR), group.random(ZR), group.random(ZR),
            E[i] = pair(g, g ** alpha[i])
            G[i] = g ** r[i]
            Z[i] = g ** z[i]
            H[i] = g ** c[i]

        pp = {'g': g, 'h': h, 'f_0': f_0, 'f': f, 'G_0': G_0, 'G': G, 'H_0': H_0, 'H': H, 'E': E, 'Z': Z}
        mk = {'alpha': alpha, 'r': r, 'c': c, 'counter': 0}
        return pp, mk

    # @Input(pp_t, mk_t, [str])
    # @Output(sk_t)
    def keygen(self, pp, mk, S):
        mk['counter'] += 1
        for i in range(0, NUM_USER_SQURT):
            for j in range(0, NUM_USER_SQURT):
                if i * NUM_USER_SQURT + j + 1 == mk['counter']:
                    sigma = group.random(ZR)
                    delta = [None] * len(S)
                    x = [None] * len(S)
                    for index, s in enumerate(S):
                        delta[index] = group.random(ZR)
                        x[index] = group.hash(s)

                    g = pp['g']
                    SK = {
                        'i': i,
                        'j': j,
                        'S': S,
                        'K': g ** mk['alpha'][i] * g ** (mk['r'][i] * mk['c'][j]) * (pp['f_0'] * pp['f'][j]) ** sigma,
                        'K_tick': g ** sigma,
                        'K_ticktick': pp['Z'][i] ** sigma,
                        'K_dash': [pp['f'][j_tick] ** sigma if j_tick != j else None for j_tick in
                                   range(0, NUM_USER_SQURT)],
                        'K_ij': [g ** delta[index] for index in range(0, len(x))],
                        'K_tick_ij': [(pp['H_0'] ** x[index] * pp['h']) ** delta[index] * pp['G_0'] ** -sigma for index
                                      in range(0, len(x))]
                    }
                    return SK

        print("SK is none.")
        return None

    def _calc_user_index(self, matrix_length, counter):
        return int(counter / matrix_length), counter % matrix_length

    def _mul_and_filter(self, f, R):
        # TODO: filter revoced user
        prod = f[0]
        for i in range(1, len(f)):
            prod *= f[i]
        return prod

    def _pow_vector(self, g, vector):
        return np.array([g ** vector[i] for i in range(0, len(vector))])

    # @Input(pp_t, GT, str)
    # @Output(ct_t)
    def encrypt(self, pp, M, policy_str, R=[], user_index=0):
        # Setup
        policy = util.createPolicy(policy_str)
        A, p = util.calculateLSSSMatrix(policy)
        p = [group.hash(p[x]) for x in range(0, len(p))]
        l, n = A.shape
        i_bar, j_bar = self._calc_user_index(NUM_USER_SQURT, user_index)
        kappa = group.random(ZR)
        tau = group.random(ZR)
        s = [group.random(ZR) for _ in range(0, NUM_USER_SQURT)]
        t = [group.random(ZR) for _ in range(0, NUM_USER_SQURT)]
        v_c = np.array([group.random(ZR) for _ in range(0, 3)])
        w = [[group.random(ZR) for _ in range(0, 3)] for _ in range(0, NUM_USER_SQURT)]
        w = np.array(w)

        eta = [group.random(ZR) for _ in range(0, l)]
        pi = group.random(ZR)
        u = [group.random(ZR) for _ in range(0, n)]
        u[0] = pi

        rx = group.random(ZR)
        ry = group.random(ZR)
        rz = group.random(ZR)

        x1 = np.array([rx, 0, rz])
        x2 = np.array([0, ry, rz])
        x3 = np.array([-ry * rz, -rx * rz, rx * ry])

        v = [None] * NUM_USER_SQURT
        for i in range(0, i_bar + 1):
            v[i] = np.array([group.random(ZR) for _ in range(0, 3)])
        for i in range(i_bar + 1, NUM_USER_SQURT):
            c1 = group.random(ZR)
            c2 = group.random(ZR)
            v[i] = x1 ** c1 + x2 ** c2

        v = np.array(v)

        # 1.
        s_hat, R1, R2, Q1, Q2, Q3, T = [None] * NUM_USER_SQURT, [None] * NUM_USER_SQURT, [None] * NUM_USER_SQURT, [
            None] * NUM_USER_SQURT, [None] * NUM_USER_SQURT, [None] * NUM_USER_SQURT, [None] * NUM_USER_SQURT
        g = pp['g']

        for i in range(0, NUM_USER_SQURT):
            # TODO: implement revocation
            if i < i_bar:
                s_hat = group.random(ZR)
                R1[i] = self._pow_vector(g, v[i])
                R2[i] = self._pow_vector(g, v[i] * kappa)
                Q1[i] = g ** s[i]
                Q2[i] = (pp['f_0'] * self._mul_and_filter(pp['f'], R)) ** s[i] * pp['Z'][i] ** t[i] * pp['f_0'] ** pi
                Q3[i] = g ** t[i]
                T[i] = pp['E'][i] ** s_hat
            else:
                t_si_vi_vc = tau * s[i] * np.dot(v[i], v_c)
                R1[i] = self._pow_vector(pp['G'][i], v[i] * s[i])
                R2[i] = self._pow_vector(pp['G'][i], v[i] * kappa * s[i])
                Q1[i] = g ** t_si_vi_vc
                Q2[i] = (pp['f_0'] * self._mul_and_filter(pp['f'], R)) ** t_si_vi_vc * pp['Z'][i] ** t[i] * pp[
                    'f_0'] ** pi
                Q3[i] = g ** t[i]
                T[i] = M * pp['E'][i] ** t_si_vi_vc

        # 2.
        C1, C2 = [None] * NUM_USER_SQURT, [None] * NUM_USER_SQURT
        for j in range(0, NUM_USER_SQURT):
            if j < j_bar:
                mu = group.random(ZR)
                C1[j] = self._pow_vector(pp['H'][j], tau * (v_c + x3 * mu)) * self._pow_vector(g, w[j] * kappa)
            else:
                C1[j] = self._pow_vector(pp['H'][j], v_c * tau) * self._pow_vector(g, w[j] * kappa)
            # g ** vector is not implemented
            C2[j] = self._pow_vector(g, w[j])
        C1 = np.array(C1)
        C2 = np.array(C2)

        # 3.
        P1, P2, P3 = [None] * l, [None] * l, [None] * l
        for k in range(0, l):
            P1[k] = pp['f_0'] ** np.dot(A[k], u) * pp['G_0'] ** eta[k]
            P2[k] = (pp['H_0'] ** p[k] * pp['h']) ** (- eta[k])
            P3[k] = g ** eta[k]
        P1 = np.array(P1)
        P2 = np.array(P2)
        P3 = np.array(P3)

        CT = {
            'R': R,
            'A': A,
            'p': p,
            'R1': R1,
            'R2': R2,
            'Q1': Q1,
            'Q2': Q2,
            'Q3': Q3,
            'T': T,
            'C1': C1,
            'C2': C2,
            'P1': P1,
            'P2': P2,
            'P3': P3
        }
        return CT

    # @Input(pp_t, sk_t, ct_t)
    # @Output(GT)
    def decrypt(self, pp, sk, ct):
        A = ct['A']
        p = ct['p']
        hash_S = [group.hash(s) for s in sk['S']]
        policy_A = np.array([A[k] for k in range(0, len(p)) if p[k] in hash_S])
        w = util.solveLSSSMatrix(policy_A)
        print(w)


def main():
    groupObj = PairingGroup('SS512')

    cpabe = CPabe_LW14(groupObj)
    attrs = ['ONE', 'TWO', 'FIVE']
    access_policy = '((four or three) and (three or one))'
    # access_policy = 'E and (((A and B) or (C and D)) or ((A or B) and (C or D)))'
    if debug:
        print("Attributes =>", attrs);
        print("Policy =>", access_policy)

    (pk, mk) = cpabe.setup()

    sk = cpabe.keygen(pk, mk, attrs)
    print("sk :=>", sk)

    rand_msg = groupObj.random(GT)
    if debug: print("msg =>", rand_msg)
    ct = cpabe.encrypt(pk, rand_msg, access_policy)
    if debug: print("\n\nCiphertext...\n")
    groupObj.debug(ct)

    rec_msg = cpabe.decrypt(pk, sk, ct)
    if debug: print("\n\nDecrypt...\n")
    if debug: print("Rec msg =>", rec_msg)

    assert rand_msg == rec_msg, "FAILED Decryption: message is incorrect"
    if debug: print("Successful Decryption!!!")


if __name__ == "__main__":
    debug = True
    main()

