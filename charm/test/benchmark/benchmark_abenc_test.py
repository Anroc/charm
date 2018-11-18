import unittest
import time
import sys

from charm.schemes.abenc.abenc_lsw08 import KPabe
from charm.schemes.abenc.abenc_unmcpabe_yahk14 import CPABE_YAHK14
from charm.schemes.abenc.abenc_lw14 import CPabe_LW14
from charm.schemes.abenc.abenc_lw10 import CPabe_LW10
from charm.toolbox.pairinggroup import PairingGroup, GT

import matplotlib.pyplot as plt
import numpy as np

groups = [PairingGroup('SS512'),  PairingGroup('SS512'),  PairingGroup('SS512'), PairingGroup('SS512')]
testclasses = [KPabe(groups[0]), CPABE_YAHK14(groups[1]), CPabe_LW14(groups[2]), CPabe_LW10(groups[3])]
setup = [tc.setup() for tc in testclasses]
message = [group.random() for group in groups]

class BenchmarkTest1(unittest.TestCase):
    NUM_RUN = 30

    index = 0
    fig, axes = plt.subplots(3, 2, figsize=(12,12))

    def benchmarkSetup(self):
        res = list()

        for _ in testclasses:
            res.append(list())

        for i in range(0, self.NUM_RUN):
            for j, tc in enumerate(testclasses):
                start_time = time.time()
                tc.setup()
                end_time = time.time()
                res[j].append(end_time - start_time)

        self.plot(res, "Setup", xlable="# of runs")

    def benchmarkKeygen(self):
        res = list()
        keygens = list()
        keygens_length = list()
        for _ in testclasses:
            res.append(list())
            keygens_length.append(list())

        # LW 10 needs special inizialisation
        sk_cm = testclasses[3].keygen(setup[3][0], setup[3][1], "de")

        for i in range(0, self.NUM_RUN):
            current = list()
            for j, tc in enumerate(testclasses):
                S = [str(a) for a in range(1, i + 2)]
                if j == 0:
                    S = " and ".join(S)
                elif j == 3:
                    S = [ "de." + a for a in S]

                start_time = time.time()
                if j == 3:
                    sk = tc.keygen(setup[j][0], sk_cm, "user1", S)
                else:
                    sk = tc.keygen(setup[j][0], setup[j][1], S)
                end_time = time.time()

                current.append(sk)
                keygens_length[j].append(sys.getsizeof(str(sk)))
                res[j].append(end_time - start_time)
            keygens.append(current)

        self.res_keygen = keygens
        self.plot(res, "Keygen")
        self.plot(keygens_length, "Key length", ylabel="Size in bytes")

    def benchmarkEncrypt(self):
        res = list()
        ciphertext_length = list()

        encrypts = list()
        for _ in testclasses:
            res.append(list())
            ciphertext_length.append(list())

        for i in range(0, self.NUM_RUN):
            current = list()
            for j, tc in enumerate(testclasses):
                S = [str(a) for a in range(1, i + 2)]
                if j != 0:
                    if j == 3:
                        S = [ "de." + s for s in S ]
                    S = " and ".join(S)

                start_time = time.time()
                ct = tc.encrypt(setup[j][0], message[j], S)
                end_time = time.time()
                res[j].append(end_time - start_time)
                current.append(ct)
                ciphertext_length[j].append(sys.getsizeof(str(ct)))
            encrypts.append(current)


        self.res_encrypt = encrypts
        self.plot(res, "Encrypt")
        self.plot(ciphertext_length, "Ciphertext length", ylabel="Size in bytes")

    def benchmarkDecrypt(self):
        res = list()
        for _ in testclasses:
            res.append(list())

        for i in range(0, self.NUM_RUN):
            for j, tc in enumerate(testclasses):
                start_time = time.time()
                if j == 0:
                    tc.decrypt(self.res_encrypt[i][j], self.res_keygen[i][j])
                else:
                    tc.decrypt(setup[j][0], self.res_keygen[i][j], self.res_encrypt[i][j])
                end_time = time.time()
                res[j].append(end_time - start_time)

        self.plot(res, "Decrypt")

    def testall(self):
        self.benchmarkSetup()
        self.benchmarkKeygen()
        self.benchmarkEncrypt()
        self.benchmarkDecrypt()
        plt.show()

    def plot(self,
             res,
             title,
             ylabel = "time in s",
             xlable = "# of attributes"):
        axes = self.subplot()
        res = np.array(res)
        axes.set_title(title, fontweight="bold")
        axes.set_ylabel(ylabel)
        axes.set_xlabel(xlable)
        x = np.linspace(1, self.NUM_RUN, num=self.NUM_RUN)
        axes.plot(x, res[0], marker=".", label="[LSW 08] - KP")
        axes.plot(x, res[1], marker="^", label="[YAHK 14] - CP with non-monoton")
        axes.plot(x, res[2], marker="X", label="[LW 14] - CP")
        axes.plot(x, res[3], marker="P", label="[LW 10] - CP hirachical")
        if self.index == 1:
            axes.legend()

    def subplot(self):
        num_cols = self.axes.shape[1]
        col = self.index % num_cols
        row = int(self.index / num_cols)
        ret = self.axes[row, col]
        self.index += 1
        return ret
