import unittest
import time, sys

from charm.test.benchmark.wrappers.dacmacs_wrapper import DACMACS_Wrapper, MAABEBenchmarkWrapper
from charm.test.benchmark.wrappers.tfdacmacs_wrapper import TFDACMACS_Wrapper
from charm.toolbox.pairinggroup import PairingGroup, GT

import matplotlib.pyplot as plt
import numpy as np


class BenchmarkTest1(unittest.TestCase):
    NUM_RUN = 30
    index = 0

    def prepare(self):
        self.fig, self.axes = plt.subplots(3, 3, figsize=(16, 16))

        self.schemes = [
            TFDACMACS_Wrapper(),
            DACMACS_Wrapper()
        ]

        self.message = self.schemes[0].group.random(GT)

    def _generate_attributes(self, i, auth_id):
        return [auth_id + "." + str(a) for a in range(0, i + 1)]

    def _init_list(self):
        res = list()
        for _ in self.schemes:
            res.append(list())
        return res

    def _user_id(self, j):
        return "userId" + str(j)

    def _auth_id(self, j):
        return "AUTHORITYID" + str(j)

    def benchmarkSetup(self):
        res = self._init_list()
        for i in range(0, self.NUM_RUN):
            for j, tc in enumerate(self.schemes):
                res[j].append(tc.measure_setup())

        self.plot(res, "Setup", xlable="# of runs")

    def benchmarkAuthoritySetup(self):
        res = self._init_list()
        authkey_length = self._init_list()

        for i in range(0, self.NUM_RUN):
            for j, tc in enumerate(self.schemes):
                auth_id = self._auth_id(j)
                attributes = self._generate_attributes(i, auth_id)
                res[j].append(tc.measure_authsetup(attributes, auth_id))
                authkey_length[j].append(tc.getSizeOfAuth(auth_id))

        self.plot(res, "Authority setup", xlable="# of attributes")
        self.plot(authkey_length, "Authority key length", ylabel="Size in bytes")

    def benchmarkRegisterUser(self):
        res = self._init_list()

        for i in range(0, self.NUM_RUN):
            for j, tc in enumerate(self.schemes):
                user_id = self._user_id(j)
                res[j].append(tc.measure_registerUser(user_id))

        self.plot(res, "Register user")

    def benchmarkKeygen(self):
        res = self._init_list()
        keygens_length = self._init_list()

        for i in range(0, self.NUM_RUN):
            for j, tc in enumerate(self.schemes):
                auth_id = self._auth_id(j)
                user_id = self._user_id(j)
                attributes = self._generate_attributes(i, auth_id)
                res[j].append(tc.measure_keygen(attributes, user_id, auth_id))
                keygens_length[j].append(tc.getSizeOfUser(user_id))

        self.plot(res, "Keygen")
        self.plot(keygens_length, "User key length", ylabel="Size in bytes")

    def benchmarkEncrypt(self):
        res = self._init_list()
        ciphertext_length = self._init_list()

        for i in range(0, self.NUM_RUN):
            for j, tc in enumerate(self.schemes):
                auth_id = self._auth_id(j)
                policy = " and ".join(self._generate_attributes(i, auth_id))
                res[j].append(tc.measure_encrypt(policy, self.message))
                ciphertext_length[j].append(tc.getSizeOfCT())

        self.plot(res, "Encrypt")
        self.plot(ciphertext_length, "Ciphertext length", ylabel="Size in bytes")

    def benchmarkDecrypt(self):
        res = self._init_list()

        for i in range(0, self.NUM_RUN):
            for j, tc in enumerate(self.schemes):
                user_id = self._user_id(j)
                res[j].append(tc.measure_decrypt(user_id))

        self.plot(res, "Decrypt")

    def testall(self):
        self.prepare()
        self.benchmarkSetup()
        self.benchmarkAuthoritySetup()
        self.benchmarkRegisterUser()
        self.benchmarkKeygen()
        self.benchmarkEncrypt()
        self.benchmarkDecrypt()
        plt.show()

    def plot(self,
             res,
             title,
             ylabel="time in s",
             xlable="# of attributes"):
        axes = self.subplot()
        res = np.array(res)
        axes.set_title(title, fontweight="bold")
        axes.set_ylabel(ylabel)
        axes.set_xlabel(xlable)
        x = np.linspace(1, self.NUM_RUN, num=self.NUM_RUN)
        axes.plot(x, res[0], marker=".", label="[LTXWC 16] - TF-DAC-MACS")
        axes.plot(x, res[1], marker="^", label="[YJ 14] - DAC-MACS")
        # axes.plot(x, res[2], marker="X", label="[LW 14] - CP")
        # axes.plot(x, res[3], marker="P", label="[WLWG 11] - CP multi-authority")
        if self.index == 1:
            axes.legend()

    def subplot(self):
        num_cols = self.axes.shape[1]
        col = self.index % num_cols
        row = int(self.index / num_cols)
        ret = self.axes[row, col]
        self.index += 1
        return ret
