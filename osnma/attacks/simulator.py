# Simple attack simulator transforms
# Add as osnma/attacks/simulator.py

import random
from typing import List

class Attack:
    def transform(self, message: bytes) -> bytes:
        return message

class BitFlipAttack(Attack):
    def __init__(self, flip_rate=0.0005):
        self.flip_rate = flip_rate

    def transform(self, message: bytes) -> bytes:
        b = bytearray(message)
        for i in range(len(b)):
            if random.random() < self.flip_rate:
                bit = 1 << random.randint(0,7)
                b[i] ^= bit
        return bytes(b)

class ReplayAttack(Attack):
    def __init__(self, probability=0.001):
        self.prob = probability
        self.cache = []

    def transform(self, message: bytes) -> bytes:
        self.cache.append(message)
        if self.cache and random.random() < self.prob:
            return random.choice(self.cache)
        return message

class AttackChain:
    def __init__(self, attacks: List[Attack]=None):
        self.attacks = attacks or []

    def transform(self, message: bytes) -> bytes:
        m = message
        for a in self.attacks:
            m = a.transform(m)
        return m
