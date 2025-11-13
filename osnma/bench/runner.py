# Bench runner that times verification with pluggable adapters
# Add as osnma/bench/runner.py

import time
import csv
import argparse
import psutil
import os
from osnma.protocol.registry import get as get_adapter
from osnma.attacks.simulator import AttackChain
# Input module: use SBF reader provided in repo tests
try:
    from osnma.receiver.input_sbf import SBF
except Exception:
    # fallback to ascii input if not available
    from osnma.receiver.input import SBFAscii as SBF

def message_from_data(data):
    """Converts DataFormat-like object into a message bytes for signing/verifying.
    This is a best-effort serializer: adjust to match your 'message' semantics.
    """
    # DataFormat from existing repo exposes nav_bits attribute or similar
    if hasattr(data, 'nav_bits'):
        try:
            return data.nav_bits.tobytes()
        except Exception:
            return bytes(str(data.nav_bits), 'utf8')
    if hasattr(data, 'raw'):
        return data.raw
    # fallback
    return bytes(repr(data), 'utf8')

class BenchRunner:
    def __init__(self, protocol_name, scenario_path, out_csv='bench.csv', attacks=None, max_iter=10000):
        self.protocol_name = protocol_name
        self.scenario_path = scenario_path
        self.out_csv = out_csv
        self.attacks = attacks or AttackChain([])
        self.max_iter = max_iter
        self.adapter_cls = get_adapter(protocol_name)

    def run(self):
        proc = psutil.Process(os.getpid())
        adapter_inst = self.adapter_cls()
        # create test keypair
        try:
            sk, pk_blob, key_id = adapter_inst.keygen()
        except Exception:
            # If adapter.keygen returns serialized public key only, handle gracefully
            sk, pk_blob, key_id = None, None, 'testkey'

        input_module = SBF(self.scenario_path)
        with open(self.out_csv, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['frame_index','t_recv_ns','t_verify_end_ns','latency_ns','result','cpu_user_ms','mem_rss_bytes'])
            for idx, data in input_module:
                if idx >= self.max_iter:
                    break
                msg = message_from_data(data)
                # apply attack chain
                msg = self.attacks.transform(msg)
                t_recv = time.perf_counter_ns()
                t0 = time.perf_counter_ns()
                # sign and verify using adapter (sign optional; this measures verify cost)
                # For timing we sign on-the-fly with the test key to create a signature
                signature = None
                try:
                    signature = adapter_inst.sign(msg, sk) if sk is not None else b''
                except Exception:
                    signature = b''
                result = adapter_inst.verify(msg, signature, pk_blob)
                t1 = time.perf_counter_ns()
                cpu_user = proc.cpu_times().user * 1000.0
                mem = proc.memory_info().rss
                writer.writerow([idx, t_recv, t1, (t1 - t0), int(result), cpu_user, mem])
        print(f'Bench completed. CSV -> {self.out_csv}')

def cli():
    ap = argparse.ArgumentParser()
    ap.add_argument('--protocol', '-p', required=True, help='protocol name (ecdsa, pqc, etc.)')
    ap.add_argument('--scenario', '-s', required=True, help='path to .sbf scenario file')
    ap.add_argument('--out', '-o', default='bench.csv', help='output csv')
    ap.add_argument('--max', type=int, default=1000)
    ap.add_argument('--attack', choices=['none','bitflip','replay','both'], default='none')
    args = ap.parse_args()

    attacks = []
    if args.attack in ('bitflip','both'):
        from osnma.attacks.simulator import BitFlipAttack
        attacks.append(BitFlipAttack(flip_rate=0.0005))
    if args.attack in ('replay','both'):
        from osnma.attacks.simulator import ReplayAttack
        attacks.append(ReplayAttack(probability=0.001))

    runner = BenchRunner(args.protocol, args.scenario, out_csv=args.out, attacks=AttackChain(attacks), max_iter=args.max)
    runner.run()

if __name__ == '__main__':
    cli()
