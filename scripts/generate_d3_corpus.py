"""
scripts/generate_d3_corpus.py
================================

Tạo data/D3_signatures.csv từ signatures/base_signer.py +
signatures/vulnerable_signer.py, tính ground-truth repeated_r, QA bằng
signatures/nonce_reuse_attacker.py, rồi mới ghi CSV.

Chạy: python3 scripts/generate_d3_corpus.py   (từ project-root)

Yêu cầu: project-root/{signatures/base_signer.py,
                       signatures/vulnerable_signer.py,
                       signatures/nonce_reuse_attacker.py,
                       data/schema_definition.json}
"""

import sys
import os
import csv
import secrets
import uuid

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
sys.path.insert(0, _PROJECT_ROOT)

from signatures.base_signer import (
    BaseECDSASigner, RandomNonceStrategy, new_lab_key_id, get_git_commit,
)
from signatures.vulnerable_signer import make_vulnerable_signer
from signatures.nonce_reuse_attacker import recover_private_key

CURVE = "P-256"
OUT_PATH = os.path.join(_PROJECT_ROOT, "data", "D3_signatures.csv")

FIELDNAMES = [
    "sig_id", "run_id", "key_id", "curve", "signer_version", "nonce_class",
    "msg_hash", "r", "s", "sig_index", "repeated_r", "repeated_r_group_id",
    "leaked_bits_class", "jti", "source", "seed", "timestamp", "git_commit",
]

# (run_id, mode, n_sigs hoặc None nếu mode='reuse_restart', strategy_kwargs)
RUNS = [
    ("run-c-ctrl-random",   "random_ok",      50,   {}),
    ("run-c-f1-constant",   "reuse_constant", 25,   {"seed": 101}),
    ("run-c-f2-restart",    "reuse_restart",  None, {"seed_space_bits": 3, "seed": 202}),
    ("run-c-f3-sparse",     "reuse_sparse",   70,   {"rho": 0.3, "seed": 303}),
    ("run-c-f4-lowentropy", "low_entropy",    90,   {"entropy_bits": 12, "seed": 404}),
]
RESTART_EPOCHS = 18      # > 2^seed_space_bits=8 -> chắc chắn có trùng (chuồng bồ câu)
RESTART_SIGS_PER_EPOCH = 2


def _gen_msg(run_id: str, idx: int) -> bytes:
    return f"{run_id}:{idx}:{secrets.token_hex(4)}".encode()


def _make_signer(mode: str, key_id: str, d_true: int, kwargs: dict):
    if mode == "random_ok":
        return BaseECDSASigner(curve=CURVE, private_key=d_true, key_id=key_id,
                                signer_version="random_ok", nonce_strategy=RandomNonceStrategy())
    return make_vulnerable_signer(mode, curve=CURVE, private_key=d_true, key_id=key_id,
                                   strategy_kwargs=kwargs)


def collect_run(run_id: str, mode: str, n_sigs, kwargs: dict):
    d_true = secrets.randbelow(2 ** 256)
    key_id = new_lab_key_id("ctrl" if mode == "random_ok" else mode)
    signer = _make_signer(mode, key_id, d_true, kwargs)

    sigs = []
    if mode == "reuse_restart":
        idx = 0
        strat = signer.nonce_strategy
        for epoch in range(RESTART_EPOCHS):
            if epoch > 0:
                strat.restart()
            for _ in range(RESTART_SIGS_PER_EPOCH):
                sig = signer.sign(_gen_msg(run_id, idx))
                sigs.append((idx, sig))
                idx += 1
    else:
        for idx in range(n_sigs):
            sig = signer.sign(_gen_msg(run_id, idx))
            sigs.append((idx, sig))

    return key_id, d_true, signer, sigs


def ground_truth_rows(run_id: str, sigs, git_commit: str, seed_tag: int):
    """Nhóm theo r THỰC TẾ quan sát được trong batch này -> gán repeated_r."""
    groups = {}
    for idx, sig in sigs:
        groups.setdefault(sig.r, []).append((idx, sig))

    rows = []
    for members in groups.values():
        group_id = f"grp-{uuid.uuid4().hex[:10]}" if len(members) >= 2 else None
        for idx, sig in members:
            rows.append(sig.to_d3_record(
                run_id=run_id, sig_index=idx, source="synthetic_corpus",
                seed=seed_tag, git_commit=git_commit,
                repeated_r=(len(members) >= 2),
                repeated_r_group_id=group_id, leaked_bits_class=None,
            ))
    return rows


def qa_check(run_id: str, mode: str, signer, sigs, d_true: int) -> bool:
    if mode == "random_ok":
        r_seen = {}
        for _, sig in sigs:
            r_seen[sig.r] = r_seen.get(sig.r, 0) + 1
        dup = {r: c for r, c in r_seen.items() if c > 1}
        print(f"  [{run_id}] control random_ok: so nhom r trung = {len(dup)} (ky vong 0)")
        return len(dup) == 0

    sig_objs = [s for _, s in sigs]
    res = recover_private_key(signer.curve, sig_objs, public_key=signer.public_key)
    ok = bool(res.success and res.d == d_true and res.verified_by_public_key)
    print(f"  [{run_id}] mode={mode:16s} recovered_d_correct={ok} "
          f"(groups={res.groups_examined}, pairs={res.pairs_examined})")
    return ok


def main() -> None:
    git_commit = get_git_commit()
    all_rows = []
    qa_all_ok = True

    print("== Sinh corpus ==")
    for run_id, mode, n_sigs, kwargs in RUNS:
        key_id, d_true, signer, sigs = collect_run(run_id, mode, n_sigs, kwargs)
        print(f"  {run_id:24s} mode={mode:16s} key_id={key_id:28s} n_sigs={len(sigs)}")
        rows = ground_truth_rows(run_id, sigs, git_commit, seed_tag=abs(hash(run_id)) % (2**31))
        all_rows.extend(rows)

        print("  QA:", end=" ")
        if not qa_check(run_id, mode, signer, sigs, d_true):
            qa_all_ok = False

    print(f"\nTong so dong: {len(all_rows)}  |  repeated_r=True: "
          f"{sum(1 for r in all_rows if r['repeated_r'])}")

    if not qa_all_ok:
        raise SystemExit("QA THAT BAI -- khong ghi file. Kiem tra lai generator truoc khi chay lai.")

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDNAMES)
        w.writeheader()
        w.writerows(all_rows)

    print(f"\nQA PASS. Da ghi {len(all_rows)} dong vao {OUT_PATH}")


if __name__ == "__main__":
    main()