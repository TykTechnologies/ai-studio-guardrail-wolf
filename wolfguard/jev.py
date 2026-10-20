"""The Wolf Defender Jev backend (vendored inference code, PyTorch fp32).

    backend = JevBackend("/models/jev-5ed7c44d", threads=2)               # CPU
    backend = JevBackend("/models/jev-5ed7c44d", device="cuda")           # a GPU (WOLFGUARD_DEVICE)

On a GPU the model stays fp32 with TF32 off, so its scores match the CPU's
(checked on the eval sets: bench/parity.py, docs/BENCHMARKS.md).

One forward() is one encoder pass over a batch of (scene, question) rows: the
vendored encode_scene's computation row by row (checked against the vendored
decide in tests/test_jev_integration.py), with each question's option
vectors encoded once in prepare().
"""
from __future__ import annotations

import sys
from pathlib import Path

VENDOR = Path(__file__).resolve().parents[1] / "vendor" / "wolf_defender_jev"


class JevBackend:
    def __init__(self, model_dir: str | Path, threads: int | None = None, revision: str = "", device: str = "cpu"):
        import torch
        if str(VENDOR) not in sys.path:
            sys.path.insert(0, str(VENDOR))
        from wolf_defender_jev import TOK_CASE, TOK_QUESTION, WolfDefenderJev
        if threads:
            torch.set_num_threads(threads)
            try:
                torch.set_num_interop_threads(1)
            except RuntimeError:
                pass  # already set in this process
        self.torch = torch
        self.device = torch.device(device or "cpu")
        if self.device.type == "cuda":
            torch.backends.cuda.matmul.allow_tf32 = False
            torch.backends.cudnn.allow_tf32 = False
        self.model = WolfDefenderJev.from_pretrained(str(model_dir))
        if self.device.type != "cpu":
            self.model.to(self.device)
        self.tok = self.model.tokenizer
        self.case, self.qtok = TOK_CASE, TOK_QUESTION
        self.revision = revision or Path(model_dir).name

    def tokenize(self, text: str) -> list[int]:
        return self.tok(text, add_special_tokens=False)["input_ids"]

    def detokenize(self, ids: list[int]) -> str:
        return self.tok.decode(ids)

    def prepare(self, question):
        q_ids = self.model._ids(question.instructions, self.model.max_q)
        with self.torch.no_grad():
            opts = self.model.encode_options(list(question.option_texts))
        return (q_ids, opts.to(self.device) if hasattr(opts, "to") else opts)

    def forward(self, rows):
        torch, m = self.torch, self.model
        bos, eos = self.tok.bos_token_id, self.tok.eos_token_id
        seqs, qpos = [], []
        for scene, (q_ids, _) in rows:
            c = m._ids(scene, m.max_case, keep_tail=True)
            seqs.append([bos, self.case] + c + [eos, self.qtok] + q_ids + [eos])
            qpos.append(len(c) + 3)
        L = max(map(len, seqs))
        with torch.no_grad():
            x = torch.zeros(len(seqs), L, dtype=torch.long)
            mask = torch.zeros(len(seqs), L, dtype=torch.bool)
            for i, s in enumerate(seqs):
                x[i, : len(s)] = torch.tensor(s)
                mask[i, : len(s)] = True
            x, mask = x.to(self.device), mask.to(self.device)
            h = m.encoder(input_ids=x, attention_mask=mask.long()).last_hidden_state
            qp = torch.tensor(qpos, device=self.device)
            r = torch.arange(len(seqs), device=self.device)
            pool = mask.clone()
            pool[:, 1] = False
            pool[r, qp] = False
            s = m.state_head(m.readout(h, pool, qp) + m.o_tok(torch.cat([h[:, 1], h[r, qp]], -1)))
            out = []
            for i, (_, (_, opts)) in enumerate(rows):
                out.append(m.scorer(s[i : i + 1], opts[None]).float()[0].softmax(0).tolist())
        return out
