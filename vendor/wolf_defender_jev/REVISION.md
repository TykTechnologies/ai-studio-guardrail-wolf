# Vendored: Wolf Defender Jev inference code

- Source: https://huggingface.co/patronus-studio/wolf-defender-jev
- Revision: `5ed7c44d8ee16b0c517952ad58e264e00ec7bbac` (2026-10-17)
- Licence: MIT (`LICENSE`, Copyright (c) 2026 Patronus Protect)
- Files: `wolf_defender_jev.py` (PyTorch) and `wolf_defender_jev_onnx.py`
  (ONNX Runtime), unmodified.

Both scripts were read in full before vendoring. They load safetensors (no
pickle) and build the encoder from its config (no remote code). They make no
network calls when given a local path.

The weights are **not** vendored. They are fetched at the same revision
(image build or `spike/fetch_model.sh`) and checked against these SHA-256
digests:

| File | SHA-256 |
|---|---|
| `model.safetensors` | `617349a97d04f263b4a797bea2ec506e6cba6aad3afe32985fb0368330d31749` |
| `tokenizer.json` | `197d4cc5406ee12cc50c8b5511f2393cc32d9db321545979ce041c1199178356` |
| `tokenizer_config.json` | `ea349495764b24570b4560fe2e4a557e5c0a47e6bce782c2409b1d6445cf8633` |
| `special_tokens_map.json` | `baec30ea10906f16adb8c18af7a34023002c1746542612b8b41c9f09e1351351` |
| `config.json` | `01acd271147e8d5f32482223659a1c0c2d7d6a6355954eee16b56c1906ddcadf` |
| `encoder/config.json` | `503a8785507affe73265784bf626692e503000450cf3abed999f6c4c4af63cfb` |
| `wolf_defender_jev.py` | `6f8ce49c9a6353c78144316c2b2c6ca8fcf73c9f79c341386ce7499b9dacbc46` |
| `wolf_defender_jev_onnx.py` | `c6d3afda449c85c8763d48b9e5b2328861bfcb058fa4505e36780d12ed61237b` |
| `onnx/onnx_fp32/model.onnx` | `159fe2d3f77b33093823e687a088b66d1425c3892a24ea5c77c30d4622ccab3c` |

`onnx/onnx_fp32/model.onnx` matches `source_fp32_graph.sha256` in the repo's
`onnx/quantization_manifest.json`, which records that it was exported from
revision `b9a3ccf6`.

The spike only measured the quantized variants (`onnx/onnx_mixed`
`17c1ea7b…`, `onnx/int8_int4_embeddings` `74f89578…`). They are not
fetched by default and not used; see `spike/RESULTS.md`.
