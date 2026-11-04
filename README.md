# Coverage boundaries of machine learning model loading defenses

## Review evidence and reproducibility

This repository supports a critical review comparing the coverage boundaries of machine-learning model loading defenses. The research corpus comprises **24 purposively selected sources**: six research papers, one public security assessment, and seventeen official technical documents. The manuscript synthesizes their stated protection targets, activation conditions, residual scope, and policy limitations.

The accompanying **12 local benign NumPy checks** probe object-versus-numeric arrays, `.npy` / `.npz` formats, and `allow_pickle` settings. The outcome categories are: **8 successful accesses, 2 load-stage blocks, 2 access-stage blocks**. These are benign controls, *not* exploit tests, scanner-performance benchmarks, demonstrations of remote code execution, or proofs of universal loader security.

### Evidence map
- `evidence/source_extraction.json` and `.csv` — source-level assessment records and source identifiers.
- `evidence/references.json` and `doi_verification.json` — bibliographic and DOI evidence.
- `evidence/discovery_queries.json` and `Search_and_Selection.md` — discovery and purposive-selection records.
- `evidence/tables.json` — four manuscript comparison tables.
- `evidence/benign_loader_results.json` — twelve benign local checks.
- `code/benign_loader_checks.py` and `code/verify_supplement.py` — reproducibility and consistency checks.
- `Model_Loading_Supplement_Anonymous.zip` — the supplementary evidence archive used for the journal submission.

**Availability notice:** An item listed above is only public once it appears in the actual repository tree. The repository extraction workflow automatically populates the evidence tree once the supplementary ZIP is uploaded.

### Reproduce
Run in a controlled, isolated Python 3.12 environment:
```bash
python -m pip install -r requirements.txt
python code/verify_supplement.py
```
All example fixtures are locally generated and benign; no malicious payloads or third-party model weights are included. Some reviewed documentation is version-specific. Full third-party articles are not redistributed.

### Limitations
The source selection is purposive, not an exhaustive systematic census. Extraction and drafting were AI-assisted; source-level interpretations were not independently human-adjudicated. Recorded source hashes refer to original retrievals and cannot be independently recomputed without the original bytes.

### Double-anonymous review
**Warning:** This repository is owned by a personally identifying GitHub account. A direct URL to it can compromise double-anonymous peer review even if file bodies contain no author names. Do not provide its direct URL to anonymous reviewers. The journal's portal handles authorship separately; use an author-blind evidence link only after confirming the journal permits it.
