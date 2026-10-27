# SupplyChainGate
CycloneDX JSON SBOM policy gate: blocked packages, license rules, required hashes, dependency diffs.

## Usage
```sh
python supplygate.py examples/sbom.json --policy examples/policy.json
python -m unittest discover -s tests -v
```
Exit 0 on pass, 1 on violation, 2 on invalid input. Optional `--previous` compares SBOMs. This tool does not provide vulnerability intelligence or full CycloneDX validation.
