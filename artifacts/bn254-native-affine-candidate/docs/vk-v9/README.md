# Fixed-VK/native-table certificate v9

The packet-local `native-artifact.json` is the public C/R/native catalog needed
by the IO-only wrapper. A safe static invocation is:

```text
python3 artifacts/bn254-native-affine-candidate/docs/vk-v9/check_public_certificate.py \
  --bundle artifacts/bn254-native-affine-candidate/docs/vk-v9/native-artifact.json \
  --fixture artifacts/bn254-native-affine-candidate/source/chunked/bn254/densless-recovered/public-fixtures.json \
  --positive-vectors src/bch/bch-groth16-bn254-sound-native-affine-candidate-positive-vectors.json \
  --certificate-inputs artifacts/bn254-native-affine-candidate/docs/vk-v9/certificate-inputs.json
```

This command is a maintainer-owned certificate action and was not run during
assembly. `codec_v8.py` is the reviewed native/body/table/GLS decoder; private
provenance and receipt files are not shipped. Raw Miller relation, VM/compiler
semantics, resource, qualification, and admission remain separate claims.
