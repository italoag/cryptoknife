# Changelog

## v0.2.0 - 2026-09-24

### Mudanças incompatíveis

- make integrity checks reliable ([baf67d9](https://github.com/italoag/cryptoknife/commit/baf67d9baccefb8b75c346e6ac82cbb7e70955a7))
  - BREAKING CHANGE: finite Algorithm variants replace bit-size variants; failures return nonzero exit codes, replacement requires --force, and implicit file logging is removed.

### Funcionalidades

- automate semantic versions and changelogs ([a0fe904](https://github.com/italoag/cryptoknife/commit/a0fe904e1ab224f547bc470cd280fee2ad5a248d))

### Correções

- address audit and filesystem review findings ([b0d220f](https://github.com/italoag/cryptoknife/commit/b0d220feaa1d6f35dab707cdb079b81b470fee87))
- resolve RustSec advisories ([ec36f51](https://github.com/italoag/cryptoknife/commit/ec36f51e9c94cbcadb0acd39368b0245e347654d))
- bind publication to trusted workflow inputs ([581f301](https://github.com/italoag/cryptoknife/commit/581f30129ddd372dbfa9097665ab67e0cd02315e))

### Outras alterações

- cryptoknife project migration ([5290718](https://github.com/italoag/cryptoknife/commit/529071823beb840e8cf4cf44735941810725d7fa))
- Add .whitesource configuration file ([a0ad1fa](https://github.com/italoag/cryptoknife/commit/a0ad1fa4be413100ca2545904b3e99a393c47836))
- add whirlpool and kangaroo12 hashes and fix extensions bug ([10346ca](https://github.com/italoag/cryptoknife/commit/10346ca19152333f83102f92aa685f8978a0a578))
- Create rust.yml ([9a1eaff](https://github.com/italoag/cryptoknife/commit/9a1eaff83aea3df1ceb27215e8641135cd53b692))

