# edge_identity
This module contains the api for registering and linking identities on Edgeware. Users will register hashes of identities, providing a signature that they have also signed such a hash. In addition, this module enables claims issuers who are fed into the system at the genesis block to issue claims over identities and remove such claims.

# Setup
Install rust or update to the latest versions.
```
curl https://sh.rustup.rs -sSf | sh
rustup update nightly
rustup target add wasm32-unknown-unknown --toolchain nightly
rustup update stable
cargo install --git https://github.com/alexcrichton/wasm-gc
```

You will also need to install the following packages:

Linux:
```
sudo apt install cmake pkg-config libssl-dev git
```

Mac:
```
brew install cmake pkg-config openssl git
```