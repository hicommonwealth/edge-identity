// Copyright 2018 Commonwealth Labs, Inc.
// This file is part of Edgeware.

// Edgeware is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Edgeware is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Edgeware.  If not, see <http://www.gnu.org/licenses/>.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
extern crate serde;

// Needed for deriving `Serialize` and `Deserialize` for various types.
// We only implement the serde traits for std builds - they're unneeded
// in the wasm runtime.
#[cfg(feature = "std")]
#[macro_use]
extern crate serde_derive;
#[cfg(test)]
#[macro_use]
extern crate hex_literal;
#[macro_use] extern crate parity_codec_derive;
#[macro_use] extern crate srml_support;


extern crate parity_codec as codec;
extern crate substrate_primitives as primitives;
#[cfg_attr(not(feature = "std"), macro_use)]
extern crate sr_std as rstd;
extern crate srml_support as runtime_support;
extern crate sr_primitives as runtime_primitives;
extern crate sr_io as runtime_io;

extern crate srml_system as system;

use rstd::prelude::*;
use runtime_support::dispatch::Result;
use primitives::ed25519;

pub mod identity;
use identity::{Module, Trait};

#[cfg(test)]
mod tests {
    use super::*;
    use runtime_io::with_externalities;
    use runtime_io::ed25519::Pair;
    use primitives::{H256, Blake2Hasher, Hasher};
    // The testing primitives are very useful for avoiding having to work with signatures
    // or public keys. `u64` is used as the `AccountId` and no `Signature`s are requried.
    use runtime_primitives::{
        BuildStorage, traits::{BlakeTwo256}, testing::{Digest, DigestItem, Header}
    };


    impl_outer_origin! {
        pub enum Origin for Test {}
    }

    impl_outer_event! {
        pub enum Event for Test {
            identity<T>,
        }
    }

    impl_outer_dispatch! {
        pub enum Call for Test where origin: Origin {}
    }

    // For testing the module, we construct most of a mock runtime. This means
    // first constructing a configuration type (`Test`) which `impl`s each of the
    // configuration traits of modules we want to use.
    #[derive(Clone, Eq, PartialEq)]
    pub struct Test;
    impl system::Trait for Test {
        type Origin = Origin;
        type Index = u64;
        type BlockNumber = u64;
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type Digest = Digest;
        type AccountId = H256;
        type Header = Header;
        type Event = Event;
        type Log = DigestItem;
    }

    impl Trait for Test {
        type Identity = Vec<u8>;
        type Event = Event;
    }

    type System = system::Module<Test>;
    type Identity = Module<Test>;

    // This function basically just builds a genesis storage key/value store according to
    // our desired mockup.
    fn new_test_ext() -> sr_io::TestExternalities<Blake2Hasher> {
        let t = system::GenesisConfig::<Test>::default().build_storage().unwrap().0;
        // We use default for brevity, but you can configure as desired if needed.
        t.into()
    }

    fn publish_identity_attestation(who: H256, message: &[u8], sig_hash: ed25519::Signature) -> super::Result {
        Identity::publish(Origin::signed(who), message.to_vec(), sig_hash)
    }

    #[test]
    fn propose_with_valid_sig_should_work() {
        with_externalities(&mut new_test_ext(), || {
            System::set_block_number(1);

            let pair: Pair = Pair::from_seed(&hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
            let message: &[u8] = b"github.com/drewstone";
            let hash: [u8; 32] = <[u8; 32]>::from(Blake2Hasher::hash(message));
            let signature = pair.sign(&hash);
            let public: H256 = pair.public().0.into();

            // verify_strong(&signature, &message[..], &public);

            // println!("\n\n
            //         OK:     {:?}
            //         PK:     {:?}
            //         MSG:    {:?}
            //         HASH:   {:?}
            //         SIG:    {:?}
            //     \n\n",
            //     ed25519::verify_strong(&signature, &hash, &pair.public()),
            //     pair.public(),
            //     message,
            //     hash,
            //     signature);

            assert_ok!(publish_identity_attestation(public, message, signature));
            println!("{:?}", System::events());
        });
    }
}