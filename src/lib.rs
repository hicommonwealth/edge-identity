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
extern crate hex_literal;

extern crate parity_codec as codec;
#[macro_use] extern crate parity_codec_derive;
extern crate substrate_primitives as primitives;
#[cfg_attr(not(feature = "std"), macro_use)]
extern crate sr_std as rstd;
extern crate srml_support as runtime_support;
extern crate sr_primitives as runtime_primitives;
extern crate sr_io as runtime_io;

#[macro_use] extern crate srml_support;
extern crate srml_balances as balances;
extern crate srml_system as system;

use runtime_primitives::traits::{Hash, MaybeSerializeDebug};
use rstd::prelude::*;
use system::ensure_signed;
use runtime_support::{StorageValue, StorageMap, Parameter};
use runtime_support::dispatch::Result;
use primitives::ed25519;

/// An identity index.
pub type IdentityIndex = u32;

pub trait Trait: system::Trait {
    /// The identity type
    type Identity: Parameter + MaybeSerializeDebug;
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

pub type LinkedProof = Option<Vec<u8>>;

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        fn link(origin, identity: T::Identity, proof_link: LinkedProof) -> Result {
            let _sender = ensure_signed(origin)?;
            let hashed_identity = T::Hashing::hash_of(&identity).into();

            // Check if the identities match the sender
            let (index, account, proof) = match <IdentityOf<T>>::get(hashed_identity) {
                Some((index, account, proof)) => (index, account, proof),
                None => (std::u32::MAX, _sender.clone(), None),
            };

            // TODO: Decide how we want to process proof updates
            // currently this implements no check against updating
            // proof links
            if account == _sender.clone() {
                if !proof.is_some() {
                    let link_count = Self::linked_count();
                    <LinkedIdentityCount<T>>::put(link_count + 1);
                };

                <IdentityOf<T>>::insert(hashed_identity, (index, _sender.clone(), proof_link));
                Self::deposit_event(RawEvent::Linked(hashed_identity, index, account));
            }

            Ok(())
        }

        fn publish(origin, identity: T::Identity, sig: ed25519::Signature) -> Result {
            let _sender = ensure_signed(origin)?;

            unsafe {
                let sender: [u8; 32] = std::mem::transmute_copy(&_sender);
                let public = ed25519::Public(sender.into());
                let hashed_identity = T::Hashing::hash_of(&identity);

                let formatted_hash: [u8; 32] = std::mem::transmute_copy(&hashed_identity);

                // Check the signature of the hash of the external identity
                if ed25519::verify_strong(&sig, &formatted_hash[..], public) {
                    // Check existence of identity
                    ensure!(!<IdentityOf<T>>::exists(hashed_identity), "duplicate identities not allowed");

                    let index = Self::identity_count();
                    let mut idents = Self::identities();
                    idents.push(hashed_identity);
                    <Identities<T>>::put(idents);

                    <IdentityOf<T>>::insert(hashed_identity, (index, _sender.clone(), None));
                    Self::deposit_event(RawEvent::Published(hashed_identity, index, _sender.clone().into()));
                }

                Ok(())
            }
        }
    }
}

/// An event in this module.
decl_event!(
    pub enum Event<T> where <T as system::Trait>::Hash, <T as system::Trait>::AccountId {
        Published(Hash, IdentityIndex, AccountId),
        Linked(Hash, IdentityIndex, AccountId),
    }
);

decl_storage! {
    trait Store for Module<T: Trait> as IdentityStorage {
        /// The number of identities that have been added.
        pub IdentityCount get(identity_count) build(|_| 0 as IdentityIndex) : IdentityIndex;
        /// The hashed identities.
        pub Identities get(identities): Vec<(T::Hash)>;
        /// Actual identity for a given hash, if it's current.
        pub IdentityOf get(identity_of): map T::Hash => Option<(IdentityIndex, T::AccountId, LinkedProof)>;
        /// The number of linked identities that have been added.
        pub LinkedIdentityCount get(linked_count) build(|_| 0 as IdentityIndex) : IdentityIndex;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use system::GenesisConfig;

    use runtime_io::with_externalities;
    use primitives::{H256, Blake2Hasher};
    // The testing primitives are very useful for avoiding having to work with signatures
    // or public keys. `u64` is used as the `AccountId` and no `Signature`s are requried.
    use runtime_primitives::{
        BuildStorage, traits::{BlakeTwo256, OnFinalise}, testing::{Digest, DigestItem, Header}
    };

    impl_outer_origin! {
        pub enum Origin for Test {}
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
        type Event = ();
        type Log = DigestItem;
    }

    impl Trait for Test {
        type Identity = Vec<u8>;
        type Event = ();
    }

    type Identity = Module<Test>;

    // This function basically just builds a genesis storage key/value store according to
    // our desired mockup.
    fn new_test_ext() -> sr_io::TestExternalities<Blake2Hasher> {
        let mut t = system::GenesisConfig::<Test>::default().build_storage().unwrap().0;
        // We use default for brevity, but you can configure as desired if needed.
        t.into()
    }
}