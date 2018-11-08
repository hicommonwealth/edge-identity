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

extern crate parity_codec as codec;
extern crate substrate_primitives as primitives;
#[cfg_attr(not(feature = "std"), macro_use)]
extern crate sr_std as rstd;
extern crate srml_support as runtime_support;
extern crate sr_primitives as runtime_primitives;
extern crate sr_io as runtime_io;

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

        pub fn link(origin, identity: T::Identity, proof_link: LinkedProof) -> Result {
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

        pub fn publish(origin, identity: T::Identity, signature: ed25519::Signature) -> Result {
            let _sender = ensure_signed(origin)?;

            unsafe {
                let sender: [u8; 32] = std::mem::transmute_copy(&_sender);
                let public = ed25519::Public(sender.into());
                let message: Vec<u8> = std::mem::transmute_copy(&identity);

                let hash_obj = T::Hashing::hash(&message[..]);
                let hash: [u8; 32] = std::mem::transmute_copy(&hash_obj);

                // println!("\n\n
                //         OK:     {:?}
                //         PK:     {:?}
                //         MSG:    {:?}
                //         HASH:   {:?}
                //         SIG:    {:?}
                //     \n\n",
                //     ed25519::verify_strong(&signature, &hash, &public),
                //     public,
                //     message,
                //     hash,
                //     signature);

                // Check the signature of the hash of the external identity
                if ed25519::verify_strong(&signature, &hash, &public) {
                    // Check existence of identity
                    ensure!(!<IdentityOf<T>>::exists(hash_obj), "duplicate identities not allowed");

                    // println!("\n           MODULE LEVEL LOGGING             \n
                    //         OK:     {:?}
                    //         PK:     {:?}
                    //         MSG:    {:?}
                    //         HASH:   {:?}
                    //         SIG:    {:?}
                    //     \n\n",
                    //     ed25519::verify_strong(&signature, &hash, &public),
                    //     public,
                    //     message,
                    //     hash,
                    //     signature);

                    let index = Self::identity_count();
                    let mut idents = Self::identities();
                    idents.push(hash_obj);
                    <Identities<T>>::put(idents);

                    <IdentityOf<T>>::insert(hash_obj, (index, _sender.clone(), None));
                    Self::deposit_event(RawEvent::Published(hash_obj, index, _sender.clone().into()));
                    return Ok(());
                }

                Err("Some error")
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
