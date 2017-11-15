// CITA
// Copyright 2016-2017 Cryptape Technologies LLC.

// This program is free software: you can redistribute it
// and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any
// later version.

// This program is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use native::storage::{Serialize, Deserialize};
use util::*;
use evm::Error as EvmError;

pub struct Proof (
    ([u64; 6], [u64; 6], bool),
    (([u64; 6], [u64; 6]), ([u64; 6], [u64; 6]), bool),
    ([u64; 6], [u64; 6], bool)
);

impl Serialize for Proof {
    fn serialize(&self) -> Result<Vec<u8>, EvmError> {
        let mut vec: Vec<u8> = Vec::new();
        let bal = self.0;
        let bal_next = self.1;
        let hash = self.2;

        let mut target = [0u8; 8];
        for x in bal.0 {
            x.to_big_endian(&mut target);
            vec.extend(target.iter().cloned());
        }
        for x in bal.1 {
            x.to_big_endian(&mut target);
            vec.extend(target.iter().cloned());
        }
        for x in (bal_next.0).0 {
            x.to_big_endian(&mut target);
            vec.extend(target.iter().cloned());
        }
        for x in (bal_next.0).1 {
            x.to_big_endian(&mut target);
            vec.extend(target.iter().cloned());
        }
        for x in (bal_next.1).0 {
            x.to_big_endian(&mut target);
            vec.extend(target.iter().cloned());
        }
        for x in (bal_next.1).1 {
            x.to_big_endian(&mut target);
            vec.extend(target.iter().cloned());
        }
        for x in hash.0 {
            x.to_big_endian(&mut target);
            vec.extend(target.iter().cloned());
        }
        for x in hash.1 {
            x.to_big_endian(&mut target);
            vec.extend(target.iter().cloned());
        }

        if bal.2 {
            vec.push(1u8);
        } else {
            vec.push(0u8);
        }
        if bal_next.2 {
            vec.push(1u8);
        } else {
            vec.push(0u8);
        }
        if hash.2 {
            vec.push(1u8);
        } else {
            vec.push(0u8);
        }

        Ok(vec)
    }
}

impl Deserialize for Proof {
    fn deserialize(bytes: &Vec<u8>) -> Result<Self, EvmError> {
        let mut bytes_clone = bytes.clone();
        let bool1 = match bytes_clone.pop() {
            Some(0) => false,
            _ => true,
        };

        let bool2 = match bytes_clone.pop() {
            Some(0) => false,
            _ => true,
        };

        let bool3 = match bytes_clone.pop() {
            Some(0) => false,
            _ => true,
        };

        let mut vec_sum: Vec<u64> = u8_2_u64(bytes);
        let mut vec1: Vec<u64> = Vec::new();
        let mut vec2: Vec<u64> = Vec::new();
        let mut vec3: Vec<u64> = Vec::new();
        let mut vec4: Vec<u64> = Vec::new();
        let mut vec5: Vec<u64> = Vec::new();
        let mut vec6: Vec<u64> = Vec::new();
        let mut vec7: Vec<u64> = Vec::new();
        let mut vec8: Vec<u64> = Vec::new();

        for i in 0..vec_sum.len() {
            match i {
                0 ... 6 => vec1.push(vec_sum.get(i)),
                6 ... 12 => vec2.push(vec_sum.get(i)),
                12 ... 18 => vec3.push(vec_sum.get(i)),
                18 ... 24 => vec4.push(vec_sum.get(i)),
                24 ... 30 => vec5.push(vec_sum.get(i)),
                30 ... 36 => vec6.push(vec_sum.get(i)),
                36 ... 42 => vec7.push(vec_sum.get(i)),
                _ => vec8.push(vec_sum.get(i)),
            }
        }

        let proof = Proof(
            (vec1, vec2, bool1),
            ((vec3, vec4), (vec5, vec6), bool2),
            (vec7, vec8, bool3),
        );
        Ok(proof)
    }
}
