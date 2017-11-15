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

use rlp::*;
use util::{Address, U256, H256};
use cita_secp256k1::{PrivKey, PubKey, KeyPair};
use cita_secp256k1::keypair::pubkey_to_address;
use rand::os::OsRng;
use std::collections::HashMap;
use rand::{Rng, thread_rng};

use zktx::pedersen_hash;
use zktx::base::*;
use super::*;
use zktx::p2c::*;
use zktx::c2p::*;

use native::storage::{Serialize, Deserialize};

// Account, complement
#[derive(Default, Debug, Clone, PartialEq)]
pub struct Account {
    pub balance: ([u64;4],[u64;4]), //in homomorphic encrpytion, = vP1+rP2
    pub address: ([u64;4],[u64;4]), //address
    v: [u64;2], //private information: balance
    r: [u64;4], //private information: random number
    sk: Vec<bool>, //private information: secret_key
}


impl Account {
    pub fn new(v:[u64;2],r:[u64;2]) -> Self {
        let rng = &mut thread_rng();
        let sk = (0..ADSK).map(|_| rng.gen()).collect::<Vec<bool>>();
        let address = address(&sk);
        let balance = v_p1_add_r_p2(v,r);
        Account{
            balance,
            address,
            v,
            r:[r[0],r[1],0,0],
            sk
        }
    }

    pub fn get_address(&self)->([u64;4], [u64;4]){
        self.address
    }

    pub fn get_balance(&self)->([u64;4], [u64;4]){
        self.balance
    }

    fn add_balance(&mut self,value:([u64;4], [u64;4])){
        self.balance = ecc_add(self.balance,value);
    }

    fn sub_balance(&mut self,value:([u64;4], [u64;4])){
        self.balance = ecc_sub(self.balance,value);
    }

    fn gen_commitment(&self, v: [u64;2], rcm: [u64;2], address: ([u64;4], [u64;4])) -> CommitmentMsg {
        let rng = &mut thread_rng();
        let enc_random = [rng.gen(),rng.gen(),rng.gen(),rng.gen()];
        let (proof,hb,coin,delt_ba,rp,enc) = p2c_info(self.r,rcm,self.v,v,address,enc_random).unwrap();
        CommitmentMsg {
            proof: proof,
            hb, hb,
            coin: coin,
            delt_ba: delt_ba,
            rp: rp,
            enc: enc,
        }
    }

    fn gen_nullifier(&self, msg: CommitmentMsg) -> NullifierMsg {
        let rng = &mut thread_rng();
        // TODO path和loc目前是随机生成的，后面需要改为coin在Merkle Tree的路径
        let path:Vec<[u64;4]> = (0..TREEDEPTH).map(|_| {
            let mut v:[u64;4] = [0;4];
            for i in 0..4{
                v[i] = rng.gen();
            }
            v
        }).collect();
        let locs:Vec<bool> = (0..TREEDEPTH).map(|_| rng.gen()).collect::<Vec<bool>>();
        let (proof, nullifier, root, delt_ba) = c2p_info(rcm, va, self.sk.clone(), path, locs).unwrap();

        ReceiveMessage{
            proof: proof,
            nullifier: nullifier,
            root: root,
            delt_ba: delt_ba,
        }
    }
}

// Vec<u8> -> Vec<u64>
pub fn u8_2_u64(vec: Vec<u8>) -> Vec<u64> {
    let mut len = vec.len();
    let mut output: Vec<u64> = Vec::new();
    let mut step = 0;
    loop {
        let sl = vec.get(step..step+8).unwrap().into_iter().collect();
        output.push(u8to64(sl));
        step += 8;
        len -= 8;
        if len < 8 {
            break;
        }
    }
    output
}

#[inline(always)]
fn u8to64(nums:[u8;8])->u64{
    let mut res:u64 = 0;
    for i in 0..8{
        res <<=8;
        res |= nums[7-i] as u64;
    }
    res
}
