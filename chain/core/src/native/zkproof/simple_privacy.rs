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

use util::{Address, H160, U256};
use super::account::{Account, Proof};
use native::storage::*;
use evm::{self, Ext, GasLeft, Error as EvmError};
use bincode::Infinite;
use bincode::internal::deserialize_from;
use bincode::internal::serialize_into;
use super::*;
use zktx::p2c::*;
use zktx::base::*;
use zktx::c2p::*;

pub struct Privacy {
    accounts: Map,        //  address -> balance   H160->U256
    nullifiers: Map,  //  nullifier -> address   U256 -> H160
    commitments: Map,    // commitment -> address   U256 -> H160
    output: Vec<u8>,
}

impl Privacy {
    // data[0..4]: func sig;
    // data[4..36]: address, data[36..68]: account balance
    fn set_accounts(&mut self, params: ActionParams, ext: &mut Ext) -> Result<GasLeft, evm::Error> {
        let data = params.data.expect("invalid data");
        let mut pilot = 4;
        let address = H160::from(data.get(pilot + 12 .. pilot + 32).expect("not enough data"));
        pliot += 32;
        let bal = data.get(pilot .. pilot + 32).expect("not enough data");
        self.accounts.set(ext, address, bal);
        Ok(GasLeft::Known(U256::from(100)))
    }

    // data[4..36]: address, like 00000000000031415926535897932384
    fn get_balance(&mut self, params: ActionParams, ext: &mut Ext) -> Result<GasLeft, evm::Error> {
        let data = params.data.expect("invalid data");
        let address = H160::from(data.get(16..36).expect("not enough data"));
        for i in self.accounts.get(ext, address)?.0.iter().rev() {
            serialize_into::<_, _, _, BigEndian>(&mut self.output, &i, Infinite).expect("failed to serialize U256");
        }
        Ok(GasLeft::NeedsReturn(U256::from(100), self.output.as_slice()))
    }

    // remittance transaction 汇款
    // 将汇款交易生成的proof、coin等作为参数，进行验证，验证通过则保存到链上，不通过则不处理
    // data[4..391]: proof, data[391..423]: coin, data[423..487]: hb, data[487..551]: delt_ba, data[551..615]: rp, data[615..647]: enc
    fn send_remittance(&self, params: ActionParams, ext: &mut Ext) -> Result<GasLeft, evm::Error> {
        let data = params.data.expect("invalid data");
        let proof = Proof::deserialize(data.get(4..391).expect("not enough data")).unwrap();
        let coin = U256::from(data.get(391..423).expect("not enough data")).0;
        let hb1 = U256::from(data.get(423..455).expect("not enough data")).0;
        let hb2 = U256::from(data.get(455..487).expect("not enough data")).0;
        let hb = (hb1, hb2);
        let delt_ba1 = U256::from(data.get(487..519).expect("not enough data")).0;
        let delt_ba2 = U256::from(data.get(519..551).expect("not enough data")).0;
        let delt_ba = (delt_ba1, delt_ba2);
        let rp1 = U256::from(data.get(551..583).expect("not enough data")).0;
        let rp2 = U256::from(data.get(583..615).expect("not enough data")).0;
        let rp = (rp1, rp2);
        let enc = U256::from(data.get(615..647).expect("not enough data")).0;
        // 验证commitment
        if !p2c_verify(hb, coin, delt_ba, rp, enc, proof) {
            return EvmError::Internal("commitment's verification failed".to_string());
        }
        self.accounts.set(ext, params.sender, ecc_sub(hb, delt_ba));
        self.commitments.set(ext, U256(coin), params.sender);

        Ok(GasLeft::Known(U256::from(100)))
    }

    // collection transaction 收款
    // data[4..391]: proof, data[391..423]: nullifier, data[423..455]: root, data[455..519]: delt_ba
    fn send_collection(&self, params: ActionParams, ext: &mut Ext) -> Result<GasLeft, evm::Error> {
        let data = params.data.expect("invalid data");
        let proof = Proof::deserialize(data.get(4..391).expect("not enough data")).unwrap();
        let nullifier = U256::from(data.get(391..423).expect("not enough data")).0;
        let root = U256::from(data.get(423..455).expect("not enough data")).0;
        let delt_ba1 = U256::from(data.get(455..487).expect("not enough data")).0;
        let delt_ba2 = U256::from(data.get(487..519).expect("not enough data")).0;
        let delt_ba = (delt_ba1, delt_ba2);
        // 验证nullifier
        if !c2p_verify(nullifier, root, delt_ba, proof) {
            return EvmError::Internal("nullifier's verification failed".to_string());
        }
        // TODO 获取余额, 将commitment设为无效
        self.accounts.set(ext, params.sender, ecc_add(self.accounts[params.sender] ,delt_ba));
        self.nullifiers.set(ext, U256(nullifier), params.sender);

        Ok(GasLeft::Known(U256::from(100)))
    }

}