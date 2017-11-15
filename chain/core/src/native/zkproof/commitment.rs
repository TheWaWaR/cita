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

//use rlp::*;
//use util::{Address, U256, H256};
use super::*;

#[derive(Default, Debug, Clone, PartialEq)]
pub struct CommitmentMsg {
    proof: Proof,
    hb:([u64;4],[u64;4]),
    coin:[u64;4],
    delt_ba:([u64;4],[u64;4]),
    rp:([u64;4],[u64;4]),
    enc:[u64;4],
}
