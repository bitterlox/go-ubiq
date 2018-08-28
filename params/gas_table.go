// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

import "math/big"

type GasTable struct {
	ExtcodeSize *big.Int
	ExtcodeCopy *big.Int
	Balance     *big.Int
	SLoad       *big.Int
	Calls       *big.Int
	Suicide     *big.Int

	ExpByte *big.Int

	// CreateBySuicide occurs when the
	// refunded account is one that does
	// not exist. This logic is similar
	// to call. May be left nil. Nil means
	// not charged.
	CreateBySuicide *big.Int
}

var (
	GasTableEIP150 = GasTable{
		ExtcodeSize: big.NewInt(700),
		ExtcodeCopy: big.NewInt(700),
		Balance:     big.NewInt(400),
		SLoad:       big.NewInt(200),
		Calls:       big.NewInt(700),
		Suicide:     big.NewInt(5000),
		ExpByte:     big.NewInt(10),

		CreateBySuicide: big.NewInt(25000),
	}

	GasTableEIP158 = GasTable{
		ExtcodeSize: big.NewInt(700),
		ExtcodeCopy: big.NewInt(700),
		Balance:     big.NewInt(400),
		SLoad:       big.NewInt(200),
		Calls:       big.NewInt(700),
		Suicide:     big.NewInt(5000),
		ExpByte:     big.NewInt(50),

		CreateBySuicide: big.NewInt(25000),
	}
)
