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

import (
	"fmt"
	"math/big"
)

// MainnetChainConfig is the chain parameters to run a node on the main network.
var MainnetChainConfig = &ChainConfig{
	ChainId:     MainNetChainID,
	EIP155Block: MainNetSpuriousDragon,
}

// TestnetChainConfig is the chain parameters to run a node on the test network.
var TestnetChainConfig = &ChainConfig{
	ChainId:     big.NewInt(9),
	EIP155Block: big.NewInt(10),
}

// ChainConfig is the core config which determines the blockchain settings.
//
// ChainConfig is stored in the database on a per block basis. This means
// that any network, identified by its genesis block, can have its own
// set of configuration options.
type ChainConfig struct {
	ChainId *big.Int `json:"chainId"` // Chain id identifies the current chain and is used for replay protection

	EIP155Block *big.Int `json:"eip155Block"` // EIP155 HF block
}

// String implements the Stringer interface.
func (c *ChainConfig) String() string {
	return fmt.Sprintf("{ChainID: %v EIP155: %v}",
		c.ChainId,
		c.EIP155Block,
	)
}

var (
	TestChainConfig = &ChainConfig{big.NewInt(1), new(big.Int)}
	TestRules       = TestChainConfig.Rules(new(big.Int))
)

// GasTable returns the gas table corresponding to the current phase (homestead or homestead reprice).
//
// The returned GasTable's fields shouldn't, under any circumstances, be changed.
func (c *ChainConfig) GasTable(num *big.Int) GasTable {
	return GasTableEIP158
}

func (c *ChainConfig) IsEIP155(num *big.Int) bool {
	if c.EIP155Block == nil || num == nil {
		return false
	}
	return num.Cmp(c.EIP155Block) >= 0

}

// Rules wraps ChainConfig and is merely syntatic sugar or can be used for functions
// that do not have or require information about the block.
//
// Rules is a one time interface meaning that it shouldn't be used in between transition
// phases.
type Rules struct {
	ChainId  *big.Int
	IsEIP155 bool
}

func (c *ChainConfig) Rules(num *big.Int) Rules {
	return Rules{ChainId: new(big.Int).Set(c.ChainId), IsEIP155: c.IsEIP155(num)}
}
