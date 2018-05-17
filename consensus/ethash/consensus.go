// Copyright 2017 The go-ethereum Authors
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

package ethash

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"time"

	"github.com/ubiq/go-ubiq/common"
	"github.com/ubiq/go-ubiq/common/math"
	"github.com/ubiq/go-ubiq/consensus"
	"github.com/ubiq/go-ubiq/log"
	"github.com/ubiq/go-ubiq/consensus/misc"
	"github.com/ubiq/go-ubiq/core/state"
	"github.com/ubiq/go-ubiq/core/types"
	"github.com/ubiq/go-ubiq/params"
	"gopkg.in/fatih/set.v0"
	"sort"
)

var (
	big88               = big.NewInt(88)
	bigMinus99          = big.NewInt(-99)
	nPowAveragingWindow = big.NewInt(21)
	nPowMaxAdjustDown   = big.NewInt(16) // 16% adjustment down
	nPowMaxAdjustUp     = big.NewInt(8)  // 8% adjustment up

	diffChangeBlock       = big.NewInt(4088)
	nPowAveragingWindow88 = big.NewInt(88)
	nPowMaxAdjustDown2    = big.NewInt(3) // 3% adjustment down
	nPowMaxAdjustUp2      = big.NewInt(2) // 2% adjustment up

	// Flux
	fluxChangeBlock       = big.NewInt(8000)
	nPowMaxAdjustDownFlux = big.NewInt(5) // 0.5% adjustment down
	nPowMaxAdjustUpFlux   = big.NewInt(3) // 0.3% adjustment up
	nPowDampFlux          = big.NewInt(1) // 0.1%
)

// Avoids a dependency cycle
type BigIntSlice []*big.Int

func (s BigIntSlice) Len() int           { return len(s) }
func (s BigIntSlice) Less(i, j int) bool { return s[i].Cmp(s[j]) < 0 }
func (s BigIntSlice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func AveragingWindowTimespan() *big.Int {
	x := new(big.Int)
	return x.Mul(nPowAveragingWindow, big88)
}

func MinActualTimespan() *big.Int {
	// (AveragingWindowTimespan() * (100 - nPowMaxAdjustUp  )) / 100
	x := new(big.Int)
	y := new(big.Int)
	z := new(big.Int)
	x.Sub(big.NewInt(100), nPowMaxAdjustUp)
	y.Mul(AveragingWindowTimespan(), x)
	z.Div(y, big.NewInt(100))
	return z
}

func MaxActualTimespan() *big.Int {
	// (AveragingWindowTimespan() * (100 + nPowMaxAdjustDown)) / 100
	x := new(big.Int)
	y := new(big.Int)
	z := new(big.Int)
	x.Add(big.NewInt(100), nPowMaxAdjustDown)
	y.Mul(AveragingWindowTimespan(), x)
	z.Div(y, big.NewInt(100))
	return z
}

func AveragingWindowTimespan88() *big.Int {
	x := new(big.Int)
	return x.Mul(nPowAveragingWindow88, big88)
}

func MinActualTimespan2() *big.Int {
	x := new(big.Int)
	y := new(big.Int)
	z := new(big.Int)
	x.Sub(big.NewInt(100), nPowMaxAdjustUp2)
	y.Mul(AveragingWindowTimespan88(), x)
	z.Div(y, big.NewInt(100))
	return z
}

func MaxActualTimespan2() *big.Int {
	x := new(big.Int)
	y := new(big.Int)
	z := new(big.Int)
	x.Add(big.NewInt(100), nPowMaxAdjustDown2)
	y.Mul(AveragingWindowTimespan88(), x)
	z.Div(y, big.NewInt(100))
	return z
}

func MinActualTimespanFlux(dampen bool) *big.Int {
	x := new(big.Int)
	y := new(big.Int)
	z := new(big.Int)
	if dampen {
		x.Sub(big.NewInt(1000), nPowDampFlux)
		y.Mul(AveragingWindowTimespan88(), x)
		z.Div(y, big.NewInt(1000))
	} else {
		x.Sub(big.NewInt(1000), nPowMaxAdjustUpFlux)
		y.Mul(AveragingWindowTimespan88(), x)
		z.Div(y, big.NewInt(1000))
	}
	return z
}

func MaxActualTimespanFlux(dampen bool) *big.Int {
	x := new(big.Int)
	y := new(big.Int)
	z := new(big.Int)
	if dampen {
		x.Add(big.NewInt(1000), nPowDampFlux)
		y.Mul(AveragingWindowTimespan88(), x)
		z.Div(y, big.NewInt(1000))
	} else {
		x.Add(big.NewInt(1000), nPowMaxAdjustDownFlux)
		y.Mul(AveragingWindowTimespan88(), x)
		z.Div(y, big.NewInt(1000))
	}
	return z
}

// CalcPastMedianTime
func CalcPastMedianTime(ch consensus.ChainReader, genesisBlock *types.Block, number uint64) *big.Int {
	var medianTimeBlocks uint64 = 11

	// Genesis block.
	if number == 0 {
		return genesisBlock.Time()
	}

	timestamps := make([]*big.Int, medianTimeBlocks)
	numNodes := 0
	iterNode := ch.GetHeaderByNumber(number)

	ancestors := make(map[common.Hash]*types.Header)
	for i, ancestor := range ch.GetBlockHeadersFromHash(iterNode.Hash(), medianTimeBlocks) {
		ancestors[ancestor.Hash()] = ancestor
		timestamps[i] = ancestor.Time
		numNodes++
	}

	// Prune the slice to the actual number of available timestamps which
	// will be fewer than desired near the beginning of the block chain
	// and sort them.
	timestamps = timestamps[:numNodes]
	sort.Sort(BigIntSlice(timestamps))

	medianTimestamp := timestamps[numNodes/2]
	return medianTimestamp
}

// Ethash proof-of-work protocol constants.
var (
	blockReward = big.NewInt(8e+18) // Block reward in wei for successfully mining a block
	maxUncles   = 2                 // Maximum number of uncles allowed in a single block
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	errLargeBlockTime    = errors.New("timestamp too big")
	errZeroBlockTime     = errors.New("timestamp equals parent's")
	errTooManyUncles     = errors.New("too many uncles")
	errDuplicateUncle    = errors.New("duplicate uncle")
	errUncleIsAncestor   = errors.New("uncle is ancestor")
	errDanglingUncle     = errors.New("uncle's parent is not ancestor")
	errNonceOutOfRange   = errors.New("nonce out of range")
	errInvalidDifficulty = errors.New("non-positive difficulty")
	errInvalidMixDigest  = errors.New("invalid mix digest")
	errInvalidPoW        = errors.New("invalid proof-of-work")
)

// Author implements consensus.Engine, returning the header's coinbase as the
// proof-of-work verified author of the block.
func (ethash *Ethash) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules of the
// stock Ethereum ethash engine.
func (ethash *Ethash) VerifyHeader(chain consensus.ChainReader, genesisBlock *types.Block, header *types.Header, seal bool) error {
	// If we're running a full engine faking, accept any input as valid
	if ethash.fakeFull {
		return nil
	}
	// Short circuit if the header is known, or it's parent not
	number := header.Number.Uint64()
	if chain.GetHeader(header.Hash(), number) != nil {
		return nil
	}
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	// Sanity checks passed, do a proper verification
	return ethash.verifyHeader(chain, genesisBlock, header, parent, false, seal)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications.
func (ethash *Ethash) VerifyHeaders(chain consensus.ChainReader, genesisBlock *types.Block, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	// If we're running a full engine faking, accept any input as valid
	if ethash.fakeFull || len(headers) == 0 {
		abort, results := make(chan struct{}), make(chan error, len(headers))
		for i := 0; i < len(headers); i++ {
			results <- nil
		}
		return abort, results
	}

	// Spawn as many workers as allowed threads
	workers := runtime.GOMAXPROCS(0)
	if len(headers) < workers {
		workers = len(headers)
	}

	// Create a task channel and spawn the verifiers
	var (
		inputs = make(chan int)
		done   = make(chan int, workers)
		errors = make([]error, len(headers))
		abort  = make(chan struct{})
	)
	for i := 0; i < workers; i++ {
		go func() {
			for index := range inputs {
				errors[index] = ethash.verifyHeaderWorker(chain, genesisBlock, headers, seals, index)
				done <- index
			}
		}()
	}

	errorsOut := make(chan error, len(headers))
	go func() {
		defer close(inputs)
		var (
			in, out = 0, 0
			checked = make([]bool, len(headers))
			inputs  = inputs
		)
		for {
			select {
			case inputs <- in:
				if in++; in == len(headers) {
					// Reached end of headers. Stop sending to workers.
					inputs = nil
				}
			case index := <-done:
				for checked[index] = true; checked[out]; out++ {
					errorsOut <- errors[out]
					if out == len(headers)-1 {
						return
					}
				}
			case <-abort:
				return
			}
		}
	}()
	return abort, errorsOut
}

func (ethash *Ethash) verifyHeaderWorker(chain consensus.ChainReader, genesisBlock *types.Block, headers []*types.Header, seals []bool, index int) error {
	var parent *types.Header
	if index == 0 {
		parent = chain.GetHeader(headers[0].ParentHash, headers[0].Number.Uint64()-1)
	} else if headers[index-1].Hash() == headers[index].ParentHash {
		parent = headers[index-1]
	}
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	if chain.GetHeader(headers[index].Hash(), headers[index].Number.Uint64()) != nil {
		return nil // known block
	}
	return ethash.verifyHeader(chain, genesisBlock, headers[index], parent, false, seals[index])
}

// VerifyUncles verifies that the given block's uncles conform to the consensus
// rules of the stock Ethereum ethash engine.
func (ethash *Ethash) VerifyUncles(chain consensus.ChainReader, genesisBlock *types.Block, block *types.Block) error {
	// If we're running a full engine faking, accept any input as valid
	if ethash.fakeFull {
		return nil
	}
	// Verify that there are at most 2 uncles included in this block
	if len(block.Uncles()) > maxUncles {
		return errTooManyUncles
	}
	// Gather the set of past uncles and ancestors
	uncles, ancestors := set.New(), make(map[common.Hash]*types.Header)

	number, parent := block.NumberU64()-1, block.ParentHash()
	for i := 0; i < 7; i++ {
		ancestor := chain.GetBlock(parent, number)
		if ancestor == nil {
			break
		}
		ancestors[ancestor.Hash()] = ancestor.Header()
		for _, uncle := range ancestor.Uncles() {
			uncles.Add(uncle.Hash())
		}
		parent, number = ancestor.ParentHash(), number-1
	}
	ancestors[block.Hash()] = block.Header()
	uncles.Add(block.Hash())

	// Verify each of the uncles that it's recent, but not an ancestor
	for _, uncle := range block.Uncles() {
		// Make sure every uncle is rewarded only once
		hash := uncle.Hash()
		if uncles.Has(hash) {
			return errDuplicateUncle
		}
		uncles.Add(hash)

		// Make sure the uncle has a valid ancestry
		if ancestors[hash] != nil {
			return errUncleIsAncestor
		}
		if ancestors[uncle.ParentHash] == nil || uncle.ParentHash == block.ParentHash() {
			return errDanglingUncle
		}
		if err := ethash.verifyHeader(chain, genesisBlock, uncle, ancestors[uncle.ParentHash], true, true); err != nil {
			return err
		}
	}
	return nil
}

// verifyHeader checks whether a header conforms to the consensus rules of the
// stock Ethereum ethash engine.
// See YP section 4.3.4. "Block Header Validity"
func (ethash *Ethash) verifyHeader(chain consensus.ChainReader, genesisBlock *types.Block, header, parent *types.Header, uncle bool, seal bool) error {
	// Ensure that the header's extra-data section is of a reasonable size
	if uint64(len(header.Extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("extra-data too long: %d > %d", len(header.Extra), params.MaximumExtraDataSize)
	}
	// Verify the header's timestamp
	if uncle {
		if header.Time.Cmp(math.MaxBig256) > 0 {
			return errLargeBlockTime
		}
	} else {
		if header.Time.Cmp(big.NewInt(time.Now().Unix())) > 0 {
			return consensus.ErrFutureBlock
		}
	}
	if header.Time.Cmp(parent.Time) <= 0 {
		return errZeroBlockTime
	}
	// Verify the block's difficulty based in it's timestamp and parent's difficulty
	expected := CalcDifficulty(chain, genesisBlock, header.Time.Uint64(), parent)
	if expected.Cmp(header.Difficulty) != 0 {
		return fmt.Errorf("invalid difficulty: have %v, want %v", header.Difficulty, expected)
	}
	// Verify that the gas limit is <= 2^63-1
	if header.GasLimit.Cmp(math.MaxBig63) > 0 {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, math.MaxBig63)
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed.Cmp(header.GasLimit) > 0 {
		return fmt.Errorf("invalid gasUsed: have %v, gasLimit %v", header.GasUsed, header.GasLimit)
	}

	// Verify that the gas limit remains within allowed bounds
	diff := new(big.Int).Set(parent.GasLimit)
	diff = diff.Sub(diff, header.GasLimit)
	diff.Abs(diff)

	limit := new(big.Int).Set(parent.GasLimit)
	limit = limit.Div(limit, params.GasLimitBoundDivisor)

	if diff.Cmp(limit) >= 0 || header.GasLimit.Cmp(params.MinGasLimit) < 0 {
		return fmt.Errorf("invalid gas limit: have %v, want %v += %v", header.GasLimit, parent.GasLimit, limit)
	}
	// Verify that the block number is parent's +1
	if diff := new(big.Int).Sub(header.Number, parent.Number); diff.Cmp(big.NewInt(1)) != 0 {
		return consensus.ErrInvalidNumber
	}
	// Verify the engine specific seal securing the block
	if seal {
		if err := ethash.VerifySeal(chain, header); err != nil {
			return err
		}
	}
	if err := misc.VerifyForkHashes(chain.Config(), header, uncle); err != nil {
		return err
	}
	return nil
}

func CalcDifficulty(ch consensus.ChainReader, genesisBlock *types.Block, time uint64, parent *types.Header) *big.Int {
	if parent.Number.Cmp(diffChangeBlock) < 0 {
		return CalcDifficultyOrig(ch, genesisBlock, parent.Number, parent.Difficulty)
	}

	if parent.Number.Cmp(fluxChangeBlock) < 0 {
		return CalcDifficulty2(ch, genesisBlock, parent.Number, parent.Difficulty)
	}

	return FluxDifficulty(ch, genesisBlock, time, parent.Time.Uint64(), parent.Number, parent.Difficulty)
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time
// given the parent block's time and difficulty.
// Rewritten to be based on Digibyte's Digishield v3 retargeting
func CalcDifficultyOrig(ch consensus.ChainReader, genesisBlock *types.Block, parentNumber, parentDiff *big.Int) *big.Int {
	// holds intermediate values to make the algo easier to read & audit
	x := new(big.Int)
	nFirstBlock := new(big.Int)
	nFirstBlock.Sub(parentNumber, nPowAveragingWindow)

	log.Debug(fmt.Sprintf("CalcDifficulty parentNumber: %v parentDiff: %v\n", parentNumber, parentDiff))

	// Check we have enough blocks
	if parentNumber.Cmp(nPowAveragingWindow) < 1 {
		log.Debug(fmt.Sprintf("CalcDifficulty: parentNumber(%+x) < nPowAveragingWindow(%+x)\n", parentNumber, nPowAveragingWindow))
		x.Set(parentDiff)
		return x
	}

	// Limit adjustment step
	// Use medians to prevent time-warp attacks
	// nActualTimespan := nLastBlockTime - nFirstBlockTime
	nLastBlockTime := CalcPastMedianTime(ch, genesisBlock, parentNumber.Uint64())
	nFirstBlockTime := CalcPastMedianTime(ch, genesisBlock, nFirstBlock.Uint64())
	nActualTimespan := new(big.Int)
	nActualTimespan.Sub(nLastBlockTime, nFirstBlockTime)
	log.Debug(fmt.Sprintf("CalcDifficulty nActualTimespan = %v before dampening\n", nActualTimespan))

	// nActualTimespan = AveragingWindowTimespan() + (nActualTimespan-AveragingWindowTimespan())/4
	y := new(big.Int)
	y.Sub(nActualTimespan, AveragingWindowTimespan())
	y.Div(y, big.NewInt(4))
	nActualTimespan.Add(y, AveragingWindowTimespan())
	log.Debug(fmt.Sprintf("CalcDifficulty nActualTimespan = %v before bounds\n", nActualTimespan))

	if nActualTimespan.Cmp(MinActualTimespan()) < 0 {
		nActualTimespan.Set(MinActualTimespan())
		log.Debug("CalcDifficulty Minimum Timespan set")
	} else if nActualTimespan.Cmp(MaxActualTimespan()) > 0 {
		nActualTimespan.Set(MaxActualTimespan())
		log.Debug("CalcDifficulty Maximum Timespan set")
	}

	log.Debug(fmt.Sprintf("CalcDifficulty nActualTimespan = %v final\n", nActualTimespan))

	// Retarget
	x.Mul(parentDiff, AveragingWindowTimespan())
	log.Debug(fmt.Sprintf("CalcDifficulty parentDiff * AveragingWindowTimespan:", x))

	x.Div(x, nActualTimespan)
	log.Debug(fmt.Sprintf("CalcDifficulty x / nActualTimespan:", x))

	// minimum difficulty can ever be (before exponential factor)
	if x.Cmp(params.MinimumDifficulty) < 0 {
		x.Set(params.MinimumDifficulty)
	}

	return x
}

func CalcDifficulty2(ch consensus.ChainReader, genesisBlock *types.Block, parentNumber, parentDiff *big.Int) *big.Int {
	x := new(big.Int)
	nFirstBlock := new(big.Int)
	nFirstBlock.Sub(parentNumber, nPowAveragingWindow88)

	log.Debug(fmt.Sprintf("CalcDifficulty2 parentNumber: %v parentDiff: %v\n", parentNumber, parentDiff))

	nLastBlockTime := CalcPastMedianTime(ch, genesisBlock, parentNumber.Uint64())
	nFirstBlockTime := CalcPastMedianTime(ch, genesisBlock, nFirstBlock.Uint64())
	nActualTimespan := new(big.Int)
	nActualTimespan.Sub(nLastBlockTime, nFirstBlockTime)

	y := new(big.Int)
	y.Sub(nActualTimespan, AveragingWindowTimespan88())
	y.Div(y, big.NewInt(4))
	nActualTimespan.Add(y, AveragingWindowTimespan88())

	if nActualTimespan.Cmp(MinActualTimespan2()) < 0 {
		nActualTimespan.Set(MinActualTimespan2())
	} else if nActualTimespan.Cmp(MaxActualTimespan2()) > 0 {
		nActualTimespan.Set(MaxActualTimespan2())
	}

	x.Mul(parentDiff, AveragingWindowTimespan88())

	x.Div(x, nActualTimespan)

	if x.Cmp(params.MinimumDifficulty) < 0 {
		x.Set(params.MinimumDifficulty)
	}

	return x
}

func FluxDifficulty(ch consensus.ChainReader, genesisBlock *types.Block, time, parentTime uint64, parentNumber, parentDiff *big.Int) *big.Int {
	x := new(big.Int)
	nFirstBlock := new(big.Int)
	nFirstBlock.Sub(parentNumber, nPowAveragingWindow88)

	diffTime := new(big.Int)
	diffTime.Sub(big.NewInt(int64(time)), big.NewInt(int64(parentTime)))

	nLastBlockTime := CalcPastMedianTime(ch, genesisBlock, parentNumber.Uint64())
	nFirstBlockTime := CalcPastMedianTime(ch, genesisBlock, nFirstBlock.Uint64())
	nActualTimespan := new(big.Int)
	nActualTimespan.Sub(nLastBlockTime, nFirstBlockTime)

	y := new(big.Int)
	y.Sub(nActualTimespan, AveragingWindowTimespan88())
	y.Div(y, big.NewInt(4))
	nActualTimespan.Add(y, AveragingWindowTimespan88())

	if nActualTimespan.Cmp(MinActualTimespanFlux(false)) < 0 {
		doubleBig88 := new(big.Int)
		doubleBig88.Mul(big88, big.NewInt(2))
		if diffTime.Cmp(doubleBig88) > 0 {
			nActualTimespan.Set(MinActualTimespanFlux(true))
		} else {
			nActualTimespan.Set(MinActualTimespanFlux(false))
		}
	} else if nActualTimespan.Cmp(MaxActualTimespanFlux(false)) > 0 {
		halfBig88 := new(big.Int)
		halfBig88.Div(big88, big.NewInt(2))
		if diffTime.Cmp(halfBig88) < 0 {
			nActualTimespan.Set(MaxActualTimespanFlux(true))
		} else {
			nActualTimespan.Set(MaxActualTimespanFlux(false))
		}
	}

	x.Mul(parentDiff, AveragingWindowTimespan88())

	x.Div(x, nActualTimespan)

	if x.Cmp(params.MinimumDifficulty) < 0 {
		x.Set(params.MinimumDifficulty)
	}

	return x
}

// VerifySeal implements consensus.Engine, checking whether the given block satisfies
// the PoW difficulty requirements.
func (ethash *Ethash) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	// If we're running a fake PoW, accept any seal as valid
	if ethash.fakeMode {
		time.Sleep(ethash.fakeDelay)
		if ethash.fakeFail == header.Number.Uint64() {
			return errInvalidPoW
		}
		return nil
	}
	// If we're running a shared PoW, delegate verification to it
	if ethash.shared != nil {
		return ethash.shared.VerifySeal(chain, header)
	}
	// Sanity check that the block number is below the lookup table size (60M blocks)
	number := header.Number.Uint64()
	if number/epochLength >= uint64(len(cacheSizes)) {
		// Go < 1.7 cannot calculate new cache/dataset sizes (no fast prime check)
		return errNonceOutOfRange
	}
	// Ensure that we have a valid difficulty for the block
	if header.Difficulty.Sign() <= 0 {
		return errInvalidDifficulty
	}
	// Recompute the digest and PoW value and verify against the header
	cache := ethash.cache(number)

	size := datasetSize(number)
	if ethash.tester {
		size = 32 * 1024
	}
	digest, result := hashimotoLight(size, cache, header.HashNoNonce().Bytes(), header.Nonce.Uint64())
	if !bytes.Equal(header.MixDigest[:], digest) {
		return errInvalidMixDigest
	}
	target := new(big.Int).Div(maxUint256, header.Difficulty)
	if new(big.Int).SetBytes(result).Cmp(target) > 0 {
		return errInvalidPoW
	}
	return nil
}

// Prepare implements consensus.Engine, initializing the difficulty field of a
// header to conform to the ethash protocol. The changes are done inline.
func (ethash *Ethash) Prepare(chain consensus.ChainReader, genesisBlock *types.Block, header *types.Header) error {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Difficulty = CalcDifficulty(chain, genesisBlock, header.Time.Uint64(), parent)

	return nil
}

// Finalize implements consensus.Engine, accumulating the block and uncle rewards,
// setting the final state and assembling the block.
func (ethash *Ethash) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// Accumulate any block and uncle rewards and commit the final state root
	AccumulateRewards(state, header, uncles)
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))

	// Header seems complete, assemble into a block and return
	return types.NewBlock(header, txs, uncles, receipts), nil
}

// Some weird constants to avoid constant memory allocs for them.
var (
	big8  = big.NewInt(8)
	big32 = big.NewInt(32)
)

// AccumulateRewards credits the coinbase of the given block with the mining
// reward. The total reward consists of the static block reward and rewards for
// included uncles. The coinbase of each uncle block is also rewarded.
// TODO (karalabe): Move the chain maker into this package and make this private!
func AccumulateRewards(state *state.StateDB, header *types.Header, uncles []*types.Header) {
	reward := new(big.Int).Set(blockReward)
	r := new(big.Int)
	for _, uncle := range uncles {
		r.Add(uncle.Number, big8)
		r.Sub(r, header.Number)
		r.Mul(r, blockReward)
		r.Div(r, big8)
		state.AddBalance(uncle.Coinbase, r)

		r.Div(blockReward, big32)
		reward.Add(reward, r)
	}
	state.AddBalance(header.Coinbase, reward)
}
