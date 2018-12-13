package main

import (
	"bytes"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/mit-dci/lit/btcutil/chaincfg/chainhash"
	"github.com/mit-dci/lit/wire"
)

var (
	// bigOne is 1 represented as a big.Int.  It is defined here to avoid
	// the overhead of creating it multiple times.
	bigOne = big.NewInt(1)

	// oneLsh256 is 1 shifted left 256 bits.  It is defined here to avoid
	// the overhead of creating it multiple times.
	oneLsh256 = new(big.Int).Lsh(bigOne, 256)
)

// Params defines a Bitcoin network by its parameters.  These parameters may be
// used by Bitcoin applications to differentiate networks as well as addresses
// and keys for one network from those intended for use on another network.
type Params struct {
	// Name defines a human-readable identifier for the network.
	Name string

	// Net defines the magic bytes used to identify the network.
	NetMagicBytes uint32

	// DefaultPort defines the default peer-to-peer port for the network.
	DefaultPort string

	// DNSSeeds defines a list of DNS seeds for the network that are used
	// as one method to discover peers.
	DNSSeeds []string

	// GenesisBlock defines the first block of the chain.
	GenesisBlock *wire.MsgBlock

	// GenesisHash is the starting block hash.
	GenesisHash *chainhash.Hash

	// The function used to calculate the proof of work value for a block
	PoWFunction func(b []byte, height int32) chainhash.Hash

	// The function used to calculate the difficulty of a given block
	DiffCalcFunction func(
		headers []*wire.BlockHeader, height int32, p *Params) (uint32, error)

	//DiffCalcFunction func(r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error)

	// The block header to start downloading blocks from
	StartHeader [80]byte

	// The height of the StartHash
	StartHeight int32

	// Assume the difficulty bits are valid before this header height
	// This is needed for coins with variable retarget lookbacks that use
	// StartHeader to offset the beginning of the header chain for SPV
	AssumeDiffBefore int32

	// The minimum number of headers to pass to the difficulty function.
	// This is primarily intended for coins that have difficulty functions
	// without fixed epoch lengths
	MinHeaders int32

	// Fee per byte for transactions
	FeePerByte int64

	// PowLimit defines the highest allowed proof of work value for a block
	// as a uint256.
	PowLimit *big.Int

	// PowLimitBits defines the highest allowed proof of work value for a
	// block in compact form.
	PowLimitBits uint32

	// CoinbaseMaturity is the number of blocks required before newly mined
	// coins (coinbase transactions) can be spent.
	CoinbaseMaturity uint16

	// SubsidyReductionInterval is the interval of blocks before the subsidy
	// is reduced.
	SubsidyReductionInterval int32

	// TargetTimespan is the desired amount of time that should elapse
	// before the block difficulty requirement is examined to determine how
	// it should be changed in order to maintain the desired block
	// generation rate.
	TargetTimespan time.Duration

	// TargetTimePerBlock is the desired amount of time to generate each
	// block.
	TargetTimePerBlock time.Duration

	// RetargetAdjustmentFactor is the adjustment factor used to limit
	// the minimum and maximum amount of adjustment that can occur between
	// difficulty retargets.
	RetargetAdjustmentFactor int64

	// ReduceMinDifficulty defines whether the network should reduce the
	// minimum required difficulty after a long enough period of time has
	// passed without finding a block.  This is really only useful for test
	// networks and should not be set on a main network.
	ReduceMinDifficulty bool

	// MinDiffReductionTime is the amount of time after which the minimum
	// required difficulty should be reduced when a block hasn't been found.
	//
	// NOTE: This only applies if ReduceMinDifficulty is true.
	MinDiffReductionTime time.Duration

	// GenerateSupported specifies whether or not CPU mining is allowed.
	GenerateSupported bool

	// Enforce current block version once network has
	// upgraded.  This is part of BIP0034.
	BlockEnforceNumRequired uint64

	// Reject previous block versions once network has
	// upgraded.  This is part of BIP0034.
	BlockRejectNumRequired uint64

	// The number of nodes to check.  This is part of BIP0034.
	BlockUpgradeNumToCheck uint64

	// Mempool parameters
	RelayNonStdTxs bool

	// Address encoding magics
	PubKeyHashAddrID byte   // First byte of a P2PKH address
	ScriptHashAddrID byte   // First byte of a P2SH address
	PrivateKeyID     byte   // First byte of a WIF private key
	Bech32Prefix     string // HRP for bech32 address

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID [4]byte
	HDPublicKeyID  [4]byte

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType uint32

	// TestCoin, when true, indicates that the network deals with money that
	// isn't worth anything.  This can be useful to skip over security code,
	//
	TestCoin bool
}

var VertcoinParams = Params{
	Name:          "vtc",
	NetMagicBytes: 0xdab5bffa,
	DefaultPort:   "5889",
	DNSSeeds: []string{
		"fr1.vtconline.org",
		"uk1.vtconline.org",
		"useast1.vtconline.org",
		"vtc.alwayshashing.com",
		"crypto.office-on-the.net",
		"p2pool.kosmoplovci.org",
	},

	// Chain parameters
	StartHeader: [80]byte{
		0x02, 0x00, 0x00, 0x00, 0x36, 0xdc, 0x16, 0xc7, 0x71, 0x63,
		0x1c, 0x52, 0xa4, 0x3d, 0xb7, 0xb0, 0xa9, 0x86, 0x95, 0x95,
		0xed, 0x7d, 0xc1, 0x68, 0xe7, 0x2e, 0xaf, 0x0f, 0x55, 0x08,
		0x02, 0x98, 0x9f, 0x5c, 0x7b, 0xe4, 0x37, 0xa6, 0x90, 0x76,
		0x66, 0xa7, 0xba, 0x55, 0x75, 0xd8, 0x8a, 0xc5, 0x14, 0x01,
		0x86, 0x11, 0x8e, 0x34, 0xe2, 0x4a, 0x04, 0x7b, 0x9d, 0x6e,
		0x96, 0x41, 0xbb, 0x29, 0xe2, 0x04, 0xcb, 0x49, 0x3c, 0x53,
		0x08, 0x58, 0x3f, 0xf4, 0x4d, 0x1b, 0x42, 0x22, 0x6e, 0x8a,
	},
	StartHeight:              598752,
	AssumeDiffBefore:         602784,
	MinHeaders:               4032,
	FeePerByte:               100,
	PowLimit:                 new(big.Int).Sub(new(big.Int).Lsh(bigOne, 236), bigOne),
	PowLimitBits:             0x1e0fffff,
	CoinbaseMaturity:         120,
	SubsidyReductionInterval: 840000,
	TargetTimespan:           time.Second * 302400, // 3.5 weeks
	TargetTimePerBlock:       time.Second * 150,    // 150 seconds
	RetargetAdjustmentFactor: 4,                    // 25% less, 400% more
	ReduceMinDifficulty:      false,
	MinDiffReductionTime:     time.Second * 150 * 2, // ?? unknown
	GenerateSupported:        false,

	BlockEnforceNumRequired: 1512,
	BlockRejectNumRequired:  1915,
	BlockUpgradeNumToCheck:  2016,

	// Mempool parameters
	RelayNonStdTxs: true,

	// Address encoding magics
	PubKeyHashAddrID: 0x47, // starts with V
	ScriptHashAddrID: 0x05, // starts with 3
	Bech32Prefix:     "vtc",
	PrivateKeyID:     0x80,

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 28,
}

// Uses Kimoto Gravity Well for difficulty adjustment. Used in VTC, MONA etc
func calcDiffAdjustKGW(
	headers []*wire.BlockHeader, height int32, p *Params) (uint32, error) {
	var minBlocks, maxBlocks int32
	minBlocks = 144
	maxBlocks = 4032

	if height-1 < minBlocks {
		return p.PowLimitBits, nil
	}

	idx := -2
	currentBlock := headers[len(headers)+idx]
	lastSolved := currentBlock

	var blocksScanned, actualRate, targetRate int64
	var difficultyAverage, previousDifficultyAverage big.Int
	var rateAdjustmentRatio, eventHorizonDeviation float64
	var eventHorizonDeviationFast, eventHorizonDevationSlow float64

	currentHeight := height - 1

	var i int32

	for i = 1; currentHeight > 0; i++ {
		if i > maxBlocks {
			break
		}

		blocksScanned++

		if i == 1 {
			difficultyAverage = *CompactToBig(currentBlock.Bits)
		} else {
			compact := CompactToBig(currentBlock.Bits)

			difference := new(big.Int).Sub(compact, &previousDifficultyAverage)
			difference.Div(difference, big.NewInt(int64(i)))
			difference.Add(difference, &previousDifficultyAverage)
			difficultyAverage = *difference
		}

		previousDifficultyAverage = difficultyAverage

		actualRate = lastSolved.Timestamp.Unix() - currentBlock.Timestamp.Unix()
		targetRate = int64(p.TargetTimePerBlock.Seconds()) * blocksScanned
		rateAdjustmentRatio = 1

		if actualRate < 0 {
			actualRate = 0
		}

		if actualRate != 0 && targetRate != 0 {
			rateAdjustmentRatio = float64(targetRate) / float64(actualRate)
		}

		eventHorizonDeviation = 1 + (0.7084 *
			math.Pow(float64(blocksScanned)/float64(minBlocks), -1.228))
		eventHorizonDeviationFast = eventHorizonDeviation
		eventHorizonDevationSlow = 1 / eventHorizonDeviation

		if blocksScanned >= int64(minBlocks) &&
			(rateAdjustmentRatio <= eventHorizonDevationSlow ||
				rateAdjustmentRatio >= eventHorizonDeviationFast) {
			break
		}

		if currentHeight <= 1 {
			break
		}

		currentHeight--
		idx--
		currentBlock = headers[len(headers)+idx]
	}

	newTarget := difficultyAverage
	if actualRate != 0 && targetRate != 0 {
		newTarget.Mul(&newTarget, big.NewInt(actualRate))

		newTarget.Div(&newTarget, big.NewInt(targetRate))
	}

	if newTarget.Cmp(p.PowLimit) == 1 {
		newTarget = *p.PowLimit
	}

	return BigToCompact(&newTarget), nil
}

// CompactToBig converts a compact representation of a whole number N to an
// unsigned 32-bit number.  The representation is similar to IEEE754 floating
// point numbers.
//
// Like IEEE754 floating point, there are three basic components: the sign,
// the exponent, and the mantissa.  They are broken out as follows:
//
//	* the most significant 8 bits represent the unsigned base 256 exponent
// 	* bit 23 (the 24th bit) represents the sign bit
//	* the least significant 23 bits represent the mantissa
//
//	-------------------------------------------------
//	|   Exponent     |    Sign    |    Mantissa     |
//	-------------------------------------------------
//	| 8 bits [31-24] | 1 bit [23] | 23 bits [22-00] |
//	-------------------------------------------------
//
// The formula to calculate N is:
// 	N = (-1^sign) * mantissa * 256^(exponent-3)
//
// This compact form is only used in bitcoin to encode unsigned 256-bit numbers
// which represent difficulty targets, thus there really is not a need for a
// sign bit, but it is implemented here to stay consistent with bitcoind.
func CompactToBig(compact uint32) *big.Int {
	// Extract the mantissa, sign bit, and exponent.
	mantissa := compact & 0x007fffff
	isNegative := compact&0x00800000 != 0
	exponent := uint(compact >> 24)

	// Since the base for the exponent is 256, the exponent can be treated
	// as the number of bytes to represent the full 256-bit number.  So,
	// treat the exponent as the number of bytes and shift the mantissa
	// right or left accordingly.  This is equivalent to:
	// N = mantissa * 256^(exponent-3)
	var bn *big.Int
	if exponent <= 3 {
		mantissa >>= 8 * (3 - exponent)
		bn = big.NewInt(int64(mantissa))
	} else {
		bn = big.NewInt(int64(mantissa))
		bn.Lsh(bn, 8*(exponent-3))
	}

	// Make it negative if the sign bit is set.
	if isNegative {
		bn = bn.Neg(bn)
	}

	return bn
}

func BigToCompact(n *big.Int) uint32 {
	// No need to do any work if it's zero.
	if n.Sign() == 0 {
		return 0
	}

	// Since the base for the exponent is 256, the exponent can be treated
	// as the number of bytes.  So, shift the number right or left
	// accordingly.  This is equivalent to:
	// mantissa = mantissa / 256^(exponent-3)
	var mantissa uint32
	exponent := uint(len(n.Bytes()))
	if exponent <= 3 {
		mantissa = uint32(n.Bits()[0])
		mantissa <<= 8 * (3 - exponent)
	} else {
		// Use a copy to avoid modifying the caller's original number.
		tn := new(big.Int).Set(n)
		mantissa = uint32(tn.Rsh(tn, 8*(exponent-3)).Bits()[0])
	}

	// When the mantissa already has the sign bit set, the number is too
	// large to fit into the available 23-bits, so divide the number by 256
	// and increment the exponent accordingly.
	if mantissa&0x00800000 != 0 {
		mantissa >>= 8
		exponent++
	}

	// Pack the exponent, sign bit, and mantissa into an unsigned 32-bit
	// int and return it.
	compact := uint32(exponent<<24) | mantissa
	if n.Sign() < 0 {
		compact |= 0x00800000
	}
	return compact
}

func CalcWork(bits uint32) *big.Int {
	// Return a work value of zero if the passed difficulty bits represent
	// a negative number. Note this should not happen in practice with valid
	// blocks, but an invalid block could trigger it.
	difficultyNum := CompactToBig(bits)
	if difficultyNum.Sign() <= 0 {
		return big.NewInt(0)
	}

	// (1 << 256) / (difficultyNum + 1)
	denominator := new(big.Int).Add(difficultyNum, bigOne)
	return new(big.Int).Div(oneLsh256, denominator)
}

func main() {

	if len(os.Args) < 4 || os.Args[1] == "help" {
		fmt.Println("Usage: kgwsimulator {rpcuser} {rpcpass} {hash} {num} {diff}")
		fmt.Println("{rpcuser} (required) : RPC user to fetch blocks from Vertcoin core")
		fmt.Println("{rpcpass} (required) : RPC password to fetch blocks from Vertcoin core")
		fmt.Println("{hash} (required) : Expected hashrate of the network in GH/s")
		fmt.Println("{num} (required) : number of blocks to simulate")
		fmt.Println("{diff} (optional) : Override diff bits (hex) at forkblock")
		os.Exit(0)
	}

	connCfg := &rpcclient.ConnConfig{
		Host:         "localhost:5888",
		User:         os.Args[1],
		Pass:         os.Args[2],
		HTTPPostMode: true, // Bitcoin core only supports HTTP POST mode
		DisableTLS:   true, // Bitcoin core does not provide TLS by default
	}
	client, err := rpcclient.New(connCfg, nil)
	if err != nil {
		log.Fatal(err)
	}
	lastBlocks := make([]*wire.BlockHeader, 0)
	hash, err := client.GetBestBlockHash()
	if err != nil {
		log.Fatal(err)
	}

	height, err := client.GetBlockCount()
	for len(lastBlocks) < 4200 {
		header, err := client.GetBlockHeader(hash)
		if err != nil {
			log.Fatal(err)
		}
		bh := new(wire.BlockHeader)
		var buf bytes.Buffer
		header.Serialize(&buf)
		buf2 := bytes.NewBuffer(buf.Bytes())
		bh.Deserialize(buf2)
		lastBlocks = append([]*wire.BlockHeader{bh}, lastBlocks...)

		hash = &header.PrevBlock
	}

	bestHeader := lastBlocks[len(lastBlocks)-1]
	diff, err := calcDiffAdjustKGW(lastBlocks, int32(height), &VertcoinParams)
	if err != nil {
		log.Fatal(err)
	}

	if len(os.Args) > 5 {

		diff64, err := strconv.ParseInt(os.Args[5], 16, 32)
		if err != nil {
			log.Fatal("Something wrong with your diff input, quitting.")
		}
		diff = uint32(diff64)
	}

	numBlocks, err := strconv.ParseInt(os.Args[4], 10, 32)
	if err != nil {
		log.Fatal("Something wrong with your numblocks input, quitting.")
	}

	hashRate, ok := big.NewInt(0).SetString(os.Args[3], 10)
	if !ok {
		log.Fatal("Something wrong with your hashrate input, quitting.")
	}
	hashRate = hashRate.Mul(hashRate, big.NewInt(1000000000))

	fmt.Printf("|%20s|%20s|%20s|\n", "Block Height", "Diff Bits", "Time to block")
	fmt.Printf("|--------------------|--------------------|--------------------|\n")

	totalSeconds := int64(0)
	startHeight := height
	nullHash, _ := chainhash.NewHashFromStr("0000000000000000000000000000000000000000000000000000000000000000")
	for i := 0; i < int(numBlocks); i++ {

		// Calculate the time it would take to mine based on Work and Hashrate
		workForBlock := CalcWork(diff)
		timeInSeconds := workForBlock.Div(workForBlock, hashRate).Int64()
		seconds := timeInSeconds % int64(60)
		minutes := (timeInSeconds - seconds) / int64(60)

		height++
		totalSeconds += timeInSeconds
		fmt.Printf("|%20d|%20x|%20s\n", height, diff, fmt.Sprintf("%dm%02ds", minutes, seconds))

		// Craft new block

		newHeader := wire.NewBlockHeader(nullHash, nullHash, diff, 0)
		newHeader.Timestamp = bestHeader.Timestamp.Add(time.Second * time.Duration(timeInSeconds))
		lastBlocks = append(lastBlocks[1:], newHeader)

		bestHeader = lastBlocks[len(lastBlocks)-1]
		diff, err = calcDiffAdjustKGW(lastBlocks, int32(height), &VertcoinParams)
		if err != nil {
			log.Fatal(err)
		}
	}

	fmt.Printf("Totally mined %d blocks in %d seconds (~%d per block)\n", height-startHeight, totalSeconds, totalSeconds/(height-startHeight))

}
