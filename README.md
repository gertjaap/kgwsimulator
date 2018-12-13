# kgwsimulator
Simulator for Kimoto Gravity Well for Vertcoin written in Go

Will fetch the latest blockheaders from Vertcoin Core over RPC, and then simulate new blocks based on the given hashrate. It will feed these blocks
to the KGW algorithm and output the expected time to block based on the given hashrate.

Made to properly determine starting diff at time of forks.

## Installation

`go get -u github.com/gertjaap/kgwsimulator`

## Usage

Make sure a synchronized Vertcoin Core (mainnet) is running and listens for RPC connections on `localhost:5888`

`kgwsimulator {rpcuser} {rpcpassword} {hash} {num} {diff}`

Where:

- `rpcuser` (required) : RPC user to fetch blocks from Vertcoin core
- `rpcpass` (required) : RPC password to fetch blocks from Vertcoin core
- `hash` (required) : Expected hashrate of the network in GH/s
- `num` (required) : number of blocks to simulate
- `diff` (optional) : Override diff bits (hex) at forkblock
 
## Result

The output will look something like this:

```
|        Block Height|           Diff Bits|       Time to block|
|--------------------|--------------------|--------------------|
|             1050862|            1c0ffff0|               0m00s
|             1050863|            1a6f342d|              10m47s
|             1050864|            1b024ada|               2m02s
|             1050865|            1b024989|               2m03s
|             1050866|            1b02497c|               2m03s
|             1050867|            1b0249cf|               2m03s
|             1050868|            1b0249c3|               2m03s
|             1050869|            1b0249b6|               2m03s
|             1050870|            1b0249a9|               2m03s
|             1050871|            1b02499c|               2m03s
|             1050872|            1b024a0a|               2m02s
|             1050873|            1b0249fd|               2m02s
|             1050874|            1b0249f0|               2m02s
|             1050875|            1b0249e3|               2m02s
|             1050876|            1b0249d6|               2m02s
|             1050877|            1b024a42|               2m02s
|             1050878|            1b024a6f|               2m02s
|             1050879|            1b024a62|               2m02s
|             1050880|            1b024a54|               2m02s
|             1050881|            1b024a47|               2m02s
Totally mined 20 blocks in 2850 seconds (~142 per block)
```


