// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include "arith_uint256.h"
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

#include <assert.h>
#include <memory>

#include <chainparamsseeds.h>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
*    Converting genesis hash to string: CBlock(hash=00050c831b07f1137c0fb85f2d1a9daedcf4dbbf91df32b1feee143a891a722f, ver=0x00000001, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=5b20cf91f544446cd62431381b0e17a0a90d081c2ecebb1043fc7a2fde41c953, nTime=1630810977, nBits=1f1fffff, nNonce=1795, vtx=1)
*    CTransaction(hash=5b20cf91f5, ver=1, vin.size=1, vout.size=1, nLockTime=0)
*    CTxIn(COutPoint(0000000000, 4294967295), coinbase 04ffff001d010416426f7879436f696e2e506f572e4a616d65732e446576)
*    CScriptWitness()
*    CTxOut(nValue=50.00000000, scriptPubKey=4104678afdb0fe5548271967f1a671)

*    Converting genesis hash to string: CBlock(hash=00178b654a2d9a3976d90b41ff27171df7f7f1ee73bbb0353a15272efb9ce06a, ver=0x00000001, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=5b20cf91f544446cd62431381b0e17a0a90d081c2ecebb1043fc7a2fde41c953, nTime=1630213092, nBits=1f1fffff, nNonce=7556, vtx=1)
*    CTransaction(hash=5b20cf91f5, ver=1, vin.size=1, vout.size=1, nLockTime=0)
*    CTxIn(COutPoint(0000000000, 4294967295), coinbase 04ffff001d010416426f7879436f696e2e506f572e4a616d65732e446576)
*    CScriptWitness()
*    CTxOut(nValue=50.00000000, scriptPubKey=4104678afdb0fe5548271967f1a671)
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "ChipMonk Clans are coming to take over your acorns";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 23500;
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 17;
        consensus.BIP34Hash = uint256S("0x000012844c804516ed35b07f163eec8dbbdd83a7263e3c023821efbaf934c41f");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("00007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 7 * 24 * 60 * 60; // 7 days
        consensus.nPowTargetSpacing = 5 * 60; // 5mins
//        consensus.nZawyLwmaAveragingWindow = 90;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 3427; // 
        consensus.nMinerConfirmationWindow = 2016 * 2; // nPowTargetTimespan / nPowTargetSpacing

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1521417600; // March 19th, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1552953600; // March 19th, 2019

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1521417600; // March 19th, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1552953600; // March 19th, 2019

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xad;
        pchMessageStart[1] = 0xae;
        pchMessageStart[2] = 0xdc;
        pchMessageStart[3] = 0xfe;
        nDefaultPort = 16852;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1631170951, 1376, 0x1f1fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0001f7bfaa43719f18b2a5ffe1339b914dcb2f0f5ce4a32a930bb5a65bbc69cb"));
        assert(genesis.hashMerkleRoot == uint256S("b459687a8c8f42b12e5954d94531dbe36d2fe1f56c6041f65957b53340ebdf43"));
        
        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));  
        vSeeds.clear();
        vSeeds.emplace_back("172.105.69.18", false);
        vSeeds.emplace_back("172.105.84.202", false); 
        vSeeds.emplace_back("172.105.90.153", false);
        vSeeds.emplace_back("172.105.86.125", false);
        vSeeds.emplace_back("172.105.91.221", false);
        vSeeds.emplace_back("172.105.69.184", false);
        vSeeds.emplace_back("178.79.189.55", false);

        
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,28); // C
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,48); // L
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
        
        bech32_hrp = "cpmk";
        
      

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
        {
        {3, uint256S("0x00124ea54e0c95776cb13886ce156ac1eaa1285a055509e0c4eaf6642bde885d")},
        {1500, uint256S("0x00000027337da04afdaaac39c14792c6a9a070088f0b68b45ac356fb26c4cbd3")},
        {2000, uint256S("0x0000001163126486625380c54937747d08049f04108b4dec9421bedb2e697f3f")},
        {3500, uint256S("0x0000001cb9494c9b5149b4cceacdc719b6ab3f692b6b145da0b97ad376797805")},
        {7000, uint256S("0x0000003e79866f2c9ddb4ad7096a5ed9778ed16b301ba7866303f44140e2f6c6")},
        {7500, uint256S("0x000000bc2b0c6ed3d3aaa57beb50fdd362e82fefda42786fdebf9d29893f66cd")}

       }
        };

        chainTxData = ChainTxData{
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 1050000;
//        consensus.BIP16Height = 0;
//        consensus.BIP34Height = 17;
//        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 24 * 60 * 60;
        consensus.nPowTargetSpacing = 60;
//        consensus.nZawyLwmaAveragingWindow = 90;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1368; // 95% of 1440
        consensus.nMinerConfirmationWindow = 1440; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

                // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1521417600; // March 19th, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1552953600; // March 19th, 2019

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1521417600; // March 19th, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1552953600; // March 19th, 2019

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xad;
        pchMessageStart[1] = 0xae;
        pchMessageStart[2] = 0xdc;
        pchMessageStart[3] = 0xfe;
        nDefaultPort = 16716;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1631170951, 1376, 0x1f1fffff, 1, 50 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0001f7bfaa43719f18b2a5ffe1339b914dcb2f0f5ce4a32a930bb5a65bbc69cb"));
        assert(genesis.hashMerkleRoot == uint256S("b459687a8c8f42b12e5954d94531dbe36d2fe1f56c6041f65957b53340ebdf43"));


        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = {
            {
                {0, uint256S("0x")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
       // consensus.BIP34Height = 17;
       // consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 24 * 60 * 60;
        consensus.nPowTargetSpacing = 60;
//        consensus.nZawyLwmaAveragingWindow = 90;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
//        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
//        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
//        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
//        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
//        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
//        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
//        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
//        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
//        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xce;
        pchMessageStart[2] = 0xba;
        pchMessageStart[3] = 0xbe;
        nDefaultPort = 39706;
        nPruneAfterHeight = 1000;
        
        genesis = CreateGenesisBlock(1631170951, 1376, 0x1f1fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0001f7bfaa43719f18b2a5ffe1339b914dcb2f0f5ce4a32a930bb5a65bbc69cb"));
        assert(genesis.hashMerkleRoot == uint256S("b459687a8c8f42b12e5954d94531dbe36d2fe1f56c6041f65957b53340ebdf43"));

        
        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                {0, uint256S("0x")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

     bech32_hrp = "cpt";
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}




