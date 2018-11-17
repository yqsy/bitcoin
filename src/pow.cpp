// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);

    // 最小难度限制
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval

    // 2016个块调整一次难度
    int64_t difficulityAdjustmentInterval =  params.DifficultyAdjustmentInterval();

    // 上一个区块的高度 == 0.1.2...
    // pindexLast->nHeight+1  == 生成区块 1.2.3...

    // 1 % 2016 = 1 , 2015 % 2016 = 2015,  [1,2015]
    // 2017 % 2016 = 1, 4031 % 2016 = 2015 [2017,4031]

    if ((pindexLast->nHeight+1) % difficulityAdjustmentInterval != 0)
    {

        // pindexLast->nHeight 属于 [0, 2014]

        // 主网false
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.

            // 当前即将生成的区块的时间 - 上一个区块的时间 超过20分钟 =>  难度降到最小  (测试网络不能挖矿挖太久)
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block

                // params.DifficultyAdjustmentInterval() != 0   => pindexLast->nHeight 属于 [1, 2014]

                // 返回上一个非强制最小难度的区块的难度
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev &&
                        pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 &&
                        pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;

                return pindex->nBits;
            }
        }

        // 主网直接返回上一个区块的难度,也就是在2015个区块之内难度不变
        return pindexLast->nBits;
    }

    // 当前区块:
    // 2016 % 2016 = 0
    // 4032 % 2016 = 0

    // Go back by what we want to be 14 days worth of blocks

    // 2016 => 0
    // 4032 => 2016
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);

    // 获得指定高度的索引, 通过2015区块对象.GetAncestor(高度0)
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    // 2015 , 0 的时间
    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

// 2015  0
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{

    // YQMARK 难度调整
    // regtest 不调整难度
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;


    // 2015 个块的时间  - 0个块的时间
    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;


    // 2016个块的时间属于[3.5,56]天之间
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;

    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);


    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);

    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

// 只是检查一下hash
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;  // 否定?
    bool fOverflow;  // 溢出

    // 将32字节数字 转换成8组,每组4字节,
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // 如果得出来的hash,大于target则算计算失败
    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

bool CheckProofOfWorkNew(uint256 hash, unsigned int nBits, uint256 powLimit)
{
    bool fNegative;  // 否定?
    bool fOverflow;  // 溢出

    // 将32字节数字 转换成8组,每组4字节,
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(powLimit))
        return false;

    // 如果得出来的hash,大于target则算计算失败
    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
