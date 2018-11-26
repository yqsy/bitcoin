// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>

#include <uint256.h>
#include <utilstrencodings.h>
#include <crypto/common.h>

#include <stdio.h>
#include <string.h>

template <unsigned int BITS>
base_uint<BITS>::base_uint(const std::string& str)
{
    static_assert(BITS/32 > 0 && BITS%32 == 0, "Template parameter BITS must be a positive multiple of 32.");

    SetHex(str);
}

template <unsigned int BITS>
base_uint<BITS>& base_uint<BITS>::operator<<=(unsigned int shift)
{
    base_uint<BITS> a(*this);
    for (int i = 0; i < WIDTH; i++)
        pn[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (int i = 0; i < WIDTH; i++) {
        if (i + k + 1 < WIDTH && shift != 0)
            pn[i + k + 1] |= (a.pn[i] >> (32 - shift));
        if (i + k < WIDTH)
            pn[i + k] |= (a.pn[i] << shift);
    }
    return *this;
}

template <unsigned int BITS>
base_uint<BITS>& base_uint<BITS>::operator>>=(unsigned int shift)
{
    base_uint<BITS> a(*this);
    for (int i = 0; i < WIDTH; i++)
        pn[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (int i = 0; i < WIDTH; i++) {
        if (i - k - 1 >= 0 && shift != 0)
            pn[i - k - 1] |= (a.pn[i] << (32 - shift));
        if (i - k >= 0)
            pn[i - k] |= (a.pn[i] >> shift);
    }
    return *this;
}

template <unsigned int BITS>
base_uint<BITS>& base_uint<BITS>::operator*=(uint32_t b32)
{
    uint64_t carry = 0;
    for (int i = 0; i < WIDTH; i++) {
        uint64_t n = carry + (uint64_t)b32 * pn[i];
        pn[i] = n & 0xffffffff;
        carry = n >> 32;
    }
    return *this;
}

template <unsigned int BITS>
base_uint<BITS>& base_uint<BITS>::operator*=(const base_uint& b)
{
    base_uint<BITS> a;
    for (int j = 0; j < WIDTH; j++) {
        uint64_t carry = 0;
        for (int i = 0; i + j < WIDTH; i++) {
            uint64_t n = carry + a.pn[i + j] + (uint64_t)pn[j] * b.pn[i];
            a.pn[i + j] = n & 0xffffffff;
            carry = n >> 32;
        }
    }
    *this = a;
    return *this;
}

template <unsigned int BITS>
base_uint<BITS>& base_uint<BITS>::operator/=(const base_uint& b)
{
    base_uint<BITS> div = b;     // make a copy, so we can shift.
    base_uint<BITS> num = *this; // make a copy, so we can subtract.
    *this = 0;                   // the quotient.
    int num_bits = num.bits();
    int div_bits = div.bits();
    if (div_bits == 0)
        throw uint_error("Division by zero");
    if (div_bits > num_bits) // the result is certainly 0.
        return *this;
    int shift = num_bits - div_bits;
    div <<= shift; // shift so that div and num align.
    while (shift >= 0) {
        if (num >= div) {
            num -= div;
            pn[shift / 32] |= (1 << (shift & 31)); // set a bit of the result.
        }
        div >>= 1; // shift back.
        shift--;
    }
    // num now contains the remainder of the division.
    return *this;
}

template <unsigned int BITS>
int base_uint<BITS>::CompareTo(const base_uint<BITS>& b) const
{
    for (int i = WIDTH - 1; i >= 0; i--) {
        if (pn[i] < b.pn[i])
            return -1;
        if (pn[i] > b.pn[i])
            return 1;
    }
    return 0;
}

template <unsigned int BITS>
bool base_uint<BITS>::EqualTo(uint64_t b) const
{
    for (int i = WIDTH - 1; i >= 2; i--) {
        if (pn[i])
            return false;
    }
    if (pn[1] != (b >> 32))
        return false;
    if (pn[0] != (b & 0xfffffffful))
        return false;
    return true;
}

template <unsigned int BITS>
double base_uint<BITS>::getdouble() const
{
    double ret = 0.0;
    double fact = 1.0;
    for (int i = 0; i < WIDTH; i++) {
        ret += fact * pn[i];
        fact *= 4294967296.0;
    }
    return ret;
}

template <unsigned int BITS>
std::string base_uint<BITS>::GetHex() const
{
    return ArithToUint256(*this).GetHex();
}

template <unsigned int BITS>
void base_uint<BITS>::SetHex(const char* psz)
{
    *this = UintToArith256(uint256S(psz));
}

template <unsigned int BITS>
void base_uint<BITS>::SetHex(const std::string& str)
{
    SetHex(str.c_str());
}

template <unsigned int BITS>
std::string base_uint<BITS>::ToString() const
{
    return (GetHex());
}

template <unsigned int BITS>
unsigned int base_uint<BITS>::bits() const
{
    // 从头往前遍历
    for (int pos = WIDTH - 1; pos >= 0; pos--) {

        // 如果里面有值
        if (pn[pos]) {

            // 1个1个bit访问
            for (int nbits = 31; nbits > 0; nbits--) {

                // 某 nbits 位有值
                if (pn[pos] & 1 << nbits)

                    // 返回有数字的具体某一位, 返回第一个有bit的地址
                    return 32 * pos + nbits + 1;
            }
            return 32 * pos + 1;
        }
    }
    return 0;
}

// Explicit instantiations for base_uint<256>
template base_uint<256>::base_uint(const std::string&);
template base_uint<256>& base_uint<256>::operator<<=(unsigned int);
template base_uint<256>& base_uint<256>::operator>>=(unsigned int);
template base_uint<256>& base_uint<256>::operator*=(uint32_t b32);
template base_uint<256>& base_uint<256>::operator*=(const base_uint<256>& b);
template base_uint<256>& base_uint<256>::operator/=(const base_uint<256>& b);
template int base_uint<256>::CompareTo(const base_uint<256>&) const;
template bool base_uint<256>::EqualTo(uint64_t) const;
template double base_uint<256>::getdouble() const;
template std::string base_uint<256>::GetHex() const;
template std::string base_uint<256>::ToString() const;
template void base_uint<256>::SetHex(const char*);
template void base_uint<256>::SetHex(const std::string&);
template unsigned int base_uint<256>::bits() const;


// nBits => traget
// This implementation directly uses shifts instead of going
// through an intermediate MPI representation.
arith_uint256& arith_uint256::SetCompact(uint32_t nBits, bool* pfNegative, bool* pfOverflow)
{
    int exponent = nBits >> 24;

    uint32_t mantissa = nBits & 0x007fffff;
    if (exponent <= 3) {
        // 指数小于尾数的本身的长度时,要把尾数本身也给修改.
        mantissa >>= 8 * (3 - exponent);
        *this = mantissa;
    } else {
        *this = mantissa;
        // 指数表示了总体占据的byte数量,包括了尾数的本身
        *this <<= 8 * (exponent - 3);
    }
    if (pfNegative)
        *pfNegative = mantissa != 0 && (nBits & 0x00800000) != 0;
    if (pfOverflow)
        *pfOverflow = mantissa != 0 && ((exponent > 34) ||                   // nWord <= 0xff, 最大长度 = 32 + 2 = 34
                                     (mantissa > 0xff && exponent > 33) ||   // 0xff < nWord && <= 0xffff, 最大长度 = 32 + 1 = 33
                                     (mantissa > 0xffff && exponent > 32));  // nWord > 0xffff, 最大长度 = 32
    return *this;
}

// target => nBits
uint32_t arith_uint256::GetCompact(bool fNegative) const
{
    // 得到指数, 非下标
    int exponent = (bits() + 7) / 8;

    // 把尾数推出来
    uint32_t nBtis = 0;
    if (exponent <= 3) {
        nBtis = GetLow64() << 8 * (3 - exponent);
    } else {
        arith_uint256 bn = *this >> 8 * (exponent - 3);
        nBtis = bn.GetLow64();
    }

    // 如果符号位为1,则整体右移动一字节, 但是会把尾数冲掉吧
    // The 0x00800000 bit denotes the sign.
    // Thus, if it is already set, divide the mantissa by 256 and increase the exponent.
    if (nBtis & 0x00800000) {
        nBtis >>= 8;
        exponent++; // 回头移动回来时会增加1 个移动字节数
    }

    // 这个时候只有尾数
    assert((nBtis & ~0x007fffff) == 0);
    assert(exponent < 256);
    nBtis |= exponent << 24;
    nBtis |= (fNegative && (nBtis & 0x007fffff) ? 0x00800000 : 0);
    return nBtis;
}


uint256 ArithToUint256(const arith_uint256 &a)
{
    uint256 b;
    for(int x=0; x<a.WIDTH; ++x)
        WriteLE32(b.begin() + x*4, a.pn[x]);
    return b;
}


arith_uint256 UintToArith256(const uint256 &a)
{
    arith_uint256 b;
    for(int x=0; x<b.WIDTH; ++x)
        b.pn[x] = ReadLE32(a.begin() + x*4);
    return b;
}
