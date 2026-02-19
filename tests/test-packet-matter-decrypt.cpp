/*
 *  Copyright (c) 2021-2023 Project CHIP Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../packet-matter-decrypt.h"


#define MATTER_MAX_MESSAGE_SIZE     1280

struct DecryptTestVector
{
    const char *name;
    const char *keyHex;
    const char *aadHex;
    const char *ivHex;
    const char *cipherHex;
    const char *tagHex;
    const char *plainHex;
};

static const DecryptTestVector kVectors[] = {
    {
        "EchoRequest_I2R",
        "44d43c91d227f3ba0824c5d87cb81b33",
        "25110100000069b6010000000000015cbc00000000000000",
        "69b601000000000001000000",
        "69c1148a4c853d439cc9492ab3a5364ecf41780712",
        "e287304edcf8cff0e368039dba2e1fe8",
        "0501699801004563686f204d65737361676520300a"
    },
    {
        "EchoResponse_R2I",
        "acc18f06c7bc9be8246a678cb1f8ba3d",
        "251104000000015cbc000000000069b60100000000000000",
        "015cbc000000000004000000",
        "4251a252588cb14c8717",
        "9514abf95c11ecf2f229cb6e3a6c3ca2",
        "02106998000001000000"
    },
};

static int HexNibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool HexToBin(const char *hex, uint8_t *out, size_t outCap, size_t &outLen)
{
    size_t hexLen = strlen(hex);
    if ((hexLen % 2) != 0 || outCap < (hexLen / 2)) {
        return false;
    }

    outLen = hexLen / 2;
    for (size_t i = 0; i < outLen; i++) {
        int hi = HexNibble(hex[i * 2]);
        int lo = HexNibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

int main()
{
    MATTER_ERROR errAny = MATTER_NO_ERROR;

    for (size_t i = 0; i < (sizeof(kVectors) / sizeof(kVectors[0])); i++) {
        const DecryptTestVector &v = kVectors[i];
        uint8_t key[64], aad[MATTER_MAX_MESSAGE_SIZE], iv[32], ct[MATTER_MAX_MESSAGE_SIZE], tag[32], expected[MATTER_MAX_MESSAGE_SIZE], pt[MATTER_MAX_MESSAGE_SIZE];
        size_t keyLen = 0, aadLen = 0, ivLen = 0, ctLen = 0, tagLen = 0, expectedLen = 0;

        printf("Testing decrypt[%zu] (%s): ", i, v.name);

        if (!HexToBin(v.keyHex, key, sizeof(key), keyLen) ||
            !HexToBin(v.aadHex, aad, sizeof(aad), aadLen) ||
            !HexToBin(v.ivHex, iv, sizeof(iv), ivLen) ||
            !HexToBin(v.cipherHex, ct, sizeof(ct), ctLen) ||
            !HexToBin(v.tagHex, tag, sizeof(tag), tagLen) ||
            !HexToBin(v.plainHex, expected, sizeof(expected), expectedLen)) {
            printf("FAIL: invalid hex input\n");
            errAny = MATTER_ERROR_INVALID_ARGUMENT;
            continue;
        }

        if (ctLen != expectedLen) {
            printf("FAIL: expected length mismatch\n");
            errAny = MATTER_ERROR_INVALID_ARGUMENT;
            continue;
        }

        memset(pt, 0, sizeof(pt));
        MATTER_ERROR err = AES_CCM_decrypt(ct, ctLen, aad, aadLen, tag, tagLen, key, keyLen, iv, ivLen, pt);
        if (err != MATTER_NO_ERROR) {
            printf("FAIL: %d\n", err);
            errAny = err;
            continue;
        }

        if (memcmp(pt, expected, expectedLen) != 0) {
            printf("FAIL: plaintext mismatch\n");
            errAny = MATTER_ERROR_INCORRECT_STATE;
            continue;
        }

        printf("PASS\n");
    }

    return errAny;
}
