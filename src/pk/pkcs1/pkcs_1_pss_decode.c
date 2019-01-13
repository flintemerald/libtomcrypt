/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

/**
  @file pkcs_1_pss_decode.c
  PKCS #1 PSS Signature Padding, Tom St Denis
*/

#ifdef LTC_PKCS_1

/**
   PKCS #1 v2.00 PSS decode
   @param  msghash         The hash to verify
   @param  msghashlen      The length of the hash (octets)
   @param content_hash_idx  The index of the content hash desired
   @param  sig             The signature data (encoded data)
   @param  siglen          The length of the signature data (octets)
   @param  saltlen         The length of the salt used (octets)
   @param  hash_idx        The index of the hash desired
   @param  modulus_bitlen  The bit length of the RSA modulus
   @param  res             [out] The result of the comparison, 1==valid, 0==invalid
   @return CRYPT_OK if successful (even if the comparison failed)
*/
int pkcs_1_pss_decode(const unsigned char *msghash, unsigned long msghashlen, int content_hash_idx,
                      const unsigned char *sig,     unsigned long siglen,
                            unsigned long saltlen,  int           hash_idx,
                            unsigned long modulus_bitlen, int    *res)
{
   unsigned char *mDash;
   unsigned char *DB, *mask, *salt, *hash;
   unsigned long x, y, hLenContent, modulus_len, mDashLen;
   int           err;
   hash_state    md;

   LTC_ARGCHK(msghash != NULL);
   LTC_ARGCHK(res     != NULL);

   /* default to invalid */
   *res = 0;

   /* ensure hash is valid */
   if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
      return err;
   }
   if ((err = hash_is_valid(content_hash_idx)) != CRYPT_OK) {
      return err;
   }

   hLenContent = hash_descriptor[content_hash_idx].hashsize;
   modulus_bitlen--;
   modulus_len = (modulus_bitlen>>3) + (modulus_bitlen & 7 ? 1 : 0);
   mDashLen    = 8 + saltlen + hLenContent;

   /* check sizes */
   if ((saltlen > modulus_len) ||
       (modulus_len < hLenContent + saltlen + 2)) {
      return CRYPT_PK_INVALID_SIZE;
   }

   /* allocate ram for DB/mask/salt/hash of size modulus_len */
   mDash = XMALLOC(mDashLen);
   DB   = XMALLOC(modulus_len);
   mask = XMALLOC(modulus_len);
   salt = XMALLOC(modulus_len);
   hash = XMALLOC(modulus_len);
   if (mDash == NULL || DB == NULL || mask == NULL || salt == NULL || hash == NULL) {
      if (mDash != NULL) {
          XFREE(mDash);
      }
      if (DB != NULL) {
         XFREE(DB);
      }
      if (mask != NULL) {
         XFREE(mask);
      }
      if (salt != NULL) {
         XFREE(salt);
      }
      if (hash != NULL) {
         XFREE(hash);
      }
      return CRYPT_MEM;
   }

   zeromem(mDash, mDashLen);
   XMEMCPY(mDash+8, msghash, msghashlen);

   /* ensure the 0xBC byte */
   if (sig[siglen-1] != 0xBC) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }

   /* copy out the DB */
   x = 0;
   XMEMCPY(DB, sig + x, modulus_len);
   x += modulus_len - hLenContent - 1;

   /* copy out the hash */
   XMEMCPY(hash, sig + x, hLenContent);
   /* x += hLen; */

   /* check the MSB */
   if ((sig[0] & ~(0xFF >> ((modulus_len<<3) - (modulus_bitlen)))) != 0) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }

   /* generate mask of length modulus_len - hLen - 1 from hash */
   if ((err = pkcs_1_mgf1(hash_idx, hash, hLenContent, mask, modulus_len - hLenContent - 1)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* xor against DB */
   for (y = 0; y < (modulus_len - hLenContent - 1); y++) {
      DB[y] ^= mask[y];
   }

   /* now clear the first byte [make sure smaller than modulus] */
   DB[0] &= 0xFF >> ((modulus_len<<3) - (modulus_bitlen));

   /* DB = PS || 0x01 || salt, PS == modulus_len - saltlen - hLen - 2 zero bytes */

   /* check for zeroes and 0x01 */
   for (x = 0; x < modulus_len - saltlen - hLenContent - 2; x++) {
       if (DB[x] != 0x00) {
          err = CRYPT_INVALID_PACKET;
          goto LBL_ERR;
       }
   }

   /* check for the 0x01 */
   if (DB[x++] != 0x01) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }

   XMEMCPY(mDash + 8 + hLenContent, DB + modulus_len - saltlen - hLenContent - 1, saltlen);

   if ((err = hash_descriptor[content_hash_idx].init(&md)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if ((err = hash_descriptor[content_hash_idx].process(&md, mDash, mDashLen)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if ((err = hash_descriptor[content_hash_idx].done(&md, mDash + 8 + saltlen)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   for (unsigned long i = modulus_len - hLenContent - 1, j = mDashLen - hLenContent; j != mDashLen; ++i, ++j) {
       if ((DB[i] ^ mDash[j]) != 0) {
           err = CRYPT_OK;
           goto LBL_ERR;
       }
   }

   *res = 1;
   err = CRYPT_OK;
LBL_ERR:
#ifdef LTC_CLEAN_STACK
   zeromem(mDash, mDashLen)
   zeromem(DB,   modulus_len);
   zeromem(mask, modulus_len);
   zeromem(salt, modulus_len);
   zeromem(hash, modulus_len);
#endif

   XFREE(hash);
   XFREE(salt);
   XFREE(mask);
   XFREE(DB);
   XFREE(mDash);

   return err;
}

#endif /* LTC_PKCS_1 */

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
