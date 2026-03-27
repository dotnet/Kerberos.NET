// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    /// <summary>
    /// Cross-platform managed Diffie-Hellman key agreement implementation using BigInteger.
    /// Used on Linux/macOS where platform-native DH (BCrypt) is not available.
    /// </summary>
    public abstract class ManagedDiffieHellman : IKeyAgreement
    {
        private readonly int keyLength;

        private readonly BigInteger prime;
        private readonly BigInteger generator;
        private readonly BigInteger factor;
        private readonly BigInteger privateKey;
        private readonly BigInteger publicValue;

        private BigInteger partnerKey;
        private bool disposedValue;

        protected ManagedDiffieHellman(ReadOnlyMemory<byte> prime, ReadOnlyMemory<byte> generator, ReadOnlyMemory<byte> factor)
        {
            this.keyLength = prime.Length;

            this.prime = ToBigInteger(prime);
            this.generator = ToBigInteger(generator);
            this.factor = ToBigInteger(factor);

            this.privateKey = GeneratePrivateKey(this.keyLength);
            this.publicValue = BigInteger.ModPow(this.generator, this.privateKey, this.prime);

            this.PublicKey = new DiffieHellmanKey
            {
                Type = AsymmetricKeyType.Public,
                Generator = ToFixedBytes(this.generator, this.keyLength),
                Modulus = ToFixedBytes(this.prime, this.keyLength),
                PublicComponent = ToFixedBytes(this.publicValue, this.keyLength),
                Factor = ToFixedBytes(this.factor, this.keyLength),
                KeyLength = this.keyLength
            };

            this.PrivateKey = new DiffieHellmanKey
            {
                Type = AsymmetricKeyType.Private,
                Generator = ToFixedBytes(this.generator, this.keyLength),
                Modulus = ToFixedBytes(this.prime, this.keyLength),
                PublicComponent = ToFixedBytes(this.publicValue, this.keyLength),
                Factor = ToFixedBytes(this.factor, this.keyLength),
                PrivateComponent = ToFixedBytes(this.privateKey, this.keyLength),
                KeyLength = this.keyLength
            };
        }

        protected ManagedDiffieHellman(DiffieHellmanKey importKey)
        {
            if (importKey == null)
            {
                throw new ArgumentNullException(nameof(importKey));
            }

            this.keyLength = importKey.KeyLength;

            this.prime = ToBigInteger(importKey.Modulus);
            this.generator = ToBigInteger(importKey.Generator);
            this.factor = ToBigInteger(importKey.Factor);
            this.privateKey = ToBigInteger(importKey.PrivateComponent);
            this.publicValue = ToBigInteger(importKey.PublicComponent);

            this.PublicKey = new DiffieHellmanKey
            {
                Type = AsymmetricKeyType.Public,
                Generator = importKey.Generator,
                Modulus = importKey.Modulus,
                PublicComponent = importKey.PublicComponent,
                Factor = importKey.Factor,
                KeyLength = this.keyLength,
                CacheExpiry = importKey.CacheExpiry
            };

            this.PrivateKey = new DiffieHellmanKey
            {
                Type = AsymmetricKeyType.Private,
                Generator = importKey.Generator,
                Modulus = importKey.Modulus,
                PublicComponent = importKey.PublicComponent,
                Factor = importKey.Factor,
                PrivateComponent = importKey.PrivateComponent,
                KeyLength = this.keyLength,
                CacheExpiry = importKey.CacheExpiry
            };
        }

        private static BigInteger GeneratePrivateKey(int keyLength)
        {
            // Generate a random private key x where 2 <= x < p-1
            // We generate keyLength random bytes and ensure it's positive and in range

            var bytes = new byte[keyLength];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }

            // Ensure positive by appending a zero byte (BigInteger is little-endian)
            var withSign = new byte[keyLength + 1];
            Array.Reverse(bytes); // Convert from big-endian to little-endian for BigInteger
            Array.Copy(bytes, 0, withSign, 0, keyLength);
            withSign[keyLength] = 0; // ensure positive

            var result = new BigInteger(withSign);

            // Ensure it's at least 2
            if (result < 2)
            {
                result = 2;
            }

            return result;
        }

        /// <summary>
        /// Parse big-endian bytes to a positive BigInteger.
        /// </summary>
        private static BigInteger ToBigInteger(ReadOnlyMemory<byte> bigEndianBytes)
        {
            var arr = bigEndianBytes.ToArray();
            Array.Reverse(arr); // big-endian to little-endian

            // Ensure positive by adding a zero byte if the high bit is set
            if (arr.Length > 0 && arr[arr.Length - 1] >= 0x80)
            {
                var padded = new byte[arr.Length + 1];
                Array.Copy(arr, 0, padded, 0, arr.Length);
                return new BigInteger(padded);
            }

            return new BigInteger(arr);
        }

        /// <summary>
        /// Convert a BigInteger to a fixed-length big-endian byte array.
        /// </summary>
        private static byte[] ToFixedBytes(BigInteger value, int length)
        {
            var littleEndian = value.ToByteArray();
            Array.Reverse(littleEndian); // to big-endian

            // Strip leading zeros added by BigInteger for sign
            int start = 0;
            while (start < littleEndian.Length - 1 && littleEndian[start] == 0)
            {
                start++;
            }

            var trimmed = new byte[littleEndian.Length - start];
            Array.Copy(littleEndian, start, trimmed, 0, trimmed.Length);

            if (trimmed.Length >= length)
            {
                // Take the last 'length' bytes
                var result = new byte[length];
                Array.Copy(trimmed, trimmed.Length - length, result, 0, length);
                return result;
            }
            else
            {
                // Pad with leading zeros
                var result = new byte[length];
                Array.Copy(trimmed, 0, result, length - trimmed.Length, trimmed.Length);
                return result;
            }
        }

        public IExchangeKey PublicKey { get; }

        public IExchangeKey PrivateKey { get; }

        public ReadOnlyMemory<byte> GenerateAgreement()
        {
            if (this.partnerKey == BigInteger.Zero)
            {
                throw new InvalidOperationException("A partner key must be imported first");
            }

            var sharedSecret = BigInteger.ModPow(this.partnerKey, this.privateKey, this.prime);

            return ToFixedBytes(sharedSecret, this.keyLength);
        }

        public void ImportPartnerKey(IExchangeKey publicKey)
        {
            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }

            this.partnerKey = ToBigInteger(publicKey.PublicComponent);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposedValue)
            {
                this.disposedValue = true;
            }
        }

        public void Dispose()
        {
            this.Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
