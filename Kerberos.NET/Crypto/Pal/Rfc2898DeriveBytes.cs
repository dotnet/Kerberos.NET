// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Reflection;
using System.Security.Cryptography;
using static Kerberos.NET.BinaryExtensions;
using Rfc2898DeriveBytesAlgorithm = System.Security.Cryptography.Rfc2898DeriveBytes;

namespace Kerberos.NET.Crypto
{
    public class Rfc2898DeriveBytes : IKeyDerivationAlgorithm
    {
        private static readonly ConstructorInfo Rfc2898Ctor = TryFindConstructor();

        /// <summary>
        /// Indicates whether this should attempt to locate the native
        /// implementation before falling back to a managed implementation.
        /// </summary>
        public static bool AttemptReflectionLookup { get; set; } = true;

        /// <summary>
        /// Indicate whether this should enforce using the native implementation
        /// (i.e. a certified version) or allow the use of the managed implementation.
        /// The default is to require the native implementation.
        /// </summary>
        public static bool RequireNativeImplementation { get; set; } = true;

        public ReadOnlyMemory<byte> Derive(
            HashAlgorithmName algName,
            ReadOnlyMemory<byte> passwordBytes,
            ReadOnlyMemory<byte> salt,
            int k, // iterations
            int keySize
        )
        {
            var passwordArray = TryGetArrayFast(passwordBytes);
            var saltArray = TryGetArrayFast(salt);

            if (algName == HashAlgorithmName.SHA1)
            {
                return DeriveSha1(passwordArray, saltArray, k, keySize);
            }
            else if (algName == HashAlgorithmName.SHA256)
            {
                return DeriveSha256(passwordArray, saltArray, k, keySize);
            }
            else if (algName == HashAlgorithmName.SHA384)
            {
                return DeriveSha384(passwordArray, saltArray, k, keySize);
            }

            throw new InvalidOperationException($"Unknown hash algorithm {algName}");
        }

        private static ReadOnlyMemory<byte> DeriveSha1(byte[] passwordBytes, byte[] salt, int iterations, int keySize)
        {
            // "Weak" algorithm is used because that's what Kerberos requires

            Rfc2898DeriveBytesAlgorithm algo = TryGetAlgorithm(passwordBytes, salt, iterations, HashAlgorithmName.SHA1);

            if (algo != null)
            {
                return algo.GetBytes(keySize);
            }

            using (var hmac = CryptoPal.Platform.HmacSha1(passwordBytes))
            {
                return DeriveManually(salt, iterations, keySize, hmac);
            }
        }

        private static ReadOnlyMemory<byte> DeriveSha256(byte[] passwordBytes, byte[] salt, int iterations, int keySize)
        {
            Rfc2898DeriveBytesAlgorithm algo = TryGetAlgorithm(passwordBytes, salt, iterations, HashAlgorithmName.SHA256);

            if (algo != null)
            {
                return algo.GetBytes(keySize);
            }

            using (var hmac = CryptoPal.Platform.HmacSha256(passwordBytes))
            {
                return DeriveManually(salt, iterations, keySize, hmac);
            }
        }

        private static Rfc2898DeriveBytesAlgorithm TryGetAlgorithm(byte[] passwordBytes, byte[] salt, int iterations, HashAlgorithmName hash)
        {
            // .NET Standard 2.0 doesn't contain this particular ctor overload
            // so we're going to see if it exists and use it instead

            if (!AttemptReflectionLookup || Rfc2898Ctor == null)
            {
                return null;
            }

            var algo = Rfc2898Ctor.Invoke(new object[] { passwordBytes, salt, iterations, hash });

            return algo as Rfc2898DeriveBytesAlgorithm;
        }

        private static ReadOnlyMemory<byte> DeriveSha384(byte[] passwordBytes, byte[] salt, int iterations, int keySize)
        {
            Rfc2898DeriveBytesAlgorithm algo = TryGetAlgorithm(passwordBytes, salt, iterations, HashAlgorithmName.SHA384);

            if (algo != null)
            {
                return algo.GetBytes(keySize);
            }

            using (var hmac = CryptoPal.Platform.HmacSha384(passwordBytes))
            {
                return DeriveManually(salt, iterations, keySize, hmac);
            }
        }

        private static ReadOnlyMemory<byte> DeriveManually(ReadOnlyMemory<byte> salt, int iterations, int keySize, IHmacAlgorithm hmac)
        {
            if (RequireNativeImplementation)
            {
                throw new CryptographicException("The caller requires the use of the native implementation but the platform doesn't support it.");
            }

            // This is here because .NET Standard doesn't include the built-in
            // ctor so it's possible the particular framework doesn't support it.
            // It's mostly based off the original Rfc2898DeriveBytes implementation.
            //
            // https://github.com/aspnet/DataProtection/blob/9941fb825fcbeefec898093755553679410d8a6b/src/Microsoft.AspNetCore.Cryptography.KeyDerivation/PBKDF2/ManagedPbkdf2Provider.cs

            // PBKDF2 is defined in NIST SP800-132, Sec. 5.3.
            // http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf

            byte[] retVal = new byte[keySize];

            int numBytesWritten = 0;
            int numBytesRemaining = keySize;

            // For each block index, U_0 := Salt || block_index

            byte[] saltWithBlockIndex = new byte[checked(salt.Length + sizeof(uint))];

            salt.CopyTo(saltWithBlockIndex);

            for (uint blockIndex = 1; numBytesRemaining > 0; blockIndex++)
            {
                // write the block index out as big-endian

                saltWithBlockIndex[saltWithBlockIndex.Length - 4] = (byte)(blockIndex >> 24);
                saltWithBlockIndex[saltWithBlockIndex.Length - 3] = (byte)(blockIndex >> 16);
                saltWithBlockIndex[saltWithBlockIndex.Length - 2] = (byte)(blockIndex >> 8);
                saltWithBlockIndex[saltWithBlockIndex.Length - 1] = (byte)blockIndex;

                // U_1 = PRF(U_0) = PRF(Salt || block_index)
                // T_blockIndex = U_1

                byte[] u_iter = hmac.ComputeHashArray(saltWithBlockIndex); // this is U_1
                byte[] t_blockIndex = u_iter;

                for (int iter = 1; iter < iterations; iter++)
                {
                    u_iter = hmac.ComputeHashArray(u_iter);

                    for (int i = 0; i < u_iter.Length; i++)
                    {
                        t_blockIndex[i] ^= u_iter[i];
                    }

                    // At this point, the 'U_iter' variable actually contains U_{iter+1} (due to indexing differences).
                }

                // At this point, we're done iterating on this block, so copy the transformed block into retVal.

                int numBytesToCopy = Math.Min(numBytesRemaining, t_blockIndex.Length);

                Buffer.BlockCopy(t_blockIndex, 0, retVal, numBytesWritten, numBytesToCopy);

                numBytesWritten += numBytesToCopy;
                numBytesRemaining -= numBytesToCopy;
            }

            // retVal := T_1 || T_2 || ... || T_n, where T_n may be truncated to meet the desired output length

            return retVal;
        }

        private static ConstructorInfo TryFindConstructor()
        {
            try
            {
                // All recent versions of Framework and Core support this specific constructor
                // however .NET Standard 2.0 doesn't expose it as an API because of annoying
                // cross-platform reasons so we need to work around that limitation

                var type = typeof(Rfc2898DeriveBytesAlgorithm);

                return type.GetConstructor(new[]
                {
                    typeof(byte[]),
                    typeof(byte[]),
                    typeof(int),
                    typeof(HashAlgorithmName)
                });
            }
            catch
            {
                // The only reason this would fail is if the ctor didn't exist.
                // We handle that below and fall back to the slow method then.

                return null;
            }
        }
    }
}