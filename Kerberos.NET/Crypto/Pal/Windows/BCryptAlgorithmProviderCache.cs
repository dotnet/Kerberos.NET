using System;
using System.Collections.Concurrent;

namespace Kerberos.NET.Crypto.Pal.Windows
{
    internal static class BCryptAlgorithmProviderCache
    {
        private static readonly ConcurrentDictionary<string, IntPtr> s_cache = new ConcurrentDictionary<string, IntPtr>();

        public static IntPtr GetCachedBCrypptAlgorithmProvider(string algorithm)
        {
            return s_cache.GetOrAdd(algorithm, alg => CreateBCryptAlgorithmProvider(alg));
        }

        private static IntPtr CreateBCryptAlgorithmProvider(string algorithm)
        {
            Interop.BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, algorithm).CheckSuccess();
            return phAlgorithm;
        }
    }
}
