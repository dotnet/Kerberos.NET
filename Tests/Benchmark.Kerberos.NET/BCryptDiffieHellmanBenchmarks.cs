using System;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnostics.Windows.Configs;
using Kerberos.NET.Crypto;

namespace Benchmark.Kerberos.NET
{
    //[EtwProfiler]
    [MemoryDiagnoser]
    [NativeMemoryProfiler]
    [RankColumn, RPlotExporter]
    public class BCryptDiffieHellmanBenchmarks
    {

        [Benchmark]
        public ReadOnlyMemory<byte> Modp14()
        {
            using (var alice = new BCryptDiffieHellmanOakleyGroup14())
            using (var bob = new BCryptDiffieHellmanOakleyGroup14())
            {
                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                return alice.GenerateAgreement();
            }
        }

        [Benchmark]
        public ReadOnlyMemory<byte> Modp2()
        {
            using (var alice = new BCryptDiffieHellmanOakleyGroup2())
            using (var bob = new BCryptDiffieHellmanOakleyGroup2())
            {
                alice.ImportPartnerKey(bob.PublicKey);
                bob.ImportPartnerKey(alice.PublicKey);

                return alice.GenerateAgreement();
            }
        }
    }
}
