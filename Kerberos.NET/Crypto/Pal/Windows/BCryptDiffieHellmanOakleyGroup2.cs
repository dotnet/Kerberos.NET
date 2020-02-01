using System;

namespace Kerberos.NET.Crypto
{
    public class BCryptDiffieHellmanOakleyGroup2 : BCryptDiffieHellman
    {
        protected override ReadOnlyMemory<byte> Modulus => Oakley.Group2.Prime;

        protected override ReadOnlyMemory<byte> Generator => Oakley.Group2.Generator;

        protected override ReadOnlyMemory<byte> Factor { get; set; } = Oakley.Group2.Factor;
    }
}
