namespace Kerberos.NET.Crypto
{
    public class BCryptDiffieHellmanOakleyGroup2 : BCryptDiffieHellman
    {
        protected override byte[] Modulus => Oakley.Group2.Prime;

        protected override byte[] Generator => Oakley.Group2.Generator;

        protected override byte[] Factor { get; set; } = Oakley.Group2.Factor;
    }
}
