namespace Kerberos.NET.Crypto
{
    public class BCryptDiffieHellmanOakleyGroup14 : BCryptDiffieHellman
    {
        protected override byte[] Modulus => Oakley.Group14.Prime;

        protected override byte[] Generator => Oakley.Group14.Generator;

        protected override byte[] Factor { get; set; } = Oakley.Group14.Factor;
    }
}
