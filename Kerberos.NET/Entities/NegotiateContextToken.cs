using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    [Choice]
    public sealed class NegotiateContextToken : ContextToken
    {
        public NegotiateContextToken(Asn1Element sequence) 
            : base(sequence)
        {
        }

        public NegTokenInit NegotiationToken { get; set; }

        public NegTokenTarg SubsequentContextToken { get; set; }

        protected override void ParseContextSpecific(Asn1Element element)
        {
            switch (element.ContextSpecificTag)
            {
                case 0:
                    NegotiationToken = new NegTokenInit(element[0]);
                    break;
                case 1:
                    SubsequentContextToken = new NegTokenTarg();
                    SubsequentContextToken.Decode(element[0]);
                    break;
            }
        }
    }
}
