using Kerberos.NET.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Kerberos.NET.Entities
{
    public class NegTokenInit
    {
        public NegTokenInit(Asn1Element sequence)
        {
            for (var i = 0; i < sequence.Count; i++)
            {
                var element = sequence[i];

                switch (element.ContextSpecificTag)
                {
                    case 0:
                        SetMechTypes(element);
                        break;

                    case 2:
                        MechToken = new InitialContextToken(element[0], MechTypes);
                        break;
                }
            }
        }

        private void SetMechTypes(Asn1Element sequence)
        {
            for (var i = 0; i < sequence.Count; i++)
            {
                var element = sequence[i];

                for (var j = 0; j < element.Count; j++)
                {
                    var childNode = element[j];

                    if (childNode.ContextSpecificTag == MechType.ContextTag)
                    {
                        MechTypes.Add(new MechType(childNode.AsString()));
                    }
                }
            }

            if (MechTypes.Count == 1 && MechTypes.Any(m => m.Oid == MechType.NTLM))
            {
                throw new NotSupportedException("NTLM is not supported");
            }
        }

        private List<MechType> mechTypes;

        public List<MechType> MechTypes { get { return mechTypes ?? (mechTypes = new List<MechType>()); } }

        public InitialContextToken MechToken { get; private set; }
    }
}
