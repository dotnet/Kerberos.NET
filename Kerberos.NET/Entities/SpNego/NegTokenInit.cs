using Kerberos.NET.Asn1;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Kerberos.NET.Entities
{
    public class NegTokenInit
    {
        public NegTokenInit Decode(Asn1Element sequence)
        {
            for (var i = 0; i < sequence.Count; i++)
            {
                var element = sequence[i];

                switch (element.ContextSpecificTag)
                {
                    case 0:
                        SetMechTypes(element);
                        break;
                    case 1: // reqFlags
                        break;
                    case 2:
                        MechToken = new MechToken().Decode(element, MechTypes);
                        break;
                    case 3: // mecListMIC
                        break;
                }
            }

            return this;
        }

        private void SetMechTypes(Asn1Element sequence)
        {
            for (var i = 0; i < sequence.Count; i++)
            {
                var element = sequence[i];

                for (var j = 0; j < element.Count; j++)
                {
                    var childNode = element[j];

                    if (childNode.UniversalTag == UniversalTag.ObjectIdentifier)
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

        public MechToken MechToken;
    }
}
