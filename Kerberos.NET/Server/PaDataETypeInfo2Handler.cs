using Kerberos.NET.Asn1;
using Kerberos.NET.Entities;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    public class PaDataETypeInfo2Handler : KdcPreAuthenticationHandlerBase
    {
        public PaDataETypeInfo2Handler(IRealmService service)
            : base(service)
        {
        }

        public override async Task PostValidate(IKerberosPrincipal principal, List<KrbPaData> preAuthRequirements)
        {
            if (preAuthRequirements.Count <= 0)
            {
                // we don't want to include this if nothing is required otherwise we could
                // trigger a pre-auth check later in the flow or by the client in response

                return;
            }

            var cred = await principal.RetrieveLongTermCredential();

            var etypeInfo = new KrbETypeInfo2
            {
                ETypeInfo = new[] {
                    new  KrbETypeInfo2Entry {
                        EType = cred.EncryptionType,
                        Salt = cred.Salt
                    }
                }
            };

            var infoPaData = new KrbPaData
            {
                Type = PaDataType.PA_ETYPE_INFO2,
                Value = etypeInfo.Encode().AsMemory()
            };

            preAuthRequirements.Add(infoPaData);
        }
    }
}