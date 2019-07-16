using System.Threading.Tasks;
using Kerberos.NET.Asn1;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Server
{
    public class PaDataETypeInfo2Handler : KdcPreAuthenticationHandlerBase
    {
        public PaDataETypeInfo2Handler(IRealmService service)
            : base(service)
        {
        }

        public override async Task<KrbPaData> Validate(KrbKdcReq asReq, IKerberosPrincipal principal)
        {
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

            return new KrbPaData
            {
                Type = PaDataType.PA_ETYPE_INFO2,
                Value = etypeInfo.Encode().AsMemory()
            };
        }
    }
}