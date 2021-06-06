// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Server
{
    public class PaDataETypeInfo2Handler : KdcPreAuthenticationHandlerBase
    {
        public PaDataETypeInfo2Handler(IRealmService service)
            : base(service)
        {
        }

        public override void PostValidate(IKerberosPrincipal principal, List<KrbPaData> preAuthRequirements)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            if (preAuthRequirements == null)
            {
                throw new ArgumentNullException(nameof(preAuthRequirements));
            }

            if (preAuthRequirements.Count <= 0)
            {
                // we don't want to include this if nothing is required otherwise we could
                // trigger a pre-auth check later in the flow or by the client in response

                return;
            }

            var entries = new List<KrbETypeInfo2Entry>();

            foreach (EncryptionType type in Enum.GetValues(typeof(EncryptionType)))
            {
                if (!CryptoService.SupportsEType(type, this.Service.Configuration.Defaults.AllowWeakCrypto))
                {
                    continue;
                }

                var cred = principal.RetrieveLongTermCredential(type);

                if (cred != null)
                {
                    entries.Add(new KrbETypeInfo2Entry
                    {
                        EType = cred.EncryptionType,
                        Salt = cred.Salt
                    });
                }
            }

            var etypeInfo = new KrbETypeInfo2
            {
                ETypeInfo = entries.ToArray()
            };

            var infoPaData = new KrbPaData
            {
                Type = PaDataType.PA_ETYPE_INFO2,
                Value = etypeInfo.Encode()
            };

            preAuthRequirements.Add(infoPaData);
        }
    }
}
