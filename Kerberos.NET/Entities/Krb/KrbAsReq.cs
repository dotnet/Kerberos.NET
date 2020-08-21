// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;

namespace Kerberos.NET.Entities
{
    public partial class KrbAsReq : IKerberosMessage
    {
        public KrbAsReq()
        {
            this.MessageType = MessageType.KRB_AS_REQ;
        }

        public MessageType KerberosMessageType => this.MessageType;

        public string Realm => this.Body.Realm;

        [KerberosIgnore]
        public int KerberosProtocolVersionNumber => this.ProtocolVersionNumber;

        public static KrbAsReq CreateAsReq(KerberosCredential credential, AuthenticationOptions options)
        {
            if (credential == null)
            {
                throw new ArgumentNullException(nameof(credential));
            }

            var kdcOptions = (KdcOptions)(options & ~AuthenticationOptions.AllAuthentication);

            var hostAddress = Environment.MachineName;

            var pacRequest = new KrbPaPacRequest
            {
                IncludePac = options.HasFlag(AuthenticationOptions.IncludePacRequest)
            };

            var padata = new List<KrbPaData>()
            {
                new KrbPaData
                {
                    Type = PaDataType.PA_PAC_REQUEST,
                    Value = pacRequest.Encode()
                }
            };

            var asreq = new KrbAsReq()
            {
                Body = new KrbKdcReqBody
                {
                    Addresses = new[]
                    {
                        new KrbHostAddress
                        {
                            AddressType = AddressType.NetBios,
                            Address = Encoding.ASCII.GetBytes(hostAddress.PadRight(16, ' '))
                        }
                    },
                    CName = ExtractCName(credential),
                    EType = KerberosConstants.ETypes.ToArray(),
                    KdcOptions = kdcOptions,
                    Nonce = KerberosConstants.GetNonce(),
                    RTime = KerberosConstants.EndOfTime,
                    Realm = credential.Domain,
                    SName = new KrbPrincipalName
                    {
                        Type = PrincipalNameType.NT_SRV_INST,
                        Name = new[] { "krbtgt", credential.Domain }
                    },
                    Till = KerberosConstants.EndOfTime
                },
                PaData = padata.ToArray()
            };

            if (options.HasFlag(AuthenticationOptions.PreAuthenticate))
            {
                credential.TransformKdcReq(asreq);
            }

            return asreq;
        }

        private static KrbPrincipalName ExtractCName(KerberosCredential credential)
        {
            var principalName = KrbPrincipalName.FromString(credential.UserName);

            if (principalName.IsServiceName)
            {
                return principalName;
            }

            return KrbPrincipalName.FromString(
                credential.UserName,
                PrincipalNameType.NT_ENTERPRISE,
                credential.Domain
            );
        }
    }
}
