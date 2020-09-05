// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
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

            var config = credential.Configuration ?? Krb5Config.Default();

            var kdcOptions = (KdcOptions)(options & ~AuthenticationOptions.AllAuthentication);

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
                    Addresses = IncludeAddresses(config),
                    CName = ExtractCName(credential),
                    EType = KerberosConstants.GetPreferredETypes(config.Defaults.DefaultTicketEncTypes).ToArray(),
                    KdcOptions = kdcOptions,
                    Nonce = KerberosConstants.GetNonce(),
                    RTime = CalculateRenewTime(kdcOptions, config),
                    Realm = credential.Domain,
                    SName = new KrbPrincipalName
                    {
                        Type = PrincipalNameType.NT_SRV_INST,
                        Name = new[] { "krbtgt", credential.Domain }
                    },
                    Till = CalculateExpirationTime(config)
                },
                PaData = padata.ToArray()
            };

            if (options.HasFlag(AuthenticationOptions.PreAuthenticate))
            {
                credential.TransformKdcReq(asreq);
            }

            return asreq;
        }

        private static DateTimeOffset CalculateExpirationTime(Krb5Config config)
        {
            if (config.Defaults.TicketLifetime > TimeSpan.Zero)
            {
                return DateTimeOffset.UtcNow.Add(config.Defaults.TicketLifetime);
            }
            else
            {
                return KerberosConstants.EndOfTime;
            }
        }

        private static DateTimeOffset? CalculateRenewTime(KdcOptions kdcOptions, Krb5Config config)
        {
            if (!kdcOptions.HasFlag(KdcOptions.Renewable))
            {
                return null;
            }

            if (config.Defaults.RenewLifetime > TimeSpan.Zero)
            {
                return DateTimeOffset.UtcNow.Add(config.Defaults.RenewLifetime);
            }
            else
            {
                return KerberosConstants.EndOfTime;
            }
        }

        private static KrbHostAddress[] IncludeAddresses(Krb5Config config)
        {
            if (config.Defaults.NoAddresses)
            {
                return null;
            }

            var addresses = new List<KrbHostAddress>
            {
                KrbHostAddress.ParseAddress(Environment.MachineName.PadRight(16, ' '))
            };

            if (config.Defaults?.ExtraAddresses?.Any() ?? false)
            {
                addresses.AddRange(config.Defaults.ExtraAddresses.Select(a => KrbHostAddress.ParseAddress(a)));
            }

            return addresses.ToArray();
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
