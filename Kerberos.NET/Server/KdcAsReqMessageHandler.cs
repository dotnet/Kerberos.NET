// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;
using static Kerberos.NET.Entities.KerberosConstants;

namespace Kerberos.NET.Server
{
    public class KdcAsReqMessageHandler : KdcMessageHandlerBase
    {
        private static readonly PaDataType[] PreAuthAscendingPriority = new PaDataType[]
        {
            PaDataType.PA_PK_AS_REQ,
            PaDataType.PA_ENC_TIMESTAMP,
        };

        private readonly ILogger<KdcAsReqMessageHandler> logger;

        public KdcAsReqMessageHandler(ReadOnlyMemory<byte> message, KdcServerOptions options)
            : base(message, options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            this.logger = options.Log.CreateLoggerSafe<KdcAsReqMessageHandler>();

            this.PostProcessAuthHandlers[PaDataType.PA_ETYPE_INFO2] = service => new PaDataETypeInfo2Handler(service);

            this.RegisterPreAuthHandlers(this.PostProcessAuthHandlers);
        }

        protected override MessageType MessageType => MessageType.KRB_AS_REQ;

        protected override IKerberosMessage DecodeMessageCore(ReadOnlyMemory<byte> message)
        {
            var asReq = KrbAsReq.DecodeApplication(message);

            this.SetRealmContext(asReq.Realm);

            return asReq;
        }

        protected override IEnumerable<PaDataType> GetOrderedPreAuth(PreAuthenticationContext preauth)
        {
            if (preauth == null)
            {
                throw new ArgumentNullException(nameof(preauth));
            }

            var keys = this.PreAuthHandlers.Keys.Intersect(preauth.Principal.SupportedPreAuthenticationTypes);

            keys = keys.OrderBy(k => Array.IndexOf(PreAuthAscendingPriority, k));

            return keys;
        }

        public override void QueryPreValidate(PreAuthenticationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            KrbAsReq asReq = (KrbAsReq)context.Message;
            KrbPrincipalName krbtgtName = KrbPrincipalName.WellKnown.Krbtgt(asReq.Body.Realm);

            context.Principal = this.RealmService.Principals.Find(asReq.Body.CName, asReq.Realm);
            context.ServicePrincipal = this.RealmService.Principals.Find(krbtgtName, asReq.Realm);
        }

        public override async Task QueryPreValidateAsync(PreAuthenticationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            KrbAsReq asReq = (KrbAsReq)context.Message;
            KrbPrincipalName krbtgtName = KrbPrincipalName.WellKnown.Krbtgt(asReq.Body.Realm);

            context.Principal = await this.RealmService.Principals.FindAsync(asReq.Body.CName, asReq.Realm).ConfigureAwait(false);
            context.ServicePrincipal = await this.RealmService.Principals.FindAsync(krbtgtName, asReq.Realm).ConfigureAwait(false);
        }

        public override void ValidateTicketRequest(PreAuthenticationContext preauth)
        {
            if (preauth?.Principal == null)
            {
                return;
            }

            try
            {
                var preauthReq = this.ProcessPreAuth(preauth);

                if (preauth.PaData == null)
                {
                    preauth.PaData = Array.Empty<KrbPaData>();
                }

                preauth.PaData = preauth.PaData.Union(preauthReq).ToArray();
            }
            catch (KerberosValidationException kex)
            {
                this.logger.LogWarning(kex, "AS-REQ failed processing for principal {Principal}", preauth.Principal.PrincipalName);

                preauth.Failure = kex;
            }
        }

        public override ReadOnlyMemory<byte> ExecuteCore(PreAuthenticationContext context)
        {
            // 1. check what pre-auth validation is required for user
            // 2. enumerate all pre-auth handlers that are available
            //      - fail hard if required doesn't intersect available
            // 3. if pre-auth is required and not present, return error prompting for it
            // 4. if pre-auth is present, validate it
            // 5. if pre-auth failed, return error
            // 6. if some pre-auth succeeded, return error
            // 7. if all required validation succeeds, generate PAC, TGT, and return it

            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.Failure != null)
            {
                return this.PreAuthFailed(context);
            }

            KrbAsReq asReq = (KrbAsReq)context.Message;

            if (context.Principal == null)
            {
                this.logger.LogInformation("User {User} not found in realm {Realm}", asReq.Body.CName.FullyQualifiedName, asReq.Body.Realm);

                return GenerateError(KerberosErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN, null, asReq.Body.Realm, asReq.Body.CName.FullyQualifiedName);
            }

            if (!context.PreAuthenticationSatisfied)
            {
                return this.RequirePreAuth(context);
            }

            return this.GenerateAsRep(asReq, context);
        }

        private ReadOnlyMemory<byte> GenerateAsRep(KrbAsReq asReq, PreAuthenticationContext context)
        {
            // 1. detect if specific PAC contents are requested (claims)
            // 2. if requested generate PAC for user
            // 3. stuff PAC into ad-if-relevant pa-data of krbtgt ticket
            // 4. look up krbtgt account
            // 5. encrypt against krbtgt
            // 6. done

            var rst = new ServiceTicketRequest
            {
                Principal = context.Principal,
                EncryptedPartKey = context.EncryptedPartKey,
                EncryptedPartEType = context.EncryptedPartEType,
                ServicePrincipal = context.ServicePrincipal,
                Addresses = asReq.Body.Addresses,
                Nonce = asReq.Body.Nonce,
                Now = this.RealmService.Now(),
                StartTime = asReq.Body.From ?? DateTimeOffset.MinValue,
                EndTime = asReq.Body.Till,
                MaximumTicketLifetime = this.RealmService.Settings.SessionLifetime,
                Flags = TicketFlags.Initial | KrbKdcRep.DefaultFlags,
                PreferredClientEType = GetPreferredEType(
                    asReq.Body.EType,
                    this.RealmService.Configuration.Defaults.PermittedEncryptionTypes,
                    this.RealmService.Configuration.Defaults.AllowWeakCrypto
                ),
                Compatibility = this.RealmService.Settings.Compatibility,
            };

            if (context.ClientAuthority != PaDataType.PA_NONE)
            {
                rst.Flags |= TicketFlags.PreAuthenticated;
            }

            // Canonicalize means the CName in the reply is allowed to be different from the CName in the request.
            // If this is not allowed, then we must use the CName from the request. Otherwise, we will set the CName
            // to what we have in our realm, i.e. user@realm.
            if (!asReq.Body.KdcOptions.HasFlag(KdcOptions.Canonicalize))
            {
                rst.SamAccountName = asReq.Body.CName.FullyQualifiedName;
            }

            if (rst.EncryptedPartKey == null)
            {
                rst.EncryptedPartKey = rst.Principal.RetrieveLongTermCredential();
            }

            if (context.IncludePac == null)
            {
                context.IncludePac = DetectPacRequirement(asReq);
            }

            rst.IncludePac = context.IncludePac ?? false;

            // this is set here instead of in GenerateServiceTicket because GST is used by unit tests to
            // generate tickets with weird lifetimes for scenario testing and we don't want to break that

            rst.ClampLifetime();

            var asRep = KrbAsRep.GenerateTgt(rst, this.RealmService);

            if (context.PaData != null)
            {
                asRep.PaData = context.PaData.ToArray();
            }

            return asRep.EncodeApplication();
        }

        private ReadOnlyMemory<byte> PreAuthFailed(PreAuthenticationContext context)
        {
            var err = new KrbError
            {
                ErrorCode = KerberosErrorCode.KDC_ERR_PREAUTH_FAILED,
                EText = context.Failure.Message,
                Realm = this.RealmService.Name,
                SName = KrbPrincipalName.FromPrincipal(context.Principal)
            };

            err.StampServerTime();

            return err.EncodeApplication();
        }

        private ReadOnlyMemory<byte> RequirePreAuth(PreAuthenticationContext context)
        {
            this.logger.LogTrace("AS-REQ requires pre-auth for user {User}", context.Principal.PrincipalName);

            var err = new KrbError
            {
                ErrorCode = KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED,
                EText = string.Empty,
                Realm = this.RealmService.Name,
                SName = KrbPrincipalName.FromPrincipal(context.Principal),
                EData = new KrbMethodData
                {
                    MethodData = context.PaData.ToArray()
                }.Encode()
            };

            err.StampServerTime();

            return err.EncodeApplication();
        }
    }
}
