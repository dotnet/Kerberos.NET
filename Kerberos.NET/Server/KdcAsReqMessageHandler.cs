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
            PaDataType.PA_SPAKE,
            PaDataType.PA_ENCRYPTED_CHALLENGE,
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

            this.PreAuthHandlers[PaDataType.PA_SPAKE] = service => new PaDataSpakeHandler(service);

            this.RegisterPreAuthHandlers(this.PostProcessAuthHandlers);

            // Register freshness after RegisterPreAuthHandlers so it only runs
            // during post-processing and doesn't add state during pre-auth
            this.PostProcessAuthHandlers[PaDataType.PA_AS_FRESHNESS] = service => new PaDataFreshnessHandler(service);
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

            // If FAST is in use, strengthen the reply key before generating the TGT
            var fastState = GetFastState(context);

            var rst = new ServiceTicketRequest
            {
                ClientRealmName = asReq.Body.Realm,
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
            // to what we have in our realm, i.e. user@realm (which will be inferred from the Principal set above).
            //
            // RFC 4120 section 3.1.5. Receipt of KRB_AS_REP Message
            // -----------------------------------------------------
            // If the reply message type is KRB_AS_REP, then the client verifies that the cname and crealm fields in
            // the cleartext portion of the reply match what it requested.
            //
            // RFC 6806 section 6. Name Canonicalization
            // -----------------------------------------
            // If the "canonicalize" KDC option is set, then the KDC MAY change the client and server principal names
            // and types in the AS response and ticket returned from those in the request.
            if (!asReq.Body.KdcOptions.HasFlag(KdcOptions.Canonicalize))
            {
                if (this.RealmService.Settings.Compatibility.HasFlag(KerberosCompatibilityFlags.EnableSpecCompliantCNameHandling))
                {
                    rst.ClientName = asReq.Body.CName;
                }
                else
                {
                    #pragma warning disable CS0618 // Type or member is obsolete
                    rst.SamAccountName = asReq.Body.CName.FullyQualifiedName;
                    #pragma warning restore CS0618 // Type or member is obsolete
                }

            }

            if (asReq.Body.KdcOptions.HasFlag(KdcOptions.RequestAnonymous))
            {
                rst.Flags |= TicketFlags.Anonymous;
                rst.Flags &= ~(TicketFlags.Forwardable | TicketFlags.Proxiable | TicketFlags.Renewable);
                rst.ClientName = KrbPrincipalName.WellKnown.Anonymous();
                rst.ClientRealmName = KerberosConstants.AnonymousRealm;
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

            // FAST reply wrapping: strengthen the reply key before generating the TGT
            // so the enc-part is encrypted with the strengthened key
            var fastPaData = PaDataFastHandler.WrapFastResponse(
                fastState,
                context.PaData?.ToArray(),
                null,
                context
            );

            // Now EncryptedPartKey has been strengthened if FAST is active
            rst.EncryptedPartKey = context.EncryptedPartKey;

            var asRep = KrbAsRep.GenerateTgt(rst, this.RealmService);

            if (context.PaData != null)
            {
                var paDataList = context.PaData.ToList();

                // Now generate the full FAST response with the ticket checksum
                if (fastState?.ArmorKey != null)
                {
                    var fullFastPaData = PaDataFastHandler.WrapFastResponse(
                        fastState,
                        context.PaData?.ToArray(),
                        asRep,
                        context
                    );

                    if (fullFastPaData != null)
                    {
                        paDataList.Add(fullFastPaData);
                    }
                }

                asRep.PaData = paDataList.ToArray();
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

            // If FAST is active, wrap the error in a FAST response
            var fastState = GetFastState(context);
            var fastError = PaDataFastHandler.WrapFastError(fastState, err);

            if (fastError != null)
            {
                err.EData = new KrbMethodData
                {
                    MethodData = new[] { fastError }
                }.Encode();
            }

            return err.EncodeApplication();
        }

        private ReadOnlyMemory<byte> RequirePreAuth(PreAuthenticationContext context)
        {
            this.logger.LogTrace("AS-REQ requires pre-auth for user {User}", context.Principal.PrincipalName);

            var methodData = context.PaData.ToList();

            // If FAST is active, include FAST-wrapped hints
            var fastState = GetFastState(context);

            if (fastState?.ArmorKey != null)
            {
                // Add PA_ENCRYPTED_CHALLENGE hint when FAST is active
                if (!methodData.Any(p => p.Type == PaDataType.PA_ENCRYPTED_CHALLENGE))
                {
                    methodData.Add(new KrbPaData { Type = PaDataType.PA_ENCRYPTED_CHALLENGE });
                }
            }

            var err = new KrbError
            {
                ErrorCode = KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED,
                EText = string.Empty,
                Realm = this.RealmService.Name,
                SName = KrbPrincipalName.FromPrincipal(context.Principal),
                EData = new KrbMethodData
                {
                    MethodData = methodData.ToArray()
                }.Encode()
            };

            err.StampServerTime();

            return err.EncodeApplication();
        }

        private static FastState GetFastState(PreAuthenticationContext context)
        {
            if (context.PreAuthenticationState.TryGetValue(PaDataType.PA_FX_FAST, out PaDataState state)
                && state is FastState fastState)
            {
                return fastState;
            }

            return null;
        }
    }
}
