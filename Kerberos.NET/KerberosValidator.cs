// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET
{
    public class KerberosValidator : IKerberosValidator
    {
        private readonly ITicketReplayValidator tokenCache;

        private readonly KeyTable keytab;

        [Obsolete("The use of this constructor is obsolete and should be replaced with KerberosValidator(KerberosKey, ...) or KerberosValidator(KeyTable, ...)")]
        public KerberosValidator(byte[] key, ILoggerFactory logger = null, ITicketReplayValidator ticketCache = null)
            : this(new KerberosKey(key), logger, ticketCache)
        {
        }

        public KerberosValidator(KerberosKey key, ILoggerFactory logger = null, ITicketReplayValidator ticketCache = null)
            : this(new KeyTable(key), logger, ticketCache)
        {
        }

        public KerberosValidator(KeyTable keytab, ILoggerFactory logger = null, ITicketReplayValidator ticketCache = null)
        {
            this.keytab = keytab;

            this.logger = logger.CreateLoggerSafe<KerberosValidator>();

            this.tokenCache = ticketCache ?? new TicketReplayValidator(logger);

            this.ValidateAfterDecrypt = ValidationActions.All;
        }

        private readonly ILogger<KerberosValidator> logger;

        public ValidationActions ValidateAfterDecrypt { get; set; }

        private Func<DateTimeOffset> nowFunc;

        public Func<DateTimeOffset> Now
        {
            get { return this.nowFunc ?? (this.nowFunc = () => DateTimeOffset.UtcNow); }
            set { this.nowFunc = value; }
        }

        public async Task<DecryptedKrbApReq> Validate(byte[] requestBytes)
        {
            var kerberosRequest = MessageParser.ParseContext(requestBytes);

            this.logger.LogTrace("Validating Kerberos request {Request}", kerberosRequest);

            DecryptedKrbApReq decryptedToken;

            try
            {
                decryptedToken = kerberosRequest.DecryptApReq(this.keytab);
            }
            catch(Exception ex)
            {
                this.logger.WarnCryptographicException(ex, this.keytab);
                throw;
            }

            if (decryptedToken == null)
            {
                return null;
            }

            this.logger.LogTrace("Kerberos request decrypted {SName}", decryptedToken.SName.FullyQualifiedName);

            decryptedToken.Now = this.Now;

            if (this.ValidateAfterDecrypt > 0)
            {
                await this.Validate(decryptedToken).ConfigureAwait(true);
            }

            return decryptedToken;
        }

        public void Validate(PrivilegedAttributeCertificate pac, KrbPrincipalName sname)
        {
            if (pac == null)
            {
                throw new ArgumentNullException(nameof(pac));
            }

            pac.ServerSignature.Validate(this.keytab, sname);
        }

        protected virtual async Task Validate(DecryptedKrbApReq decryptedToken)
        {
            if (decryptedToken == null)
            {
                throw new ArgumentNullException(nameof(decryptedToken));
            }

            var sequence = this.ObscureSequence(decryptedToken.Authenticator.SequenceNumber ?? 0);
            var container = this.ObscureContainer(decryptedToken.Ticket.CRealm);

            var entry = new TicketCacheEntry
            {
                Key = sequence,
                Container = container,
                Expires = decryptedToken.Ticket.EndTime
            };

            var replayDetected = true;

            var detectReplay = this.ValidateAfterDecrypt.HasFlag(ValidationActions.Replay);

            if (!detectReplay)
            {
                decryptedToken.Validate(this.ValidateAfterDecrypt);
                replayDetected = false;
            }
            else if (!await this.tokenCache.Contains(entry).ConfigureAwait(true))
            {
                decryptedToken.Validate(this.ValidateAfterDecrypt);

                if (await this.tokenCache.Add(entry).ConfigureAwait(true))
                {
                    replayDetected = false;
                }
            }

            if (replayDetected)
            {
                throw new ReplayException($"Replay detected in container '{entry.Container}' with key {entry.Key}.");
            }
        }

        protected virtual string ObscureContainer(string realm)
        {
            return Hash(realm);
        }

        protected virtual string ObscureSequence(int sequenceNumber)
        {
            return Hash(sequenceNumber.ToString(CultureInfo.InvariantCulture));
        }

        private static string Hash(string value)
        {
            using (var sha = CryptoPal.Platform.Sha256())
            {
                return Hex.Hexify(
                    sha.ComputeHash(Encoding.UTF8.GetBytes(value)).Span
                );
            }
        }
    }
}
