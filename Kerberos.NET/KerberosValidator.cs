using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;
using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Kerberos.NET
{
    public class KerberosValidator : IKerberosValidator
    {
        private readonly ITicketReplayValidator TokenCache;

        private readonly KeyTable keytab;

        public KerberosValidator(byte[] key, ILoggerFactory logger = null, ITicketReplayValidator ticketCache = null)
            : this(new KerberosKey(key), logger, ticketCache)
        { }

        public KerberosValidator(KerberosKey key, ILoggerFactory logger = null, ITicketReplayValidator ticketCache = null)
            : this(new KeyTable(key), logger, ticketCache)
        { }

        public KerberosValidator(KeyTable keytab, ILoggerFactory logger = null, ITicketReplayValidator ticketCache = null)
        {
            this.keytab = keytab;

            this.logger = logger.CreateLoggerSafe<KerberosValidator>();

            TokenCache = ticketCache ?? new TicketReplayValidator(logger);

            ValidateAfterDecrypt = ValidationActions.All;
        }

        private readonly ILogger<KerberosValidator> logger;

        public ValidationActions ValidateAfterDecrypt { get; set; }

        private Func<DateTimeOffset> nowFunc;

        public Func<DateTimeOffset> Now
        {
            get { return nowFunc ?? (nowFunc = () => DateTimeOffset.UtcNow); }
            set { nowFunc = value; }
        }

        public async Task<DecryptedKrbApReq> Validate(byte[] requestBytes)
        {
            var kerberosRequest = MessageParser.ParseContext(requestBytes);

            logger.LogTrace("Validating Kerberos request {Request}", kerberosRequest);

            var decryptedToken = kerberosRequest.DecryptApReq(keytab);

            if (decryptedToken == null)
            {
                return null;
            }

            logger.LogTrace("Kerberos request decrypted {Request}", decryptedToken);

            decryptedToken.Now = Now;

            if (ValidateAfterDecrypt > 0)
            {
                await Validate(decryptedToken);
            }

            return decryptedToken;
        }

        public void Validate(PrivilegedAttributeCertificate pac, KrbPrincipalName sname)
        {
            pac.ServerSignature.Validate(keytab, sname);
        }

        protected virtual async Task Validate(DecryptedKrbApReq decryptedToken)
        {
            var sequence = ObscureSequence(decryptedToken.Authenticator.SequenceNumber ?? 0);
            var container = ObscureContainer(decryptedToken.Ticket.CRealm);

            var entry = new TicketCacheEntry
            {
                Key = sequence,
                Container = container,
                Expires = decryptedToken.Ticket.EndTime
            };

            var replayDetected = true;

            var detectReplay = ValidateAfterDecrypt.HasFlag(ValidationActions.Replay);

            if (!detectReplay)
            {
                decryptedToken.Validate(ValidateAfterDecrypt);
                replayDetected = false;
            }
            else if (!await TokenCache.Contains(entry))
            {
                decryptedToken.Validate(ValidateAfterDecrypt);

                if (await TokenCache.Add(entry))
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
            using (var sha = SHA256.Create())
            {
                return Hex.Hexify(
                    sha.ComputeHash(Encoding.UTF8.GetBytes(value))
                );
            }
        }
    }
}