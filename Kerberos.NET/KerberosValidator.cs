using System;
using Kerberos.NET.Entities;
using Kerberos.NET.Crypto;
using System.Globalization;
using System.Threading.Tasks;
using System.Text;

#if NETSTANDARD1_3
using Microsoft.Extensions.Caching.Distributed;
#endif

namespace Kerberos.NET
{
    public class KerberosValidator : IKerberosValidator
    {
        private readonly ITicketReplayValidator TokenCache;

        private readonly KeyTable keytab;

        public KerberosValidator(byte[] key, ITicketReplayValidator ticketCache = null)
            : this(new KerberosKey(key), ticketCache)
        { }

        public KerberosValidator(KerberosKey key, ITicketReplayValidator ticketCache = null)
            : this(new KeyTable(key), ticketCache)
        { }
#if NETSTANDARD1_3
        public KerberosValidator(KeyTable keytab, ITicketReplayValidator ticketCache = null, IDistributedCache cache = null)
        {
            this.keytab = keytab;

            TokenCache = ticketCache ?? new TicketReplayValidator(cache);

            ValidateAfterDecrypt = ValidationActions.All;
        }
#else
        public KerberosValidator(KeyTable keytab, ITicketReplayValidator ticketCache = null)
        {
            this.keytab = keytab;

            TokenCache = ticketCache ?? new TicketReplayValidator();

            ValidateAfterDecrypt = ValidationActions.All;
        }
#endif
        private ILogger logger;

        public ILogger Logger
        {
            get { return logger ?? (logger = new DebugLogger()); }
            set { logger = value; }
        }

        public ValidationActions ValidateAfterDecrypt { get; set; }

        private Func<DateTimeOffset> nowFunc;

        public Func<DateTimeOffset> Now
        {
            get { return nowFunc ?? (nowFunc = () => DateTimeOffset.UtcNow); }
            set { nowFunc = value; }
        }

        public async Task<DecryptedData> Validate(byte[] requestBytes)
        {
            var kerberosRequest = KerberosRequest.Parse(requestBytes);

            Logger.WriteLine(kerberosRequest.ToString());

            var decryptedToken = kerberosRequest.Decrypt(keytab);

            if (decryptedToken == null)
            {
                return null;
            }

            Logger.WriteLine(decryptedToken.ToString());

            decryptedToken.Now = Now;

            if (ValidateAfterDecrypt > 0)
            {
                await Validate(decryptedToken);
            }

            return decryptedToken;
        }

        protected virtual async Task Validate(DecryptedData decryptedToken)
        {
            var sequence = ObscureSequence(decryptedToken.Authenticator.SequenceNumber);
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
            else if (!(await TokenCache.Contains(entry)))
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

        protected virtual string ObscureSequence(long sequenceNumber)
        {
            return Hash(sequenceNumber.ToString(CultureInfo.InvariantCulture));
        }

        private static string Hash(string value)
        {
            var hash = KerberosHash.SHA256(value);

            return ToBase64UrlString(hash);
        }

        private static string ToBase64UrlString(byte[] input)
        {
            StringBuilder result = new StringBuilder(Convert.ToBase64String(input).TrimEnd('='));

            result.Replace('+', '-');
            result.Replace('/', '_');

            return result.ToString();
        }
    }
}