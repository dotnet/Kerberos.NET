using System;
using Syfuhs.Security.Kerberos.Entities;
using Syfuhs.Security.Kerberos.Crypto;
using System.Globalization;

namespace Syfuhs.Security.Kerberos
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

        public KerberosValidator(KeyTable keytab, ITicketReplayValidator ticketCache = null)
        {
            this.keytab = keytab;

            TokenCache = ticketCache ?? new TicketReplayValidator();

            ValidateAfterDecrypt = ValidationAction.All;
        }

        public Action<string> Logger = (s) => { };

        public ValidationAction ValidateAfterDecrypt { get; set; }
        
        public DecryptedData Validate(byte[] requestBytes)
        {
            var kerberosRequest = KerberosRequest.Parse(requestBytes);

            Logger(kerberosRequest.ToString());

            var decryptedToken = kerberosRequest.Decrypt(keytab);

            if (decryptedToken == null)
            {
                return null;
            }
            
            Logger(decryptedToken.ToString());

            if (ValidateAfterDecrypt > 0)
            {
                Validate(decryptedToken);
            }

            return decryptedToken;
        }

        protected virtual void Validate(DecryptedData decryptedToken)
        {
            var sequence = ObscureSequence(decryptedToken.Authenticator.SequenceNumber);
            var container = ObscureContainer(decryptedToken.Ticket.CRealm);

            var entry = new TicketCacheEntry
            {
                Key = sequence,
                Container = container,
                Expires = decryptedToken.Ticket.EndTime
            };

            var replay = true;

            var detectReplay = ValidateAfterDecrypt.HasFlag(ValidationAction.Replay);

            if (!detectReplay)
            {
                decryptedToken.Validate(ValidateAfterDecrypt);
                replay = false;
            }
            else if (!TokenCache.Contains(entry))
            {
                decryptedToken.Validate(ValidateAfterDecrypt);

                if (TokenCache.Add(entry))
                {
                    replay = false;
                }
            }

            if (replay)
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

            return Convert.ToBase64String(hash);
        }
    }
}