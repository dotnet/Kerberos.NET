using System;
using System.Collections.Generic;

namespace Syfuhs.Security.Kerberos
{
    internal class SimpleTicketCacheValidator : ITicketCacheValidator
    {
        private static readonly HashSet<string> TokenCache = new HashSet<string>();

        public bool Add(string ticketIdentifier)
        {
            return TokenCache.Add(ticketIdentifier);
        }
    }
}