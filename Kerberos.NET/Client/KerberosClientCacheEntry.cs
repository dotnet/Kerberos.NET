// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Client
{
    public struct KerberosClientCacheEntry : IEquatable<KerberosClientCacheEntry>
    {
        public KrbEncryptionKey SessionKey { get; set; }

        public KrbKdcRep KdcResponse { get; set; }

        public int Nonce { get; set; }

        public KrbPrincipalName SName { get; set; }

        public TicketFlags Flags { get; set; }

        public override bool Equals(object obj)
        {
            if (obj is KerberosClientCacheEntry entry)
            {
                return this.Equals(entry);
            }

            return false;
        }

        public bool Equals(KerberosClientCacheEntry other)
        {
            if (other.KdcResponse != this.KdcResponse)
            {
                return false;
            }

            if (other.SessionKey != this.SessionKey)
            {
                return false;
            }

            if (other.Nonce != this.Nonce)
            {
                return false;
            }

            if (!other.SName.Matches(this.SName))
            {
                return false;
            }

            return true;
        }

        public override int GetHashCode()
        {
            return EntityHashCode.GetHashCode(this.KdcResponse, this.SessionKey, this.Nonce);
        }

        public static bool operator ==(KerberosClientCacheEntry left, KerberosClientCacheEntry right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(KerberosClientCacheEntry left, KerberosClientCacheEntry right)
        {
            return !(left == right);
        }
    }
}
