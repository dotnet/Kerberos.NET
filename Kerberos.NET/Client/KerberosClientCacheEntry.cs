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

        public DateTimeOffset AuthTime { get; set; }

        public DateTimeOffset? StartTime { get; set; }

        public DateTimeOffset EndTime { get; set; }

        public DateTimeOffset? RenewTill { get; set; }

        public int BranchId { get; set; }

        public string KdcCalled { get; set; }

        public int CacheFlags { get; set; }

        public bool IsValid(bool ignoreExpiration = false)
        {
            return this.KdcResponse != null &&
                  (ignoreExpiration || (this.StartTime <= DateTimeOffset.UtcNow &&
                                        this.EndTime >= DateTimeOffset.UtcNow));
        }

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

            if (other.AuthTime != this.AuthTime)
            {
                return false;
            }

            if (other.StartTime != this.StartTime)
            {
                return false;
            }

            if (other.EndTime != this.EndTime)
            {
                return false;
            }

            if (other.RenewTill != this.RenewTill)
            {
                return false;
            }

            return true;
        }

        public override int GetHashCode()
        {
            return EntityHashCode.GetHashCode(
                this.KdcResponse,
                this.SessionKey,
                this.Nonce,
                this.AuthTime,
                this.StartTime,
                this.EndTime,
                this.RenewTill
            );
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
