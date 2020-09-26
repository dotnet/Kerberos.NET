// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography.X509Certificates;
using Kerberos.NET.Configuration;
using Kerberos.NET.Entities;

namespace Kerberos.NET
{
    /// <summary>
    /// The parameters used during a TGS-REQ
    /// </summary>
    public struct RequestServiceTicket : IEquatable<RequestServiceTicket>
    {
        /// <summary>
        /// The SPN of the service a ticket is requested
        /// </summary>
        public string ServicePrincipalName { get; set; }

        /// <summary>
        /// The authentication options for this request
        /// </summary>
        public ApOptions ApOptions { get; set; }

        /// <summary>
        /// The username a service ticket is requested on-behalf-of
        /// </summary>
        public string S4uTarget { get; set; }

        public X509Certificate2 S4uTargetCertificate { get; set; }

        /// <summary>
        /// The evidence ticket used to prove the requestor is allowed to
        /// request a ticket on-behalf-of the S4uTarget user
        /// </summary>
        public KrbTicket S4uTicket { get; set; }

        /// <summary>
        /// The TGT of the service receiving the requested ticket to initiate
        /// the U2U encrypted in session key flow
        /// </summary>
        public KrbTicket UserToUserTicket { get; set; }

        /// <summary>
        /// KDC request options
        /// </summary>
        public KdcOptions KdcOptions { get; set; }

        /// <summary>
        /// A hint provided in the TGS-REQ to help the KDC find the user details
        /// before having to decrypt their TGT
        /// </summary>
        public KrbPrincipalName CNameHint { get; set; }

        /// <summary>
        /// The realm of the authenticated user
        /// </summary>
        public string Realm { get; set; }

        /// <summary>
        /// Indicates which flags should be sent to the target within the GSS Delegation Info structure
        /// </summary>
        public GssContextEstablishmentFlag GssContextFlags { get; set; }

        /// <summary>
        /// Includes additional configuration details for the request.
        /// </summary>
        public Krb5Config Configuration { get; set; }

        /// <summary>
        /// Indicates whether the client should cache the ticket. Default null indicates the client should decide.
        /// </summary>
        public bool? CacheTicket { get; set; }

        public override bool Equals(object obj)
        {
            if (obj is RequestServiceTicket rst)
            {
                return this.Equals(rst);
            }

            return false;
        }

        public override int GetHashCode()
        {
            return EntityHashCode.GetHashCode(
                this.ApOptions,
                this.CNameHint,
                this.GssContextFlags,
                this.KdcOptions,
                this.Realm,
                this.S4uTarget,
                this.S4uTicket,
                this.ServicePrincipalName,
                this.UserToUserTicket
            );
        }

        public static bool operator ==(RequestServiceTicket left, RequestServiceTicket right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(RequestServiceTicket left, RequestServiceTicket right)
        {
            return !(left == right);
        }

        public bool Equals(RequestServiceTicket other)
        {
            if (other.ApOptions != this.ApOptions)
            {
                return false;
            }

            if (other.CNameHint != this.CNameHint)
            {
                return false;
            }

            if (other.GssContextFlags != this.GssContextFlags)
            {
                return false;
            }

            if (other.KdcOptions != this.KdcOptions)
            {
                return false;
            }

            if (other.Realm != this.Realm)
            {
                return false;
            }

            if (other.S4uTarget != this.S4uTarget)
            {
                return false;
            }

            if (other.S4uTicket != this.S4uTicket)
            {
                return false;
            }

            if (other.ServicePrincipalName != this.ServicePrincipalName)
            {
                return false;
            }

            if (other.UserToUserTicket != this.UserToUserTicket)
            {
                return false;
            }

            return true;
        }
    }
}
