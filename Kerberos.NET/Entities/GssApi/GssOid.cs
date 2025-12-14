// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;

namespace Kerberos.NET.Entities.GssApi
{
    /// <summary>
    /// Represents a GSS-API Object Identifier (OID).
    /// </summary>
    public class GssOid : IEquatable<GssOid>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="GssOid"/> class.
        /// </summary>
        /// <param name="value">The OID string value (e.g., "1.2.840.113554.1.2.2").</param>
        public GssOid(string value)
        {
            this.Value = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets the OID string value.
        /// </summary>
        public string Value { get; }

        /// <summary>
        /// Kerberos V5 mechanism OID.
        /// </summary>
        public static readonly GssOid GSS_MECH_KRB5 = new GssOid(MechType.KerberosGssApi);

        /// <summary>
        /// Kerberos V5 legacy mechanism OID.
        /// </summary>
        public static readonly GssOid GSS_MECH_KRB5_LEGACY = new GssOid(MechType.KerberosV5Legacy);

        /// <summary>
        /// SPNEGO mechanism OID.
        /// </summary>
        public static readonly GssOid GSS_MECH_SPNEGO = new GssOid(MechType.SPNEGO);

        /// <summary>
        /// NTLM mechanism OID.
        /// </summary>
        public static readonly GssOid GSS_MECH_NTLM = new GssOid(MechType.NTLM);

        public override string ToString() => Value;

        public override bool Equals(object obj)
        {
            return Equals(obj as GssOid);
        }

        public bool Equals(GssOid other)
        {
            return other != null && Value == other.Value;
        }

        public override int GetHashCode()
        {
            return Value.GetHashCode();
        }

        public static bool operator ==(GssOid left, GssOid right)
        {
            if (ReferenceEquals(left, null))
            {
                return ReferenceEquals(right, null);
            }

            return left.Equals(right);
        }

        public static bool operator !=(GssOid left, GssOid right)
        {
            return !(left == right);
        }
    }

    /// <summary>
    /// Represents a set of GSS-API OIDs.
    /// </summary>
    public class GssOidSet : IDisposable
    {
        private bool disposed = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="GssOidSet"/> class.
        /// </summary>
        public GssOidSet()
        {
            this.Oids = new System.Collections.Generic.List<GssOid>();
        }

        /// <summary>
        /// Gets the list of OIDs in this set.
        /// </summary>
        public System.Collections.Generic.List<GssOid> Oids { get; }

        /// <summary>
        /// Gets the count of OIDs in this set.
        /// </summary>
        public int Count => Oids.Count;

        /// <summary>
        /// Adds an OID to the set.
        /// </summary>
        public void Add(GssOid oid)
        {
            if (oid == null)
            {
                throw new ArgumentNullException(nameof(oid));
            }

            if (!Oids.Contains(oid))
            {
                Oids.Add(oid);
            }
        }

        /// <summary>
        /// Tests whether an OID is a member of the set.
        /// </summary>
        public bool Contains(GssOid oid)
        {
            return Oids.Contains(oid);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    Oids.Clear();
                }

                disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
