// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Entities.GssApi
{
    /// <summary>
    /// Name types as defined in GSS-API.
    /// </summary>
    public static class GssNameType
    {
        /// <summary>
        /// Indicates a host-based service name (e.g., service@hostname).
        /// </summary>
        public static readonly GssOid GSS_C_NT_HOSTBASED_SERVICE = new GssOid("1.2.840.113554.1.2.1.4");

        /// <summary>
        /// Indicates a user name.
        /// </summary>
        public static readonly GssOid GSS_C_NT_USER_NAME = new GssOid("1.2.840.113554.1.2.1.1");

        /// <summary>
        /// Indicates a machine UID name.
        /// </summary>
        public static readonly GssOid GSS_C_NT_MACHINE_UID_NAME = new GssOid("1.2.840.113554.1.2.1.2");

        /// <summary>
        /// Indicates a string UID name.
        /// </summary>
        public static readonly GssOid GSS_C_NT_STRING_UID_NAME = new GssOid("1.2.840.113554.1.2.1.3");

        /// <summary>
        /// Indicates an exported name.
        /// </summary>
        public static readonly GssOid GSS_C_NT_EXPORT_NAME = new GssOid("1.3.6.1.5.6.4");

        /// <summary>
        /// Indicates an anonymous name.
        /// </summary>
        public static readonly GssOid GSS_C_NT_ANONYMOUS = new GssOid("1.3.6.1.5.6.3");

        /// <summary>
        /// Kerberos principal name.
        /// </summary>
        public static readonly GssOid GSS_KRB5_NT_PRINCIPAL_NAME = new GssOid("1.2.840.113554.1.2.2.1");
    }

    /// <summary>
    /// Represents a GSS-API name (principal).
    /// </summary>
    public class GssName : IDisposable
    {
        private bool disposed = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="GssName"/> class.
        /// </summary>
        /// <param name="name">The name string.</param>
        /// <param name="nameType">The name type OID.</param>
        public GssName(string name, GssOid nameType = null)
        {
            this.Name = name ?? throw new ArgumentNullException(nameof(name));
            this.NameType = nameType ?? GssNameType.GSS_C_NT_USER_NAME;
        }

        /// <summary>
        /// Gets the name string.
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the name type.
        /// </summary>
        public GssOid NameType { get; private set; }

        /// <summary>
        /// Gets a value indicating whether this is a mechanism name (MN).
        /// </summary>
        public bool IsMechanismName { get; internal set; }

        /// <summary>
        /// Gets the mechanism OID if this is a mechanism name.
        /// </summary>
        public GssOid MechanismType { get; internal set; }

        public override string ToString() => Name;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    Name = null;
                    NameType = null;
                    MechanismType = null;
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
