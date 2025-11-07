// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Entities.GssApi
{
    /// <summary>
    /// GSS-API major status codes as defined in RFC 2743
    /// </summary>
    public enum GssMajorStatus : uint
    {
        /// <summary>
        /// The routine completed successfully.
        /// </summary>
        GSS_S_COMPLETE = 0,

        /// <summary>
        /// The routine must be called again to complete its function.
        /// </summary>
        GSS_S_CONTINUE_NEEDED = 1 << 0,

        /// <summary>
        /// The token had a duplicate sequence number.
        /// </summary>
        GSS_S_DUPLICATE_TOKEN = 1 << 1,

        /// <summary>
        /// The token's validity period has expired.
        /// </summary>
        GSS_S_OLD_TOKEN = 1 << 2,

        /// <summary>
        /// A later token has already been processed.
        /// </summary>
        GSS_S_UNSEQ_TOKEN = 1 << 3,

        /// <summary>
        /// An expected per-message token was not received.
        /// </summary>
        GSS_S_GAP_TOKEN = 1 << 4,

        /// <summary>
        /// An unsupported mechanism was requested.
        /// </summary>
        GSS_S_BAD_MECH = 1 << 16,

        /// <summary>
        /// An invalid name was supplied.
        /// </summary>
        GSS_S_BAD_NAME = 2 << 16,

        /// <summary>
        /// A supplied name was of an unsupported type.
        /// </summary>
        GSS_S_BAD_NAMETYPE = 3 << 16,

        /// <summary>
        /// Incorrect channel bindings were supplied.
        /// </summary>
        GSS_S_BAD_BINDINGS = 4 << 16,

        /// <summary>
        /// An invalid status code was supplied.
        /// </summary>
        GSS_S_BAD_STATUS = 5 << 16,

        /// <summary>
        /// A token had an invalid MIC.
        /// </summary>
        GSS_S_BAD_SIG = 6 << 16,

        /// <summary>
        /// Alias for GSS_S_BAD_SIG.
        /// </summary>
        GSS_S_BAD_MIC = GSS_S_BAD_SIG,

        /// <summary>
        /// No credentials were supplied or the credentials were unavailable or inaccessible.
        /// </summary>
        GSS_S_NO_CRED = 7 << 16,

        /// <summary>
        /// No context has been established.
        /// </summary>
        GSS_S_NO_CONTEXT = 8 << 16,

        /// <summary>
        /// A token was invalid.
        /// </summary>
        GSS_S_DEFECTIVE_TOKEN = 9 << 16,

        /// <summary>
        /// A credential was invalid.
        /// </summary>
        GSS_S_DEFECTIVE_CREDENTIAL = 10 << 16,

        /// <summary>
        /// The referenced credentials have expired.
        /// </summary>
        GSS_S_CREDENTIALS_EXPIRED = 11 << 16,

        /// <summary>
        /// The context has expired.
        /// </summary>
        GSS_S_CONTEXT_EXPIRED = 12 << 16,

        /// <summary>
        /// Miscellaneous failure.
        /// </summary>
        GSS_S_FAILURE = 13 << 16,

        /// <summary>
        /// The quality-of-protection requested could not be provided.
        /// </summary>
        GSS_S_BAD_QOP = 14 << 16,

        /// <summary>
        /// The operation is forbidden by local security policy.
        /// </summary>
        GSS_S_UNAUTHORIZED = 15 << 16,

        /// <summary>
        /// The operation or option is unavailable.
        /// </summary>
        GSS_S_UNAVAILABLE = 16 << 16,

        /// <summary>
        /// The requested credential element already exists.
        /// </summary>
        GSS_S_DUPLICATE_ELEMENT = 17 << 16,

        /// <summary>
        /// The provided name was not a mechanism name.
        /// </summary>
        GSS_S_NAME_NOT_MN = 18 << 16,
    }

    /// <summary>
    /// GSS-API minor status codes (mechanism-specific).
    /// </summary>
    public enum GssMinorStatus : uint
    {
        /// <summary>
        /// No error.
        /// </summary>
        GSS_S_COMPLETE = 0,

        /// <summary>
        /// Generic error.
        /// </summary>
        GSS_S_FAILURE = 1,
    }

    /// <summary>
    /// Represents a GSS-API status result containing major and minor status codes.
    /// </summary>
    public struct GssStatus
    {
        /// <summary>
        /// Gets or sets the major status code.
        /// </summary>
        public GssMajorStatus MajorStatus { get; set; }

        /// <summary>
        /// Gets or sets the minor (mechanism-specific) status code.
        /// </summary>
        public uint MinorStatus { get; set; }

        /// <summary>
        /// Gets a value indicating whether the operation completed successfully.
        /// </summary>
        public bool IsSuccess => MajorStatus == GssMajorStatus.GSS_S_COMPLETE;

        /// <summary>
        /// Gets a value indicating whether the operation requires continuation.
        /// </summary>
        public bool IsContinueNeeded => MajorStatus == GssMajorStatus.GSS_S_CONTINUE_NEEDED;

        /// <summary>
        /// Creates a successful status.
        /// </summary>
        public static GssStatus Complete => new GssStatus
        {
            MajorStatus = GssMajorStatus.GSS_S_COMPLETE,
            MinorStatus = 0
        };

        /// <summary>
        /// Creates a continue needed status.
        /// </summary>
        public static GssStatus ContinueNeeded => new GssStatus
        {
            MajorStatus = GssMajorStatus.GSS_S_CONTINUE_NEEDED,
            MinorStatus = 0
        };

        public override string ToString()
        {
            return $"MajorStatus: {MajorStatus}, MinorStatus: {MinorStatus}";
        }
    }
}
