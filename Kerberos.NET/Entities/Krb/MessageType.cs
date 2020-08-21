// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Entities
{
    public static class MessageTypeExtensions
    {
        /// <summary>
        /// Determines whether the provided type is within the bounds of the expected range of message types.
        /// </summary>
        /// <param name="type">The value to compare</param>
        /// <returns>Returns true if the value matches an expected type otherwise returns false</returns>
        public static bool IsValidMessageType(this MessageType type)
        {
            return (type >= MessageType.KRB_AS_REQ &&
                    type <= MessageType.KRB_RESERVED17) ||
                   (type >= MessageType.KRB_SAFE &&
                    type <= MessageType.KRB_CRED) ||
                    type == MessageType.KRB_ERROR;
        }
    }

    public enum MessageType
    {
        /// <summary>
        /// Request for initial authentication
        /// </summary>
        KRB_AS_REQ = 10,

        /// <summary>
        /// Response to KRB_AS_REQ request
        /// </summary>
        KRB_AS_REP = 11,

        /// <summary>
        /// Request for authentication based on TGT
        /// </summary>
        KRB_TGS_REQ = 12,

        /// <summary>
        /// Response to KRB_TGS_REQ request
        /// </summary>
        KRB_TGS_REP = 13,

        /// <summary>
        /// Application request to server
        /// </summary>
        KRB_AP_REQ = 14,

        /// <summary>
        /// Response to KRB_AP_REQ_MUTUAL
        /// </summary>
        KRB_AP_REP = 15,

        /// <summary>
        /// Reserved for user-to-user krb_tgt_request
        /// </summary>
        KRB_RESERVED16 = 16,

        /// <summary>
        /// Reserved for user-to-user krb_tgt_reply
        /// </summary>
        KRB_RESERVED17 = 17,

        /// <summary>
        /// Safe (checksummed) application message
        /// </summary>
        KRB_SAFE = 20,

        /// <summary>
        /// Private (encrypted) application message
        /// </summary>
        KRB_PRIV = 21,

        /// <summary>
        /// Private (encrypted) message to forward credentials
        /// </summary>
        KRB_CRED = 22,

        /// <summary>
        /// Error response
        /// </summary>
        KRB_ERROR = 30
    }
}