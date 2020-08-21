// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Entities
{
    public enum NegotiateMessageType
    {
        MESSAGE_TYPE_INITIATOR_NEGO = 0,
        MESSAGE_TYPE_ACCEPTOR_NEGO,
        MESSAGE_TYPE_INITIATOR_META_DATA,
        MESSAGE_TYPE_ACCEPTOR_META_DATA,
        MESSAGE_TYPE_CHALLENGE,
        MESSAGE_TYPE_AP_REQUEST,
        MESSAGE_TYPE_VERIFY,
        MESSAGE_TYPE_ALERT,
    }
}