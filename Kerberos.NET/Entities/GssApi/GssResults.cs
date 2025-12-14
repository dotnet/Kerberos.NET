// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Entities.GssApi
{
    /// <summary>
    /// Result of GSS_Acquire_cred operation.
    /// </summary>
    public class GssAcquireCredResult
    {
        public GssMajorStatus MajorStatus { get; set; }
        public uint MinorStatus { get; set; }
        public GssCredential OutputCredHandle { get; set; }
        public GssOidSet ActualMechs { get; set; }
        public uint TimeRec { get; set; }
    }

    /// <summary>
    /// Result of GSS_Add_cred operation.
    /// </summary>
    public class GssAddCredResult
    {
        public GssMajorStatus MajorStatus { get; set; }
        public uint MinorStatus { get; set; }
        public GssCredential OutputCredHandle { get; set; }
        public GssOidSet ActualMechs { get; set; }
        public uint InitiatorTimeRec { get; set; }
        public uint AcceptorTimeRec { get; set; }
    }

    /// <summary>
    /// Result of GSS_Init_sec_context operation.
    /// </summary>
    public class GssInitSecContextResult
    {
        public GssMajorStatus MajorStatus { get; set; }
        public uint MinorStatus { get; set; }
        public GssSecurityContext ContextHandle { get; set; }
        public GssOid ActualMechType { get; set; }
        public GssBuffer OutputToken { get; set; }
        public GssContextEstablishmentFlag RetFlags { get; set; }
        public uint TimeRec { get; set; }
    }

    /// <summary>
    /// Result of GSS_Accept_sec_context operation.
    /// </summary>
    public class GssAcceptSecContextResult
    {
        public GssMajorStatus MajorStatus { get; set; }
        public uint MinorStatus { get; set; }
        public GssSecurityContext ContextHandle { get; set; }
        public GssName SrcName { get; set; }
        public GssOid MechType { get; set; }
        public GssBuffer OutputToken { get; set; }
        public GssContextEstablishmentFlag RetFlags { get; set; }
        public uint TimeRec { get; set; }
        public GssCredential DelegatedCredHandle { get; set; }
    }
}
