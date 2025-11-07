// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET.Entities.GssApi
{
    /// <summary>
    /// GSS-API context interface as defined in RFC 2743.
    /// Provides a standardized interface for authentication and message protection.
    /// </summary>
    public interface IGssContext : IDisposable
    {
        // ===========================
        // Credential Management
        // ===========================

        /// <summary>
        /// Acquires a GSS-API credential for use.
        /// </summary>
        /// <param name="desiredName">Name of principal whose credential should be acquired.</param>
        /// <param name="timeReq">Number of seconds that the credential should remain valid (0 for default).</param>
        /// <param name="desiredMechs">Set of mechanisms with which the credential may be used.</param>
        /// <param name="credUsage">How credential will be used (initiate, accept, or both).</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Result containing status and acquired credential information.</returns>
        Task<GssAcquireCredResult> GSS_Acquire_cred(
            GssName desiredName,
            uint timeReq,
            GssOidSet desiredMechs,
            GssCredentialUsage credUsage,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Releases a GSS-API credential.
        /// </summary>
        /// <param name="credHandle">The credential to release.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Release_cred(
            ref GssCredential credHandle,
            out uint minorStatus);

        /// <summary>
        /// Obtains information about a credential.
        /// </summary>
        /// <param name="credHandle">The credential to query.</param>
        /// <param name="name">The name of the credential's principal.</param>
        /// <param name="lifetime">Number of seconds for which the credential will remain valid.</param>
        /// <param name="credUsage">How the credential may be used.</param>
        /// <param name="mechanisms">Set of mechanisms for which the credential is valid.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Inquire_cred(
            GssCredential credHandle,
            out GssName name,
            out uint lifetime,
            out GssCredentialUsage credUsage,
            out GssOidSet mechanisms,
            out uint minorStatus);

        /// <summary>
        /// Adds a credential element to a credential.
        /// </summary>
        /// <param name="inputCredHandle">The credential to which an element should be added.</param>
        /// <param name="desiredName">Name of principal whose credential should be acquired.</param>
        /// <param name="desiredMech">Mechanism with which the new credential may be used.</param>
        /// <param name="credUsage">How the credential will be used.</param>
        /// <param name="initiatorTimeReq">Number of seconds for initiator credential to remain valid.</param>
        /// <param name="acceptorTimeReq">Number of seconds for acceptor credential to remain valid.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Result containing status and updated credential information.</returns>
        Task<GssAddCredResult> GSS_Add_cred(
            GssCredential inputCredHandle,
            GssName desiredName,
            GssOid desiredMech,
            GssCredentialUsage credUsage,
            uint initiatorTimeReq,
            uint acceptorTimeReq,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Obtains per-mechanism information about a credential.
        /// </summary>
        /// <param name="credHandle">The credential to query.</param>
        /// <param name="mechType">The mechanism for which information should be returned.</param>
        /// <param name="name">The name of the credential's principal.</param>
        /// <param name="initiatorLifetime">Number of seconds for which the initiator credential will remain valid.</param>
        /// <param name="acceptorLifetime">Number of seconds for which the acceptor credential will remain valid.</param>
        /// <param name="credUsage">How the credential may be used with the specified mechanism.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Inquire_cred_by_mech(
            GssCredential credHandle,
            GssOid mechType,
            out GssName name,
            out uint initiatorLifetime,
            out uint acceptorLifetime,
            out GssCredentialUsage credUsage,
            out uint minorStatus);

        // ===========================
        // Context Management
        // ===========================

        /// <summary>
        /// Initiates a security context with a peer application.
        /// </summary>
        /// <param name="initiatorCredHandle">Handle for credentials claimed.</param>
        /// <param name="contextHandle">Context handle for new context (null on first call).</param>
        /// <param name="targetName">Name of target.</param>
        /// <param name="mechType">Desired mechanism.</param>
        /// <param name="reqFlags">Contains various independent flags.</param>
        /// <param name="timeReq">Desired number of seconds for context to remain valid.</param>
        /// <param name="inputChanBindings">Application-specified channel bindings.</param>
        /// <param name="inputToken">Token received from peer application.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Result containing status and context information.</returns>
        Task<GssInitSecContextResult> GSS_Init_sec_context(
            GssCredential initiatorCredHandle,
            GssSecurityContext contextHandle,
            GssName targetName,
            GssOid mechType,
            GssContextEstablishmentFlag reqFlags,
            uint timeReq,
            GssChannelBindings inputChanBindings,
            GssBuffer inputToken,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Accepts a security context initiated by a peer application.
        /// </summary>
        /// <param name="contextHandle">Context handle for new context.</param>
        /// <param name="acceptorCredHandle">Handle for credentials claimed.</param>
        /// <param name="inputTokenBuffer">Token received from peer application.</param>
        /// <param name="inputChanBindings">Application-specified channel bindings.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Result containing status and context information.</returns>
        Task<GssAcceptSecContextResult> GSS_Accept_sec_context(
            GssSecurityContext contextHandle,
            GssCredential acceptorCredHandle,
            GssBuffer inputTokenBuffer,
            GssChannelBindings inputChanBindings,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Deletes a security context.
        /// </summary>
        /// <param name="contextHandle">Context handle identifying context to delete.</param>
        /// <param name="outputToken">Token to send to peer application.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Delete_sec_context(
            ref GssSecurityContext contextHandle,
            out GssBuffer outputToken,
            out uint minorStatus);

        /// <summary>
        /// Processes a token on a security context from a peer application.
        /// </summary>
        /// <param name="contextHandle">Context handle.</param>
        /// <param name="token">Token to process.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Process_context_token(
            GssSecurityContext contextHandle,
            GssBuffer token,
            out uint minorStatus);

        /// <summary>
        /// Determines for how long a context will remain valid.
        /// </summary>
        /// <param name="contextHandle">Context handle.</param>
        /// <param name="timeRec">Number of seconds for which the context will remain valid.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Context_time(
            GssSecurityContext contextHandle,
            out uint timeRec,
            out uint minorStatus);

        /// <summary>
        /// Obtains information about a security context.
        /// </summary>
        /// <param name="contextHandle">Context handle.</param>
        /// <param name="srcName">Name of context initiator.</param>
        /// <param name="targName">Name of context acceptor.</param>
        /// <param name="lifetimeRec">Number of seconds for which the context will remain valid.</param>
        /// <param name="mechType">Mechanism used.</param>
        /// <param name="ctxFlags">Context flags.</param>
        /// <param name="locallyInitiated">Non-zero if context was initiated by this application.</param>
        /// <param name="open">Non-zero if context is fully established.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Inquire_context(
            GssSecurityContext contextHandle,
            out GssName srcName,
            out GssName targName,
            out uint lifetimeRec,
            out GssOid mechType,
            out GssContextEstablishmentFlag ctxFlags,
            out bool locallyInitiated,
            out bool open,
            out uint minorStatus);

        /// <summary>
        /// Determines maximum message size for a given maximum wrapped message size.
        /// </summary>
        /// <param name="contextHandle">Context handle.</param>
        /// <param name="confReq">Whether confidentiality is requested.</param>
        /// <param name="qopReq">Quality of protection to be used.</param>
        /// <param name="reqOutputSize">Desired maximum size for output tokens.</param>
        /// <param name="maxInputSize">Maximum size for input messages.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Wrap_size_limit(
            GssSecurityContext contextHandle,
            bool confReq,
            uint qopReq,
            uint reqOutputSize,
            out uint maxInputSize,
            out uint minorStatus);

        /// <summary>
        /// Exports a security context for transfer to another process.
        /// </summary>
        /// <param name="contextHandle">Context handle identifying context to export.</param>
        /// <param name="interstageToken">Token to be transferred to target.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Export_sec_context(
            ref GssSecurityContext contextHandle,
            out GssBuffer interstageToken,
            out uint minorStatus);

        /// <summary>
        /// Imports a security context established by another process.
        /// </summary>
        /// <param name="interstageToken">Token received from context exporter.</param>
        /// <param name="contextHandle">Context handle of newly-created context.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Import_sec_context(
            GssBuffer interstageToken,
            out GssSecurityContext contextHandle,
            out uint minorStatus);

        // ===========================
        // Per-message Protection
        // ===========================

        /// <summary>
        /// Generates a cryptographic MIC for a message.
        /// </summary>
        /// <param name="contextHandle">Context handle.</param>
        /// <param name="qopReq">Quality of protection to be used.</param>
        /// <param name="messageBuffer">Message to be protected.</param>
        /// <param name="messageToken">Buffer to receive token.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_GetMIC(
            GssSecurityContext contextHandle,
            uint qopReq,
            GssBuffer messageBuffer,
            out GssBuffer messageToken,
            out uint minorStatus);

        /// <summary>
        /// Verifies that a cryptographic MIC matches a message.
        /// </summary>
        /// <param name="contextHandle">Context handle.</param>
        /// <param name="messageBuffer">Message to be verified.</param>
        /// <param name="tokenBuffer">Token associated with message.</param>
        /// <param name="qopState">Quality of protection used.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_VerifyMIC(
            GssSecurityContext contextHandle,
            GssBuffer messageBuffer,
            GssBuffer tokenBuffer,
            out uint qopState,
            out uint minorStatus);

        /// <summary>
        /// Wraps (protects and optionally encrypts) a message.
        /// </summary>
        /// <param name="contextHandle">Context handle.</param>
        /// <param name="confReq">Whether confidentiality is requested.</param>
        /// <param name="qopReq">Quality of protection to be used.</param>
        /// <param name="inputMessageBuffer">Message to be protected.</param>
        /// <param name="confState">Whether confidentiality was applied.</param>
        /// <param name="outputMessageBuffer">Protected message.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Wrap(
            GssSecurityContext contextHandle,
            bool confReq,
            uint qopReq,
            GssBuffer inputMessageBuffer,
            out bool confState,
            out GssBuffer outputMessageBuffer,
            out uint minorStatus);

        /// <summary>
        /// Unwraps (verifies and optionally decrypts) a message.
        /// </summary>
        /// <param name="contextHandle">Context handle.</param>
        /// <param name="inputMessageBuffer">Protected message.</param>
        /// <param name="outputMessageBuffer">Unprotected message.</param>
        /// <param name="confState">Whether message was encrypted.</param>
        /// <param name="qopState">Quality of protection used.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Unwrap(
            GssSecurityContext contextHandle,
            GssBuffer inputMessageBuffer,
            out GssBuffer outputMessageBuffer,
            out bool confState,
            out uint qopState,
            out uint minorStatus);

        // ===========================
        // Support Functions
        // ===========================

        /// <summary>
        /// Converts a status code to a displayable string.
        /// </summary>
        /// <param name="statusValue">Status code to convert.</param>
        /// <param name="statusType">Whether status code is major or minor.</param>
        /// <param name="mechType">Mechanism for which status code was generated.</param>
        /// <param name="messageContext">Allows iteration through multiple messages.</param>
        /// <param name="statusString">Human-readable status message.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Display_status(
            uint statusValue,
            int statusType,
            GssOid mechType,
            ref uint messageContext,
            out GssBuffer statusString,
            out uint minorStatus);

        /// <summary>
        /// Returns the set of mechanisms supported by the GSS-API implementation.
        /// </summary>
        /// <param name="mechSet">Set of mechanisms supported.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Indicate_mechs(
            out GssOidSet mechSet,
            out uint minorStatus);

        /// <summary>
        /// Compares two internal names.
        /// </summary>
        /// <param name="name1">First name to compare.</param>
        /// <param name="name2">Second name to compare.</param>
        /// <param name="nameEqual">Non-zero if names are equal.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Compare_name(
            GssName name1,
            GssName name2,
            out bool nameEqual,
            out uint minorStatus);

        /// <summary>
        /// Converts an internal name to a displayable string.
        /// </summary>
        /// <param name="inputName">Name to be displayed.</param>
        /// <param name="outputNameBuffer">Buffer to receive displayable name.</param>
        /// <param name="outputNameType">Type of the name.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Display_name(
            GssName inputName,
            out GssBuffer outputNameBuffer,
            out GssOid outputNameType,
            out uint minorStatus);

        /// <summary>
        /// Converts a displayable name to an internal name.
        /// </summary>
        /// <param name="inputNameBuffer">Buffer containing displayable name.</param>
        /// <param name="inputNameType">Type of name supplied.</param>
        /// <param name="outputName">Internal name.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Import_name(
            GssBuffer inputNameBuffer,
            GssOid inputNameType,
            out GssName outputName,
            out uint minorStatus);

        /// <summary>
        /// Releases a name.
        /// </summary>
        /// <param name="name">Name to release.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Release_name(
            ref GssName name,
            out uint minorStatus);

        /// <summary>
        /// Releases a buffer.
        /// </summary>
        /// <param name="buffer">Buffer to release.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Release_buffer(
            ref GssBuffer buffer,
            out uint minorStatus);

        /// <summary>
        /// Releases an OID set.
        /// </summary>
        /// <param name="set">OID set to release.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Release_OID_set(
            ref GssOidSet set,
            out uint minorStatus);

        /// <summary>
        /// Creates an empty OID set.
        /// </summary>
        /// <param name="oidSet">Empty OID set.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Create_empty_OID_set(
            out GssOidSet oidSet,
            out uint minorStatus);

        /// <summary>
        /// Adds an OID to an OID set.
        /// </summary>
        /// <param name="memberOid">OID to add.</param>
        /// <param name="oidSet">OID set to which OID should be added.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Add_OID_set_member(
            GssOid memberOid,
            ref GssOidSet oidSet,
            out uint minorStatus);

        /// <summary>
        /// Tests whether an OID is a member of an OID set.
        /// </summary>
        /// <param name="member">OID to test.</param>
        /// <param name="set">OID set to test.</param>
        /// <param name="present">Non-zero if OID is present in set.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Test_OID_set_member(
            GssOid member,
            GssOidSet set,
            out bool present,
            out uint minorStatus);

        /// <summary>
        /// Lists the name types supported by the specified mechanism.
        /// </summary>
        /// <param name="mechType">Mechanism to query.</param>
        /// <param name="nameTypes">Set of name types supported.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Inquire_names_for_mech(
            GssOid mechType,
            out GssOidSet nameTypes,
            out uint minorStatus);

        /// <summary>
        /// Lists mechanisms that support the specified name type.
        /// </summary>
        /// <param name="inputName">Name for which to list mechanisms.</param>
        /// <param name="mechTypes">Set of mechanisms supporting the name type.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Inquire_mechs_for_name(
            GssName inputName,
            out GssOidSet mechTypes,
            out uint minorStatus);

        /// <summary>
        /// Converts a name to a mechanism name (MN).
        /// </summary>
        /// <param name="inputName">Name to be canonicalized.</param>
        /// <param name="mechType">Mechanism for which name should be canonicalized.</param>
        /// <param name="outputName">Canonicalized name.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Canonicalize_name(
            GssName inputName,
            GssOid mechType,
            out GssName outputName,
            out uint minorStatus);

        /// <summary>
        /// Converts a mechanism name to export form.
        /// </summary>
        /// <param name="inputName">Mechanism name to export.</param>
        /// <param name="exportedName">Exported name in canonical form.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Export_name(
            GssName inputName,
            out GssBuffer exportedName,
            out uint minorStatus);

        /// <summary>
        /// Creates a copy of an internal name.
        /// </summary>
        /// <param name="srcName">Name to duplicate.</param>
        /// <param name="destName">Duplicate name.</param>
        /// <param name="minorStatus">Mechanism-specific status code.</param>
        /// <returns>GSS major status code.</returns>
        GssMajorStatus GSS_Duplicate_name(
            GssName srcName,
            out GssName destName,
            out uint minorStatus);
    }
}
