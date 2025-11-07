// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Text;
using System.Threading.Tasks;
using Kerberos.NET.Entities.GssApi;

namespace Kerberos.NET.Samples
{
    /// <summary>
    /// Example demonstrating GSS-API usage with Kerberos.NET
    /// This sample shows how to use the GSS-API interface for authentication
    /// </summary>
    public class GssApiExample
    {
        /// <summary>
        /// Example: Simple GSS-API context initialization
        /// </summary>
        public static /* async */ Task SimpleContextInitialization()
        {
            Console.WriteLine("=== Simple GSS-API Context Initialization ===\n");

            using (var gssContext = new GssContext())
            {
                // Step 1: List available mechanisms
                var status = gssContext.GSS_Indicate_mechs(
                    out GssOidSet mechSet,
                    out uint minorStatus
                );

                if (status == GssMajorStatus.GSS_S_COMPLETE)
                {
                    Console.WriteLine($"Available mechanisms: {mechSet.Count}");
                    foreach (var mech in mechSet.Oids)
                    {
                        Console.WriteLine($"  - {mech.Value}");
                    }
                    Console.WriteLine();
                }

                // Step 2: Create and display a name
                var targetNameBuffer = new GssBuffer(
                    Encoding.UTF8.GetBytes("HTTP/server.example.com")
                );

                status = gssContext.GSS_Import_name(
                    targetNameBuffer,
                    GssNameType.GSS_C_NT_HOSTBASED_SERVICE,
                    out GssName targetName,
                    out minorStatus
                );

                if (status == GssMajorStatus.GSS_S_COMPLETE)
                {
                    Console.WriteLine($"Target name imported: {targetName.Name}");
                    Console.WriteLine($"Name type: {targetName.NameType.Value}");
                    Console.WriteLine();
                }

                // Step 3: Display name information
                status = gssContext.GSS_Display_name(
                    targetName,
                    out GssBuffer displayNameBuffer,
                    out GssOid nameType,
                    out minorStatus
                );

                if (status == GssMajorStatus.GSS_S_COMPLETE)
                {
                    var displayName = Encoding.UTF8.GetString(displayNameBuffer.ToArray());
                    Console.WriteLine($"Display name: {displayName}");
                    Console.WriteLine($"Display name type: {nameType.Value}");
                    Console.WriteLine();
                }

                // Step 4: Canonicalize the name for Kerberos
                status = gssContext.GSS_Canonicalize_name(
                    targetName,
                    GssOid.GSS_MECH_KRB5,
                    out GssName canonicalName,
                    out minorStatus
                );

                if (status == GssMajorStatus.GSS_S_COMPLETE)
                {
                    Console.WriteLine($"Canonical name: {canonicalName.Name}");
                    Console.WriteLine($"Is mechanism name: {canonicalName.IsMechanismName}");
                    Console.WriteLine($"Mechanism: {canonicalName.MechanismType?.Value}");
                    Console.WriteLine();
                }

                // Clean up
                gssContext.GSS_Release_name(ref targetName, out _);
                gssContext.GSS_Release_name(ref canonicalName, out _);
            }

            return Task.CompletedTask;
        }

        /// <summary>
        /// Example: Working with OID sets
        /// </summary>
        public static void OidSetOperations()
        {
            Console.WriteLine("=== OID Set Operations ===\n");

            using (var gssContext = new GssContext())
            {
                // Create an empty OID set
                var status = gssContext.GSS_Create_empty_OID_set(
                    out GssOidSet oidSet,
                    out uint minorStatus
                );

                Console.WriteLine($"Created empty OID set");

                // Add Kerberos mechanism
                status = gssContext.GSS_Add_OID_set_member(
                    GssOid.GSS_MECH_KRB5,
                    ref oidSet,
                    out minorStatus
                );
                Console.WriteLine($"Added Kerberos V5 mechanism");

                // Add SPNEGO mechanism
                status = gssContext.GSS_Add_OID_set_member(
                    GssOid.GSS_MECH_SPNEGO,
                    ref oidSet,
                    out minorStatus
                );
                Console.WriteLine($"Added SPNEGO mechanism");

                // Test membership
                status = gssContext.GSS_Test_OID_set_member(
                    GssOid.GSS_MECH_KRB5,
                    oidSet,
                    out bool present,
                    out minorStatus
                );
                Console.WriteLine($"Kerberos V5 in set: {present}");

                status = gssContext.GSS_Test_OID_set_member(
                    GssOid.GSS_MECH_NTLM,
                    oidSet,
                    out present,
                    out minorStatus
                );
                Console.WriteLine($"NTLM in set: {present}");

                Console.WriteLine($"\nTotal mechanisms in set: {oidSet.Count}");

                // Clean up
                gssContext.GSS_Release_OID_set(ref oidSet, out _);
                Console.WriteLine();
            }
        }

        /// <summary>
        /// Example: Name comparison operations
        /// </summary>
        public static void NameComparison()
        {
            Console.WriteLine("=== Name Comparison ===\n");

            using (var gssContext = new GssContext())
            {
                var name1 = new GssName("user@REALM.COM", GssNameType.GSS_KRB5_NT_PRINCIPAL_NAME);
                var name2 = new GssName("user@realm.com", GssNameType.GSS_KRB5_NT_PRINCIPAL_NAME);
                var name3 = new GssName("admin@REALM.COM", GssNameType.GSS_KRB5_NT_PRINCIPAL_NAME);

                // Compare name1 and name2 (case-insensitive)
                var status = gssContext.GSS_Compare_name(
                    name1,
                    name2,
                    out bool nameEqual,
                    out uint minorStatus
                );

                Console.WriteLine($"'{name1.Name}' == '{name2.Name}': {nameEqual}");

                // Compare name1 and name3
                status = gssContext.GSS_Compare_name(
                    name1,
                    name3,
                    out nameEqual,
                    out minorStatus
                );

                Console.WriteLine($"'{name1.Name}' == '{name3.Name}': {nameEqual}");

                // Duplicate a name
                status = gssContext.GSS_Duplicate_name(
                    name1,
                    out GssName duplicateName,
                    out minorStatus
                );

                Console.WriteLine($"\nDuplicated name: {duplicateName.Name}");
                Console.WriteLine($"Original and duplicate are different objects: {!ReferenceEquals(name1, duplicateName)}");

                // Clean up
                name1?.Dispose();
                name2?.Dispose();
                name3?.Dispose();
                gssContext.GSS_Release_name(ref duplicateName, out _);
                Console.WriteLine();
            }
        }

        /// <summary>
        /// Example: Query mechanism capabilities
        /// </summary>
        public static void MechanismInquiry()
        {
            Console.WriteLine("=== Mechanism Inquiry ===\n");

            using (var gssContext = new GssContext())
            {
                // Inquire about name types supported by Kerberos
                var status = gssContext.GSS_Inquire_names_for_mech(
                    GssOid.GSS_MECH_KRB5,
                    out GssOidSet nameTypes,
                    out uint minorStatus
                );

                if (status == GssMajorStatus.GSS_S_COMPLETE)
                {
                    Console.WriteLine($"Name types supported by Kerberos V5:");
                    foreach (var nameType in nameTypes.Oids)
                    {
                        Console.WriteLine($"  - {nameType.Value}");
                    }
                    Console.WriteLine();
                }

                // Inquire about mechanisms that support a specific name type
                var testName = new GssName("user@REALM.COM", GssNameType.GSS_KRB5_NT_PRINCIPAL_NAME);
                status = gssContext.GSS_Inquire_mechs_for_name(
                    testName,
                    out GssOidSet mechTypes,
                    out minorStatus
                );

                if (status == GssMajorStatus.GSS_S_COMPLETE)
                {
                    Console.WriteLine($"Mechanisms supporting the name type:");
                    foreach (var mechType in mechTypes.Oids)
                    {
                        Console.WriteLine($"  - {mechType.Value}");
                    }
                    Console.WriteLine();
                }

                testName?.Dispose();
            }
        }

        /// <summary>
        /// Example: Status code display
        /// </summary>
        public static void StatusDisplay()
        {
            Console.WriteLine("=== Status Code Display ===\n");

            using (var gssContext = new GssContext())
            {
                var statusCodes = new[]
                {
                    GssMajorStatus.GSS_S_COMPLETE,
                    GssMajorStatus.GSS_S_CONTINUE_NEEDED,
                    GssMajorStatus.GSS_S_BAD_MECH,
                    GssMajorStatus.GSS_S_BAD_NAME,
                    GssMajorStatus.GSS_S_NO_CRED,
                    GssMajorStatus.GSS_S_NO_CONTEXT,
                    GssMajorStatus.GSS_S_BAD_MIC
                };

                foreach (var statusCode in statusCodes)
                {
                    uint messageContext = 0;
                    var status = gssContext.GSS_Display_status(
                        (uint)statusCode,
                        1, // GSS_C_GSS_CODE
                        null,
                        ref messageContext,
                        out GssBuffer statusString,
                        out uint minorStatus
                    );

                    if (status == GssMajorStatus.GSS_S_COMPLETE)
                    {
                        var message = Encoding.UTF8.GetString(statusString.ToArray());
                        Console.WriteLine($"{statusCode,30}: {message}");
                        gssContext.GSS_Release_buffer(ref statusString, out _);
                    }
                }
                Console.WriteLine();
            }
        }

        /// <summary>
        /// Run all examples
        /// </summary>
        public static async Task RunAllExamples()
        {
            try
            {
                await SimpleContextInitialization();
                OidSetOperations();
                NameComparison();
                MechanismInquiry();
                StatusDisplay();

                Console.WriteLine("All examples completed successfully!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error running examples: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }
    }
}
