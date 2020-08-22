// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace System.Security.Cryptography.Asn1
{
    internal sealed partial class AsnWriter
    {
        /// <summary>
        ///   Begin writing a Set-Of with a tag UNIVERSAL 17.
        /// </summary>
        /// <remarks>
        ///   In <see cref="AsnEncodingRules.CER"/> and <see cref="AsnEncodingRules.DER"/> modes
        ///   the writer will sort the Set-Of elements when the tag is closed.
        /// </remarks>
        /// <exception cref="ObjectDisposedException">The writer has been Disposed.</exception>
        /// <seealso cref="PushSetOf(Asn1Tag)"/>
        /// <seealso cref="PopSetOf()"/>
        public void PushSetOf()
        {
            this.PushSetOf(Asn1Tag.SetOf);
        }

        /// <summary>
        ///   Begin writing a Set-Of with a specified tag.
        /// </summary>
        /// <param name="tag">The tag to write.</param>
        /// <remarks>
        ///   In <see cref="AsnEncodingRules.CER"/> and <see cref="AsnEncodingRules.DER"/> modes
        ///   the writer will sort the Set-Of elements when the tag is closed.
        /// </remarks>
        /// <exception cref="ArgumentException">
        ///   <paramref name="tag"/>.<see cref="Asn1Tag.TagClass"/> is
        ///   <see cref="TagClass.Universal"/>, but
        ///   <paramref name="tag"/>.<see cref="Asn1Tag.TagValue"/> is not correct for
        ///   the method
        /// </exception>
        /// <exception cref="ObjectDisposedException">The writer has been Disposed.</exception>
        /// <seealso cref="PopSetOf(Asn1Tag)"/>
        public void PushSetOf(Asn1Tag tag)
        {
            CheckUniversalTag(tag, UniversalTagNumber.SetOf);

            // Assert the constructed flag, in case it wasn't.
            this.PushSetOfCore(tag.AsConstructed());
        }

        /// <summary>
        ///   Indicate that the open Set-Of with the tag UNIVERSAL 17 is closed,
        ///   returning the writer to the parent context.
        /// </summary>
        /// <remarks>
        ///   In <see cref="AsnEncodingRules.CER"/> and <see cref="AsnEncodingRules.DER"/> modes
        ///   the writer will sort the Set-Of elements when the tag is closed.
        /// </remarks>
        /// <exception cref="InvalidOperationException">
        ///   the writer is not currently positioned within a Sequence with tag UNIVERSAL 17
        /// </exception>
        /// <exception cref="ObjectDisposedException">The writer has been Disposed.</exception>
        /// <seealso cref="PopSetOf(Asn1Tag)"/>
        /// <seealso cref="PushSetOf()"/>
        public void PopSetOf()
        {
            this.PopSetOfCore(Asn1Tag.SetOf);
        }

        /// <summary>
        ///   Indicate that the open Set-Of with the specified tag is closed,
        ///   returning the writer to the parent context.
        /// </summary>
        /// <param name="tag">The tag to write.</param>
        /// <remarks>
        ///   In <see cref="AsnEncodingRules.CER"/> and <see cref="AsnEncodingRules.DER"/> modes
        ///   the writer will sort the Set-Of elements when the tag is closed.
        /// </remarks>
        /// <exception cref="ArgumentException">
        ///   <paramref name="tag"/>.<see cref="Asn1Tag.TagClass"/> is
        ///   <see cref="TagClass.Universal"/>, but
        ///   <paramref name="tag"/>.<see cref="Asn1Tag.TagValue"/> is not correct for
        ///   the method
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   the writer is not currently positioned within a Set-Of with the specified tag
        /// </exception>
        /// <exception cref="ObjectDisposedException">The writer has been Disposed.</exception>
        /// <seealso cref="PushSetOf(Asn1Tag)"/>
        public void PopSetOf(Asn1Tag tag)
        {
            CheckUniversalTag(tag, UniversalTagNumber.SetOf);

            // Assert the constructed flag, in case it wasn't.
            this.PopSetOfCore(tag.AsConstructed());
        }

        // T-REC-X.690-201508 sec 8.12
        // The writer claims SetOf, and not Set, so as to avoid the field
        // ordering clause of T-REC-X.690-201508 sec 9.3
        private void PushSetOfCore(Asn1Tag tag)
        {
            this.PushTag(tag, UniversalTagNumber.SetOf);
        }

        // T-REC-X.690-201508 sec 8.12
        private void PopSetOfCore(Asn1Tag tag)
        {
            // T-REC-X.690-201508 sec 11.6
            bool sortContents = this.RuleSet == AsnEncodingRules.CER || this.RuleSet == AsnEncodingRules.DER;

            this.PopTag(tag, UniversalTagNumber.SetOf, sortContents);
        }
    }
}
