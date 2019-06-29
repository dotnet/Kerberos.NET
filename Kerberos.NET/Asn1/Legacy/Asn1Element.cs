using Kerberos.NET.Crypto;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;

namespace Kerberos.NET.Asn1
{
    public enum LegacyTagClass
    {
        Universal = 0,
        Application = 1,
        ContextSpecific = 2,
        Private = 3
    }

    public enum UniversalTag
    {
        None = -1,
        EndOfContents = 0,
        Boolean = 1,
        Integer = 2,
        BitString = 3,
        OctetString = 4,
        Null = 5,
        ObjectIdentifier = 6,
        ObjectDescriptor = 7,
        External = 8,
        InstanceOf = External,
        Real = 9,
        Enumerated = 10,
        Embedded = 11,
        UTF8String = 12,
        RelativeObjectIdentifier = 13,
        Time = 14,
        Sequence = 16,
        SequenceOf = Sequence,
        Set = 17,
        SetOf = Set,
        NumericString = 18,
        PrintableString = 19,
        TeletexString = 20,
        T61String = TeletexString,
        VideotexString = 21,
        IA5String = 22,
        UtcTime = 23,
        GeneralizedTime = 24,
        GraphicString = 25,
        VisibleString = 26,
        ISO646String = VisibleString,
        GeneralString = 27,
        UniversalString = 28,
        UnrestrictedCharacterString = 29,
        BMPString = 30,
        Date = 31,
        TimeOfDay = 32,
        DateTime = 33,
        Duration = 34,
        ObjectIdentifierIRI = 35,
        RelativeObjectIdentifierIRI = 36
    }

    [DebuggerDisplay("Class: {Class}; " +
                     "UT: {UniversalTag}; " +
                     "AT: {ApplicationTag}; " +
                     "CST: {ContextSpecificTag}; " +
                     "T: {Tag}; " +
                     "Constructed: {IsConstructed}; " +
                     "Children: {Count}")]
    public class Asn1Element
    {
        private readonly int position;
        private readonly int valueLength;
        private readonly int valuePosition;
        private readonly List<Asn1Element> children;

        public Asn1Element(byte[] rawData, string source = null)
            : this(rawData, 0)
        {
            if (!string.IsNullOrWhiteSpace(source))
            {
                Debug.WriteLine($"[{source}]");
            }

            DebugPrint(this, 0);
        }

        public byte[] RawData { get; private set; }

        public byte[] BlockCopy()
        {
            var block = new byte[Value.Length];

            Buffer.BlockCopy(Value, 0, block, 0, Value.Length);

            return block;
        }

        private Asn1Element(byte[] rawData, int start)
        {
            RawData = rawData;

            position = start;
            valuePosition = start + 1;

            valueLength = RawData[valuePosition++];

            if (valueLength == 0x80)
            {
                valueLength = -1;
            }
            else if ((valueLength & 0x80) == 0x80)
            {
                int len = valueLength & 0x7F;
                valueLength = 0;

                for (int i = 0; i < len; i++)
                {
                    valueLength = valueLength * 256 + RawData[valuePosition++];
                }
            }

            if (valueLength > RawData.Length)
            {
                valueLength = RawData.Length;
                valuePosition = 0;
            }

            if (IsConstructed && (valueLength != 0))
            {
                children = DecodeChildren(RawData, valuePosition, valueLength);

                if (valueLength == -1)
                {
                    int childLength = 0;

                    if (children.Count > 0)
                    {
                        foreach (var child in children)
                        {
                            childLength += child.TotalLength;
                        }
                    }

                    valueLength = childLength;
                }
            }
        }

        private void DebugPrint(Asn1Element element, int indent)
        {
            var tabs = string.Join("", Enumerable.Repeat("   ", indent));

            switch (element.Class)
            {
                case LegacyTagClass.Application:
                    Debug.WriteLine($"{tabs}[APPLICATION {element.ApplicationTag}] {element.Count} {element.IsConstructed}");
                    break;
                case LegacyTagClass.ContextSpecific:
                    Debug.WriteLine($"{tabs}[{element.ContextSpecificTag}] {element.Count} {element.IsConstructed}");
                    break;
                case LegacyTagClass.Private:
                    break;
                case LegacyTagClass.Universal:
                    Debug.WriteLine($"{tabs}[{element.UniversalTag}] {element.Count} {element.IsConstructed}");
                    break;
            }

            if (element.Count > 0)
            {
                for (var i = 0; i < element.Count; i++)
                {
                    DebugPrint(element[i], indent + 1);
                }
            }
        }

        public Asn1Element Find(Func<Asn1Element, bool> expression)
        {
            if (children == null)
            {
                return null;
            }

            return children.FirstOrDefault(expression);
        }

        public Asn1Element AsEncapsulatedElement(string source)
        {
            return new Asn1Element(AsOctetString(), $"{source} ENCAPSULATED");
        }

        public string AsString(bool hexify = false)
        {
            if (hexify)
            {
                return Hex.Hexify(Value, lineLength: 16, spaces: true);
            }

            switch (Tag)
            {
                case 2:
                case 3:
                    return Hex.Hexify(Value, lineLength: 16, spaces: true);
                case 6:
                    return ConvertToOid(Value);
                case 12:
                    return Encoding.UTF8.GetString(Value);
                case 13:
                    return ConvertToOid(Value);
                case 18:
                case 19:
                case 22:
                case 23:
                case 24:
                case 26:
                case 27:
                case 28:
                case 30:
                    return Encoding.ASCII.GetString(Value);
            }

            if (ContextSpecificTag == 6 || IsAsciiString(Value))
            {
                return Encoding.ASCII.GetString(Value);
            }

            return Hex.Hexify(Value, lineLength: 16, spaces: true);
        }

        public byte[] AsOctetString()
        {
            var octet = this[0];

            if (octet.Class != LegacyTagClass.Universal)
            {
                throw new InvalidDataException();
            }

            return octet.Value;
        }

        public int AsInt(bool reverse = false)
        {
            var bytes = Value;

            int num = 0;

            if (reverse)
            {
                Array.Reverse(bytes);
            }

            for (int i = 0; i < bytes.Length; i++)
            {
                num = (num << 8) | bytes[i];
            }

            return num;
        }

        public long AsLong()
        {
            var bytes = Value;

            long num = 0L;

            for (int i = 0; i < bytes.Length; i++)
            {
                num = (num << 8) | bytes[i];
            }

            return num;
        }

        private static string ConvertToOid(byte[] oid)
        {
            // this is deceptively complex
            // most implementations of this are wrong
            // this looks like a correct solution https://www.codeproject.com/Articles/16468/OID-Conversion?msg=2900857#xx2900857xx

            var sb = new StringBuilder();

            byte x = (byte)(oid[0] / 40);
            byte y = (byte)(oid[0] % 40);

            if (x > 2)
            {
                y += (byte)((x - 2) * 40);
                x = 2;
            }

            sb.AppendFormat("{0}.{1}", x, y);

            long val = 0;

            for (x = 1; x < oid.Length; x++)
            {
                val = (val << 7) | ((byte)(oid[x] & 0x7F));

                if ((oid[x] & 0x80) != 0x80)
                {
                    sb.AppendFormat(".{0}", val);

                    val = 0;
                }
            }

            return sb.ToString();
        }

        public byte Tag { get { return RawData[position]; } }

        public LegacyTagClass Class
        {
            get
            {
                return (LegacyTagClass)((Tag & 192) >> 6);
            }
        }

        public UniversalTag UniversalTag
        {
            get
            {
                if ((Tag & 192) == 0)
                {
                    return (UniversalTag)(Tag & 31);
                }

                return 0;
            }
        }

        public int ApplicationTag
        {
            get
            {
                if ((Tag & 32) != 0)
                {
                    return Tag & 31;
                }

                return 0;
            }
        }

        public int ContextSpecificTag
        {
            get
            {
                if ((Tag & 128) != 0)
                {
                    return Tag & 31;
                }

                return 0;
            }
        }

        private byte[] value;

        public byte[] Value
        {
            get
            {
                if (valueLength < 0)
                {
                    return null;
                }

                if (value == null)
                {
                    value = new byte[valueLength];

                    Buffer.BlockCopy(RawData, valuePosition, value, 0, value.Length);
                }

                return value;
            }
        }

        protected bool IsConstructed { get { return (RawData[position] & 0x20) == 0x20; } }

        public int Count { get { return children?.Count ?? 0; } }

        public Asn1Element this[int index]
        {
            get
            {
                if (index < 0 || index >= children.Count)
                {
                    return null;
                }

                return children[index];
            }
        }

        internal int TotalLength { get { return valuePosition - position + valueLength; } }

        private static List<Asn1Element> DecodeChildren(byte[] rawData, int position, int length)
        {
            var decoded = new List<Asn1Element>();

            int childPos = position;
            int end = childPos + length;

            while (length == -1 || childPos < end)
            {
                var el = new Asn1Element(rawData, childPos);

                decoded.Add(el);
                childPos += el.TotalLength;

                if (el.Tag == 0x00 && el.valueLength == 0)
                {
                    break;
                }
            }

            return decoded;
        }

        private static bool IsAsciiString(byte[] data)
        {
            return !data.Any(d => d < 32);
        }

        public DateTimeOffset AsDateTimeOffset()
        {
            // TODO: this is still probably wrong 

            var stringVal = AsString();

            return DateTimeOffset.ParseExact(
                stringVal,
                new[] {
                    "yyyyMMddHHmmssZ",
                    "yyyyMMddHHmmsszzz",
                    "yyMMddHHmmssZ",
                    "yyMMddHHmmsszzz"
                },
                CultureInfo.InvariantCulture,
                DateTimeStyles.None
            );
        }
    }
}
