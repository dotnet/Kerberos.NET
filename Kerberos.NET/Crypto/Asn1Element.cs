using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace Kerberos.NET.Crypto
{
    public enum TagClass
    {
        Universal = 0,
        Application = 1,
        ContextSpecific = 2,
        Private = 3
    }

    [DebuggerDisplay("Class: {Class}; UT: {UniversalTag}; AT: {ApplicationTag}; CST: {ContextSpecificTag}; T: {Tag}; Constructed: {IsConstructed}; Children: {Count}")]
    public class Asn1Element
    {
        private readonly int position;
        private readonly int valueLength;
        private readonly int valuePosition;
        private readonly List<Asn1Element> children;

        public Asn1Element(byte[] rawData)
            : this(rawData, 0)
        {

        }

        public byte[] RawData { get; private set; }

        public byte[] BlockCopy()
        {
            var block = new byte[Value.Length];

            Buffer.BlockCopy(Value, 0, block, 0, Value.Length);

            return block;
        }

        public Asn1Element(byte[] rawData, int start)
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
            else
            {
                children = new List<Asn1Element>();
            }
        }

        public Asn1Element Find(Func<Asn1Element, bool> expression)
        {
            return children.FirstOrDefault(expression);
        }

        public Asn1Element AsEncapsulatedElement()
        {
            return new Asn1Element(AsOctetString());
        }

        public string AsString(bool hexify = false)
        {
            if (hexify)
            {
                return Hexify(Value, lineLength: 16, spaces: true);
            }

            switch (Tag)
            {
                case 2:
                case 3:
                    return Hexify(Value, lineLength: 16, spaces: true);
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

            return Hexify(Value, lineLength: 16, spaces: true);
        }

        public byte[] AsOctetString()
        {
            var octet = this[0];

            if (octet.Class != TagClass.Universal)
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

        public TagClass Class
        {
            get
            {
                return (TagClass)((Tag & 192) >> 6);
            }
        }

        public int UniversalTag
        {
            get
            {
                if ((Tag & 192) == 0)
                {
                    return Tag & 31;
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

        public int Length { get { return valueLength; } }

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

                if (el.Tag == 0x00 && el.Length == 0)
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

        private static string Hexify(byte[] hash, int lineLength = 0, bool spaces = false)
        {
            if (hash == null || hash.Length <= 0)
            {
                return null;
            }

            // It's considerably faster to just do a lookup and append than to do something like BitConverter.ToString(byte[])

            int len = hash.Length * (spaces ? 3 : 2);

            StringBuilder result = new StringBuilder(len);

            var lineCounter = 0;

            for (int i = 0; i < hash.Length; i++)
            {
                result.Append(HEX_INDEX[hash[i]]);

                if (spaces)
                {
                    result.Append(" ");
                }

                if (lineLength > 0 && ++lineCounter > lineLength)
                {
                    result.Append("\r\n");
                    lineCounter = 0;
                }
            }

            return result.ToString();
        }

        private static readonly string[] HEX_INDEX = new string[] {
            "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
            "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f",
            "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
            "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f",
            "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c", "4d", "4e", "4f",
            "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5a", "5b", "5c", "5d", "5e", "5f",
            "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d", "6e", "6f",
            "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7a", "7b", "7c", "7d", "7e", "7f",
            "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
            "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9a", "9b", "9c", "9d", "9e", "9f",
            "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
            "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf",
            "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf",
            "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "da", "db", "dc", "dd", "de", "df",
            "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef",
            "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff",
        };

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
