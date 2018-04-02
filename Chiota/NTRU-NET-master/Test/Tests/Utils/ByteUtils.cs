using System;

namespace Test.Tests
{
    internal static class ByteUtils
    {
        public static byte[] GetBytes(string Value)
        {
            return System.Text.Encoding.ASCII.GetBytes(Value);
        }

        public static byte[] ToBytes(sbyte[] Data)
        {
            byte[] data = new byte[Data.Length];
            Buffer.BlockCopy(Data, 0, data, 0, Data.Length);
            return data;
        }
    }
}
