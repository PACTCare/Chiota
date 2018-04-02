namespace VTDev.Libraries.CEXEngine.Tools
{
    /// <summary>
    /// A Hexadecimal conversion helper class
    /// </summary>
    public static class HexConverter
    {
        #region Fields
        private static readonly byte[] _decodingTable = new byte[128];
        private static readonly byte[] _encodingTable =
		{
			(byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
			(byte)'8', (byte)'9', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f'
		};
        #endregion

        #region Constructor
        static HexConverter()
		{
			for (int i = 0; i < _encodingTable.Length; i++)
				_decodingTable[_encodingTable[i]] = (byte)i;

			_decodingTable['A'] = _decodingTable['a'];
			_decodingTable['B'] = _decodingTable['b'];
			_decodingTable['C'] = _decodingTable['c'];
			_decodingTable['D'] = _decodingTable['d'];
			_decodingTable['E'] = _decodingTable['e'];
			_decodingTable['F'] = _decodingTable['f'];
		}
        #endregion

        #region Public Methods
        /// <summary>
        /// Convert an array into a hex string
        /// </summary>
        /// 
        /// <param name="Data">Data to convert</param>
        /// 
        /// <returns>Data as a string</returns>
        public static string ToString(byte[] Data)
        {
            return System.Text.Encoding.Default.GetString(Encode(Data, 0, Data.Length));
        }

        /// <summary>
        /// Encode an array of bytes in hexadecimal format
        /// </summary>
        /// 
        /// <param name="Data">The bytes to encode</param>
        /// <param name="Offset">The starting offset within the Data array</param>
        /// <param name="Length">The number of bytes to encode</param>
        /// 
        /// <returns>Encode bytes</returns>
        public static byte[] Encode(byte[] Data, int Offset, int Length)
        {
            byte[] temp = new byte[Length * 2];
            int counter = 0;

            for (int i = Offset; i < (Offset + Length); i++)
            {
                int v = Data[i];
                temp[counter++] = _encodingTable[v >> 4];
                temp[counter++] = _encodingTable[v & 0xf];
            }

            return temp;
        }

        /// <summary>
        /// Decode a Hex encoded string and return the output
        /// </summary>
        /// 
        /// <param name="Data">Hex string</param>
        /// 
        /// <returns>Decoded bytes</returns>
        public static byte[] Decode(string Data)
        {
            byte b1, b2;
            int length = 0;
            int end = Data.Length;
            byte[] temp = new byte[end / 2];

            while (end > 0)
            {
                if (!Ignore(Data[end - 1]))
                    break;

                end--;
            }

            int i = 0;
            int ct = 0;

            while (i < end)
            {
                while (i < end && Ignore(Data[i]))
                    i++;

                b1 = _decodingTable[Data[i++]];

                while (i < end && Ignore(Data[i]))
                    i++;

                b2 = _decodingTable[Data[i++]];
                temp[ct++] = (byte)((b1 << 4) | b2);
                length++;
            }

            return temp;
        }
        #endregion

        #region Helpers
        private static bool Ignore(char C)
        {
            return (C == '\n' || C == '\r' || C == '\t' || C == ' ');
        }
        #endregion
    }
}
