namespace VTDev.Libraries.CEXEngine.Tools
{
    /// <summary>
    /// A Hexadecimal conversion helper class
    /// </summary>
    public static class HexConverter
    {
        #region Fields
        private static readonly byte[] m_decodingTable = new byte[128];
        private static readonly byte[] m_encodingTable =
		{
			(byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
			(byte)'8', (byte)'9', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f'
		};
        #endregion

        #region Constructor
        static HexConverter()
		{
			for (int i = 0; i < m_encodingTable.Length; i++)
				m_decodingTable[m_encodingTable[i]] = (byte)i;

			m_decodingTable['A'] = m_decodingTable['a'];
			m_decodingTable['B'] = m_decodingTable['b'];
			m_decodingTable['C'] = m_decodingTable['c'];
			m_decodingTable['D'] = m_decodingTable['d'];
			m_decodingTable['E'] = m_decodingTable['e'];
			m_decodingTable['F'] = m_decodingTable['f'];
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
                temp[counter++] = m_encodingTable[v >> 4];
                temp[counter++] = m_encodingTable[v & 0xf];
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

                b1 = m_decodingTable[Data[i++]];

                while (i < end && Ignore(Data[i]))
                    i++;

                b2 = m_decodingTable[Data[i++]];
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
