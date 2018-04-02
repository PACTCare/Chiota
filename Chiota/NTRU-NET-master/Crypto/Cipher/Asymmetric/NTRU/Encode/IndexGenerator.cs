#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Digest;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

#region License Information
// NTRU Encrypt in C# (NTRUSharp)
// Copyright (C) 2015 John Underhill
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
// 
//
// Based on the java project NTRUEncrypt by Tim Buktu: <https://github.com/tbuktu/ntru> and the C version
// <https://github.com/NTRUOpenSourceProject/ntru-crypto> NTRUOpenSourceProject/ntru-crypto.
// NTRU is owned and patented by Security Innovations: <https://www.securityinnovation.com/products/encryption-libraries/ntru-crypto/>,
// authors and originators include; Jeffrey Hoffstein, Jill Pipher, and Joseph H. Silverman.
// 
// Implementation Details:
// An implementation of NTRU Encrypt in C#.
// Written by John Underhill, April 09, 2015
// contact: develop@vtdev.com
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.Encode
{
    /// <summary>
    /// An implementation of the Index Generation Function IGF-2 in IEEE P1363.1 section 8.4.2.1.
    /// </summary>
    public sealed class IndexGenerator
    {
        #region Private Fields
        private BitString _bitBuffer;
        private int _callCounter;
        private IDigest _digestEngine;
        private int _hashLen;
        private int _remLen;
        private int _C;
        private int _N;
        private byte[] _Z;
        #endregion

        #region Constructor
        /// <summary>
        /// Constructs a new index generator
        /// </summary>
        /// 
        /// <param name="Seed">A seed of arbitrary length to initialize the index generator</param>
        /// <param name="EncParam">NtruEncrypt parameters</param>
        public IndexGenerator(byte[] Seed, NTRUParameters EncParam)
        {
            _N = EncParam.N;
            _C = EncParam.CBits;
            int minCallsR = EncParam.MinIGFHashCalls;

            _digestEngine = GetDigest(EncParam.MessageDigest);
            _hashLen = _digestEngine.DigestSize;
            _Z = Seed;
            _callCounter = 0;
            _bitBuffer = new BitString();

            while (_callCounter < minCallsR)
            {
                byte[] data = new byte[_Z.Length + 4];
                Buffer.BlockCopy(_Z, 0, data, 0, _Z.Length);
                Buffer.BlockCopy(IntUtils.IntToBytes(_callCounter), 0, data, _Z.Length, 4);
                byte[] H = _digestEngine.ComputeHash(data);
                _bitBuffer.AppendBits(H);
                _callCounter++;
            }

            _remLen = minCallsR * 8 * _hashLen;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Returns a number
        /// </summary>
        /// 
        /// <returns>The next pseudo-random index</returns>
        public int NextIndex()
        {
            while (true)
            {
                if (_remLen < _C)
                {
                    BitString M = _bitBuffer.GetTrailing(_remLen);
                    int tmpLen = _C - _remLen;
                    int cThreshold = _callCounter + (tmpLen + _hashLen - 1) / _hashLen;

                    while (_callCounter < cThreshold)
                    {
                        byte[] data = new byte[_Z.Length + 4];
                        Buffer.BlockCopy(_Z, 0, data, 0, _Z.Length);
                        Buffer.BlockCopy(IntUtils.IntToBytes(_callCounter), 0, data, _Z.Length, 4);
                        byte[] H = _digestEngine.ComputeHash(data);

                        M.AppendBits(H);
                        _callCounter++;
                        _remLen += 8 * _hashLen;
                    }
                    _bitBuffer = M;
                }

                // assume c less than 32
                int i = _bitBuffer.Pop(_C);   
                _remLen -= _C;

                if (i < (1 << _C) - ((1 << _C) % _N))
                    return i % _N;
            }
        }
        #endregion

        #region BitString Class
        /// <summary>
        /// Represents a string of bits and supports appending, reading the head, and reading the tail
        /// </summary>
        public class BitString
        {
            #region Fields
            private const int INITIAL_SIZE = 4;
            private byte[] _bytes = new byte[INITIAL_SIZE];
            // includes the last byte even if only some of its bits are used
            private int _numBytes;   
            // lastByteBits <= 8
            private int _lastByteBits;
            #endregion

            #region Properties
            /// <summary>
            /// Bit string state array
            /// </summary>
            public byte[] Bytes 
            {
                get { return _bytes; }
                internal set { _bytes = value; }
            }
            #endregion

            #region Methods
            /// <summary>
            /// Append bits to an array
            /// </summary>
            /// 
            /// <param name="Data">Array to write to</param>
            public void AppendBits(byte[] Data)
            {
                for (int i = 0; i < Data.Length; i++)
                    AppendBits(Data[i]);
            }

            /// <summary>
            /// Appends all bits in a byte to the end of the bit string
            /// </summary>
            /// 
            /// <param name="Value">The byte to append</param>
            public void AppendBits(byte Value)
            {
                if (_numBytes == Bytes.Length)
                    Bytes = Bytes.CopyOf(Math.Max(2 * Bytes.Length, INITIAL_SIZE));

                if (_numBytes == 0)
                {
                    _numBytes = 1;
                    Bytes[0] = Value;
                    _lastByteBits = 8;
                }
                else if (_lastByteBits == 8)
                {
                    Bytes[_numBytes++] = Value;
                }
                else
                {
                    int s = 8 - _lastByteBits;
                    Bytes[_numBytes - 1] |= (byte)((Value & 0xFF) << _lastByteBits);
                    Bytes[_numBytes++] = (byte)((Value & 0xFF) >> s);
                }
            }

            /// <summary>
            /// Returns the last <c>NumBits</c> bits from the end of the bit string
            /// </summary>
            /// 
            /// <param name="NumBits">Number of bits to return</param>
            /// 
            /// <returns>A new <c>BitString</c> of length <c>numBits</c></returns>
            public BitString GetTrailing(int NumBits)
            {
                BitString newStr = new BitString();
                newStr._numBytes = (NumBits + 7) / 8;
                newStr.Bytes = new byte[newStr._numBytes];

                for (int i = 0; i < newStr._numBytes; i++)
                    newStr.Bytes[i] = Bytes[i];

                newStr._lastByteBits = NumBits % 8;

                if (newStr._lastByteBits == 0)
                {
                    newStr._lastByteBits = 8;
                }
                else
                {
                    int s = 32 - newStr._lastByteBits;
                    newStr.Bytes[newStr._numBytes - 1] = (byte)(IntUtils.URShift((newStr.Bytes[newStr._numBytes - 1] << s), s));
                }

                return newStr;
            }

            /// <summary>
            /// Returns up to 32 bits from the beginning of the bit string, and removes those bits from the bit string.
            /// </summary>
            /// 
            /// <param name="NumBits">Number of bits to return</param>
            /// 
            /// <returns>An <c>int</c> whose lower <c>NumBits</c> bits are the beginning of the bit string</returns>
            public int Pop(int NumBits)
            {
                int i = GetLeadingAsInt(NumBits);
                Truncate(NumBits);

                return i;
            }

            /// <summary>
            /// Returns up to 32 bits from the beginning of the bit string
            /// </summary>
            /// 
            /// <param name="NumBits">The number of bits</param>
            /// 
            /// <returns>An <c>int</c> whose lower <c>NumBits</c> bits are the beginning of the bit string</returns>
            public int GetLeadingAsInt(int NumBits)
            {
                int startBit = (_numBytes - 1) * 8 + _lastByteBits - NumBits;
                int startByte = startBit / 8;
                int startBitInStartByte = startBit % 8;
                int sum = IntUtils.URShift((Bytes[startByte] & 0xFF), startBitInStartByte);
                int shift = 8 - startBitInStartByte;

                for (int i = startByte + 1; i < _numBytes - 1; i++)
                {
                    sum |= (Bytes[i] & 0xFF) << shift;
                    shift += 8;
                }

                // #bits in the byte
                int finalBits = NumBits - shift;
                // append finalBits more bits
                sum |= (Bytes[_numBytes - 1] & IntUtils.URShift(0xFF, (8 - finalBits))) << shift;   

                return sum;
            }

            /// <summary>
            /// Removes a given number of bits from the end of the bit string
            /// </summary>
            /// 
            /// <param name="NumBits">The number of bits to remove</param>
            public void Truncate(int NumBits)
            {
                _numBytes -= NumBits / 8;
                _lastByteBits -= NumBits % 8;

                if (_lastByteBits < 0)
                {
                    _lastByteBits += 8;
                    _numBytes--;
                }
            }
            #endregion
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Get the digest engine
        /// </summary>
        /// 
        /// <param name="Engine">Engine type</param>
        /// 
        /// <returns>Instance of digest</returns>
        private IDigest GetDigest(Digests Engine)
        {
            switch (Engine)
            {
                case Digests.Blake256:
                    return new Blake256();
                case Digests.Blake512:
                    return new Blake512();
                case Digests.Keccak256:
                    return new Keccak256();
                case Digests.Keccak512:
                    return new Keccak512();
                case Digests.Keccak1024:
                    return new Keccak1024();
                case Digests.SHA256:
                    return new SHA256();
                case Digests.SHA512:
                    return new SHA512();
                case Digests.Skein256:
                    return new Skein256();
                case Digests.Skein512:
                    return new Skein512();
                case Digests.Skein1024:
                    return new Skein1024();
                default:
                    throw new ArgumentException("The digest type is not supported!");
            }
        }
        #endregion
    }
}