#region Directives
using System;
using System.IO;
using NTRU.Exceptions;
using NTRUEngine.NTRU.Digest;
#endregion

namespace NTRU.Sign
{
    public class Prng
    {
        #region Constants
        #endregion
        #region Fields
        #endregion
        #region Constructor
        #endregion
        #region Public Methods
        #endregion
        #region Private Methods
        #endregion

        private int counter;
        private byte[] seed;
        private SHA256 hashAlg;

        /**
         * Constructs a new PRNG and seeds it with a byte array.
         * @param seed a seed
         * @param hashAlg the hash algorithm to use
         * @throws NtruException if the JRE doesn't implement the specified hash algorithm
         */
        public Prng(byte[] seed, string hashAlg)
        {
            counter = 0;
            this.seed = seed;
            try
            {
                this.hashAlg = new SHA256();// MessageDigest.getInstance(hashAlg);
            }
            catch (Exception e)
            {
                throw new NtruException(e.Message);
            }
        }

        /**
         * Returns <code>n</code> random bytes
         * @param n number of bytes to return
         * @return the next <code>n</code> random bytes
         */
        public byte[] nextBytes(int n)
        {
            MemoryStream buf = new MemoryStream(n);

            while (buf.Position < buf.Capacity)
            {
                MemoryStream cbuf = new MemoryStream(seed.Length + 4);
                BinaryWriter bwr = new BinaryWriter(cbuf);
                cbuf.Write(seed, 0, seed.Length);
                bwr.Write(counter);
                byte[] hash = hashAlg.ComputeHash(cbuf.ToArray());

                if (buf.Length - buf.Position < hash.Length)
                    buf.Write(hash, 0, (int)(buf.Capacity - buf.Position));
                else
                    buf.Write(hash, 0, hash.Length);
                counter++;
            }

            return buf.ToArray();
        }
    }
}