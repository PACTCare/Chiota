#region Directives
using System.IO;
using NTRU.Exceptions;
using NTRU.Polynomial;
#endregion

namespace NTRU.Sign
{
/**
 * A NtruSign public key is essentially a polynomial named <code>h</code>.
 */
    public class SignaturePublicKey
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
        public IntegerPolynomial h;
        public int q;

        /**
         * Constructs a new public key from a polynomial
         * @param h the polynomial <code>h</code> which determines the key
         * @param q the modulus
         */
        public SignaturePublicKey(IntegerPolynomial h, int q)
        {
            this.h = h;
            this.q = q;
        }

        /**
         * Reconstructs a public key from its <code>byte</code> array representation.
         * @param b an encoded key
         * @see #getEncoded()
         */
        public SignaturePublicKey(byte[] b) :
            this(new MemoryStream(b))
        {
            ;
        }

        /**
         * Reconstructs a public key from its <code>byte</code> array representation.
         * @param is an input stream containing an encoded key
         * @throws NtruException if an {@link IOException} occurs
         * @see #writeTo(OutputStream)
         */
        public SignaturePublicKey(MemoryStream ins)
        {
            BinaryReader dataStream = new BinaryReader(ins);
            try
            {
                int N = dataStream.ReadInt16();
                q = dataStream.ReadInt16();
                h = IntegerPolynomial.FromBinary(ins, N, q);
            }
            catch (IOException e)
            {
                throw new NtruException(e.Message);
            }
        }

        private static int readShort(Stream ins)
        {
            return ins.ReadByte() * 256 + ins.ReadByte();

        }

        /**
         * Converts the key to a byte array
         * @return the encoded key
         * @see #SignaturePublicKey(byte[])
         */
        public byte[] getEncoded()
        {
            MemoryStream os = new MemoryStream();
            BinaryWriter dataStream = new BinaryWriter(os);
            try
            {
                dataStream.Write((short)h.Coeffs.Length);
                dataStream.Write((short)q);
                dataStream.Write(h.ToBinary(q));//pos 161
            }
            catch (IOException e)
            {
                throw new NtruException(e.Message);
            }
            return os.ToArray();
        }

        /**
         * Writes the key to an output stream
         * @param os an output stream
         * @throws IOException
         * @see #SignaturePublicKey(InputStream)
         */
        public void writeTo(MemoryStream os)
        {
            new BinaryWriter(os).Write(getEncoded());
        }

        //@Override
        public override int GetHashCode()
        {
            int prime = 31;
            int result = 1;
            result = prime * result + ((h == null) ? 0 : h.GetHashCode());
            result = prime * result + q;
            return result;
        }

        //@Override
        public override bool Equals(object obj)
        {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            //if (getClass() != obj.getClass())
            //     return false;
            SignaturePublicKey other = (SignaturePublicKey)obj;
            if (h == null)
            {
                if (other.h != null)
                    return false;
            }
            else if (!h.Equals(other.h))
                return false;
            if (q != other.q)
                return false;
            return true;
        }
    }
}