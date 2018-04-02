#region Directives
using System.Collections.Generic;
using System.IO;
using NTRU.Exceptions;
using Numeric;
#endregion

namespace NTRU.Sign
{
/**
 * A NtruSign private key comprises one or more {@link Basis} of three polynomials each,
 * except the zeroth basis for which <code>h</code> is undefined.
 */
    public class SignaturePrivateKey
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

        public int N;
        public int q;
        private bool sparse;
        private TernaryPolynomialType polyType;
        private BasisType basisType;
        private float keyNormBoundSq;
        private List<Basis> bases;

        /**
         * Constructs a new private key from a byte array
         * @param b an encoded private key
         */
        public SignaturePrivateKey(byte[] b) :
            this(new MemoryStream(b))
        {
            ;
        }

        /**
         * Constructs a new private key from an input stream
         * @param is an input stream
         * @throws NtruException if an {@link IOException} occurs
         */
        public SignaturePrivateKey(MemoryStream ins)
        {
            bases = new List<Basis>();

            BinaryReader dataStream = new BinaryReader(ins);
            try
            {
                N = dataStream.ReadInt16();
                q = dataStream.ReadInt16();
                byte flags = dataStream.ReadByte();
                sparse = (flags & 1) != 0;
                polyType = (flags & 4) == 0 ? TernaryPolynomialType.SIMPLE : TernaryPolynomialType.PRODUCT;
                basisType = ((flags & 8) == 0) ? BasisType.STANDARD : BasisType.TRANSPOSE;
                keyNormBoundSq = (float)dataStream.ReadInt32();

                int numBases = dataStream.ReadByte();
                for (int i = 0; i < numBases; i++)
                    // include a public key h[i] in all bases except for the first one
                    add(new Basis(ins, N, q, sparse, polyType, basisType, keyNormBoundSq, i != 0));
            }
            catch (IOException e)
            {
                throw new NtruException(e.Message);
            }
        }

        /**
         * Constructs a private key that contains no bases
         */
        public SignaturePrivateKey(SignatureParameters param)
        {
            N = param.N;
            q = param.q;
            sparse = param.sparse;
            polyType = param.polyType;
            basisType = param.basisType;
            keyNormBoundSq = param.keyNormBoundSq;

            bases = new List<Basis>();
        }

        /**
         * Adds a basis to the key.
         * @param b a NtruSign basis
         */
        public void add(Basis b)
        {
            bases.Add(b);
        }

        /**
         * Returns the <code>i</code>-th basis
         * @param <code>i</code> the index
         * @return the basis at index <code>i</code>
         */
        public Basis getBasis(int i)
        {
            return bases[i];
        }

        public int getNumBases()
        {
            return bases.Count;
        }

        /**
         * Converts the key to a byte array
         * @return the encoded key
         */
        public byte[] getEncoded()
        {
            int numBases = bases.Count;

            MemoryStream os = new MemoryStream();
            BinaryWriter dataStream = new BinaryWriter(os);
            try
            {
                dataStream.Write((short)N);
                dataStream.Write((short)q);

                int flags = sparse ? 1 : 0;
                flags |= polyType == TernaryPolynomialType.PRODUCT ? 4 : 0;
                flags |= basisType == BasisType.TRANSPOSE ? 8 : 0;
                dataStream.Write((byte)flags);//8

                dataStream.Write((float)keyNormBoundSq);//12
                dataStream.Write((byte)numBases);   //13

                for (int i = 0; i < numBases; i++)
                    // all bases except for the first one contain a public key
                    bases[i].encode(os, i != 0);
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
         */
        public void writeTo(MemoryStream os)
        {
            new BinaryWriter(os).Write(getEncoded());
        }

        // @Override
        public override int GetHashCode()
        {
            int prime = 31;
            int result = 1;
            result = prime * result + ((bases == null) ? 0 : bases.GetHashCode());
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
            //    return false;
            SignaturePrivateKey other = (SignaturePrivateKey)obj;
            if (bases == null)
            {
                if (other.bases != null)
                    return false;
            }

            if (bases.Count != other.bases.Count)
                return false;

            for (int i = 0; i < bases.Count; i++)
            {
                if (bases[i].f == null)
                {
                    if (other.bases[i].f != null)
                        return false;
                }
                else if (!bases[i].f.Equals(other.bases[i].f))
                {
                    return false;
                }
                if (bases[i].h == null)
                {
                    if (other.bases[i].h != null)
                        return false;
                }
                else if (!bases[i].h.Equals(other.bases[i].h))
                {
                    return false;
                }
                if (bases[i].N == null)
                {
                    if (other.bases[i].N != null)
                        return false;
                }
                else if (!bases[i].N.Equals(other.bases[i].N))
                {
                    return false;
                }
                if (bases[i].q == null)
                {
                    if (other.bases[i].q != null)
                        return false;
                }
                else if (!bases[i].q.Equals(other.bases[i].q))
                {
                    return false;
                }
            }


            return true;
        }
    }
}