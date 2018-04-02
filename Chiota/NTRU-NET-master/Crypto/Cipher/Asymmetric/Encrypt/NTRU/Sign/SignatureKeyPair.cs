#region Directives
using System;
using System.IO;
using Numeric;
#endregion

namespace NTRU.Sign
{
/** Contains a public and a private signature key */
    public class SignatureKeyPair
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

        public SignaturePrivateKey priv;
        public SignaturePublicKey pub;

        /**
         * Constructs a new key pair.
         * @param priv a private key
         * @param pub a public key
         */
        public SignatureKeyPair(SignaturePrivateKey priv, SignaturePublicKey pub)
        {
            this.priv = priv;
            this.pub = pub;
        }

        /**
         * Constructs a new key pair from a byte array
         * @param b an encoded key pair
         */
        public SignatureKeyPair(byte[] b) :
            this(new MemoryStream(b))
        {

        }

        /**
         * Constructs a new key pair from an input stream
         * @param is an input stream
         * @throws NtruException if an {@link IOException} occurs
         */
        public SignatureKeyPair(MemoryStream ins)
        {
            pub = new SignaturePublicKey(ins);
            priv = new SignaturePrivateKey(ins);
        }

        /**
         * Returns the private key
         * @return the private key
         */
        public SignaturePrivateKey getPrivate()
        {
            return priv;
        }

        /**
         * Returns the public key (verification key)
         * @return the public key
         */
        public SignaturePublicKey getPublic()
        {
            return pub;
        }

        /**
         * Tests if the key pair is valid.
         * @return <code>true</code> if the key pair is valid, <code>false</code> otherwise
         */
        public bool isValid()
        {
            if (priv.N != pub.h.Coeffs.Length)
                return false;
            if (priv.q != pub.q)
                return false;

            int B = priv.getNumBases() - 1;
            for (int i = 0; i <= B; i++)
            {
                Basis basis = priv.getBasis(i);
                if (!basis.isValid(i == 0 ? pub.h : basis.h))
                    return false;
            }

            return true;
        }

        /**
         * Converts the key pair to a byte array
         * @return the encoded key pair
         */
        public byte[] getEncoded()
        {
            byte[] pubArr = pub.getEncoded();//161
            byte[] privArr = priv.getEncoded();//295
            byte[] kpArr = ArrayUtils.CopyOf(pubArr, pubArr.Length + privArr.Length);
            Array.Copy(privArr, 0, kpArr, pubArr.Length, privArr.Length);
            return kpArr;//456
        }

        /**
         * Writes the key pair to an output stream
         * @param os an output stream
         * @throws IOException
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
            result = prime * result + ((priv == null) ? 0 : priv.GetHashCode());
            result = prime * result + ((pub == null) ? 0 : pub.GetHashCode());
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
            SignatureKeyPair other = (SignatureKeyPair)obj;
            if (priv == null)
            {
                if (other.priv != null)
                    return false;
            }
            else if (!priv.Equals(other.priv))
                return false;
            if (pub == null)
            {
                if (other.pub != null)
                    return false;
            }
            else if (!pub.Equals(other.pub))
                return false;
            return true;
        }
    }
}