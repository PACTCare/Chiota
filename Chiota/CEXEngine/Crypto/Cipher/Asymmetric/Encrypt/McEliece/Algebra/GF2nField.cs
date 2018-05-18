#region Directives
using System;
using System.Collections;
using System.Collections.Generic;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece.Algebra
{
    /// <summary>
    /// This abstract class defines the finite field <c>GF(2 pow n)</c>.
    /// <para>It holds the extension degree <c>n</c>, the characteristic, the irreducible fieldpolynomial and conversion matrices. 
    /// GF2nField is implemented by the classes GF2nPolynomialField and GF2nONBField.</para>
    /// </summary>
    internal abstract class GF2nField
    {
        #region Public Fields
        /// <summary>
        /// The degree of this field 
        /// </summary>
        protected int DegreeN;
        /// <summary>
        /// The irreducible fieldPolynomial stored in normal order (also for ONB)
        /// </summary>
        protected GF2Polynomial FieldPoly;
        /// <summary>
        /// Holds a list of GF2nFields to which elements have been converted and thus a COB-Matrix exists
        /// </summary>
        public List<GF2nField> Fields;
        /// <summary>
        /// The COB matrices
        /// </summary>
        public List<GF2Polynomial[]> Matrices; 
        #endregion

        #region Properties
        /// <summary>
        /// Get: Returns the degree <c>n</c> of this field
        /// </summary>
        public int Degree
        {
            get { return DegreeN; }
        }

        /// <summary>
        /// Get: Returns the fieldpolynomial as a new Bitstring
        /// </summary>
        public GF2Polynomial FieldPolynomial
        {
            get
            {
                if (FieldPoly == null)
                    ComputeFieldPolynomial();

                return new GF2Polynomial(FieldPoly);
            }
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Decides whether the given object <c>other</c> is the same as this field
        /// </summary>
        /// 
        /// <param name="Obj">The object for comparison</param>
        /// 
        /// <returns>Returns <c>(this == other)</c></returns>
        public override bool Equals(Object Obj)
        {
            if (Obj == null || !(Obj is GF2nField))
                return false;

            GF2nField otherField = (GF2nField)Obj;

            if (otherField.DegreeN != DegreeN)
                return false;
            if (!FieldPoly.Equals(otherField.FieldPoly))
                return false;
            if ((this is GF2nPolynomialField) && !(otherField is GF2nPolynomialField))
                return false;
            if ((this is GF2nONBField) && !(otherField is GF2nONBField))
                return false;
            
            return true;
        }

        /// <summary>
        /// Returns the hash code of this field
        /// </summary>
        /// 
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            return DegreeN * 31 + FieldPoly.GetHashCode();
        }
        #endregion

        #region Abstract Methods
        /// <summary>
        /// Computes a random root from the given irreducible fieldpolynomial according to IEEE 1363 algorithm A.5.6.
        /// <para>This calculation take very long for big degrees.</para>
        /// </summary>
        /// 
        /// <param name="B0FieldPolynomial">The fieldpolynomial if the other basis as a Bitstring</param>
        /// 
        /// <returns>Returns a random root of BOFieldPolynomial in representation according to this field</returns>
        public abstract GF2nElement RandomRoot(GF2Polynomial B0FieldPolynomial);

        /// <summary>
        /// Computes the change-of-basis matrix for basis conversion according to 1363.
        /// <para>The result is stored in the lists fields and matrices.</para>
        /// </summary>
        /// 
        /// <param name="B1">The GF2nField to convert to</param>
        public abstract void ComputeCOBMatrix(GF2nField B1);

        /// <summary>
        /// Computes the fieldpolynomial. This can take a long time for big degrees.
        /// </summary>
        protected abstract void ComputeFieldPolynomial();

        /// <summary>
        /// Inverts the given matrix represented as bitstrings
        /// </summary>
        /// 
        /// <param name="MatrixN">The matrix to invert as a Bitstring[]</param>
        /// 
        /// <returns>Returns <c>matrix^(-1)</c></returns>
        protected GF2Polynomial[] InvertMatrix(GF2Polynomial[] MatrixN)
        {
            GF2Polynomial[] a = new GF2Polynomial[MatrixN.Length];
            GF2Polynomial[] inv = new GF2Polynomial[MatrixN.Length];
            GF2Polynomial dummy;
            int i, j;
            // initialize a as a copy of matrix and inv as E(inheitsmatrix)
            for (i = 0; i < DegreeN; i++)
            {
                try
                {
                    a[i] = new GF2Polynomial(MatrixN[i]);
                    inv[i] = new GF2Polynomial(DegreeN);
                    inv[i].SetBit(DegreeN - 1 - i);
                }
                catch
                {
                    throw;
                }
            }
            // construct triangle matrix so that for each a[i] the first i bits are
            // zero
            for (i = 0; i < DegreeN - 1; i++)
            {
                // find column where bit i is set
                j = i;
                while ((j < DegreeN) && !a[j].TestBit(DegreeN - 1 - i))
                    j++;
                
                if (j >= DegreeN)
                    throw new Exception("GF2nField.InvertMatrix: Matrix cannot be inverted!");
                
                if (i != j)
                { // swap a[i]/a[j] and inv[i]/inv[j]
                    dummy = a[i];
                    a[i] = a[j];
                    a[j] = dummy;
                    dummy = inv[i];
                    inv[i] = inv[j];
                    inv[j] = dummy;
                }

                for (j = i + 1; j < DegreeN; j++)
                { // add column i to all columns>i
                    // having their i-th bit set
                    if (a[j].TestBit(DegreeN - 1 - i))
                    {
                        a[j].AddToThis(a[i]);
                        inv[j].AddToThis(inv[i]);
                    }
                }
            }
            // construct Einheitsmatrix from a
            for (i = DegreeN - 1; i > 0; i--)
            {
                for (j = i - 1; j >= 0; j--)
                { // eliminate the i-th bit in all
                    // columns < i
                    if (a[j].TestBit(DegreeN - 1 - i))
                    {
                        a[j].AddToThis(a[i]);
                        inv[j].AddToThis(inv[i]);
                    }
                }
            }

            return inv;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Converts the given element in representation according to this field to a new element in 
        /// representation according to B1 using the change-of-basis matrix calculated by computeCOBMatrix.
        /// </summary>
        /// 
        /// <param name="Elem">The GF2nElement to convert</param>
        /// <param name="Basis">The basis to convert <c>Elem</c> to</param>
        /// 
        /// <returns>Returns <c>Elem</c> converted to a new element representation according to <c>basis</c></returns>
        public GF2nElement Convert(GF2nElement Elem, GF2nField Basis)
        {
            if (Basis == this)
                return (GF2nElement)Elem.Clone();
            if (FieldPoly.Equals(Basis.FieldPoly))
                return (GF2nElement)Elem.Clone();
            if (DegreeN != Basis.DegreeN)
                throw new Exception("GF2nField.Convert: B1 has a different degree and thus cannot be coverted to!");

            int i;
            GF2Polynomial[] COBMatrix;
            i = Fields.IndexOf(Basis);

            if (i == -1)
            {
                ComputeCOBMatrix(Basis);
                i = Fields.IndexOf(Basis);
            }
            COBMatrix = (GF2Polynomial[])Matrices[i];

            GF2nElement elemCopy = (GF2nElement)Elem.Clone();
            if (elemCopy is GF2nONBElement)
                ((GF2nONBElement)elemCopy).ReverseOrder();

            GF2Polynomial bs = new GF2Polynomial(DegreeN, elemCopy.ToFlexiBigInt());
            bs.ExpandN(DegreeN);
            GF2Polynomial result = new GF2Polynomial(DegreeN);
            for (i = 0; i < DegreeN; i++)
            {
                if (bs.VectorMult(COBMatrix[i]))
                    result.SetBit(DegreeN - 1 - i);
            }

            if (Basis is GF2nPolynomialField)
            {
                return new GF2nPolynomialElement((GF2nPolynomialField)Basis, result);
            }
            else if (Basis is GF2nONBField)
            {
                GF2nONBElement res = new GF2nONBElement((GF2nONBField)Basis, result.ToFlexiBigInt());
                res.ReverseOrder();

                return res;
            }
            else
            {
                throw new Exception("GF2nField.convert: B1 must be an instance of GF2nPolynomialField or GF2nONBField!");
            }
        }
        #endregion
    }
}
