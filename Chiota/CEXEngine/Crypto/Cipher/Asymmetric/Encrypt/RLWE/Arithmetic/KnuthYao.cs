using System;

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.RLWE.Arithmetic
{
    // from: https://github.com/jnortiz/PKE-PEKS/blob/const_time/PKE-PEKS/Samplers.cpp
    // Work in progress.. problems with this class!
    internal class KnuthYao
    {
        private static int[][] _P;
        Random _secRand = new Random(0);

        internal uint GetRand()
        {
            return (uint)_secRand.Next();
        }

        double Probability(double x, double sigma)
        {
            double S = sigma * Math.Sqrt(2 * Math.PI);
            double overS = 1.0 / S;

            if (x == 0.0)
                return overS;

            return overS * Math.Exp(-(Math.Pow(x / sigma, 2.0)) / 2.0);
        }

        // This method build the probability matrix for samples in the range; [-tailcut*\floor(sigma), +tailcut*\floor(sigma)]
        internal void BuildProbabilityMatrix(int precision, int tailcut, double sigma)
        {
            // The random variable consists of elements in [-tailcut*sigma, tailcut*sigma]
            int i, bound; // p:55, t:109? 14, 133
            double probOfX;
            bound = (tailcut * (int)sigma);
            
            _P = new int[precision][];
            for (i = 0; i < _P.Length; i++)
                _P[i] = new int[2 * bound + 1];

            i = 2 * bound;
            for (int x = -bound; x <= bound || i >= 0; x++, i--)
            {
                probOfX = Probability((double)x, sigma);
                BinaryExpansion(probOfX, precision, i);
            }
        }

        // Method for computing the binary expansion of a given probability in [0, 1] 
        void BinaryExpansion(double probability, int precision, int index)
        {
            double pow;
            int i, j;
            i = -1;
            j = 0;

            while (probability > 0 && j < precision)
            {
                //pow = 2^{i}
                pow = Math.Pow(2, i--);
                if (pow <= probability)
                {
                    _P[j][index] = 1;
                    probability -= pow;
                }
                else
                {
                    _P[j][index] = 0;
                }

                j++;
            }
        }

        // Using the Knuth-Yao algorithm, it produces a n-dimension polynomial with coefficients from the Gaussian distribution
        internal int[] PolyGeneratorKnuthYao(int dimension, int precision, int tailcut, double sigma) 
        {
            //cout << "\n[*] Knuth-Yao Gaussian sampling" << endl;
            // Output precision setup
            precision = SetOutputPrecision(precision);
            BuildProbabilityMatrix(precision, tailcut, sigma);
            //cout << "[*] Probability matrix building status: Pass!" << endl;
            int[] polynomial;
            int bound, samplesGen, iterations;
    
            polynomial =  new int[dimension]; //.SetLength((long)dimension);
            bound = tailcut * (int)sigma;
            iterations = 0;
    
            do 
            {
                samplesGen = 0; // It counts the number of successfully generated samples
                for(int i = 0; i < dimension; i++) 
                {
                    polynomial[i] = KnuthYaoSample(precision, tailcut, sigma);
                    // Samples equal to the bound won't be accepted
                    if(polynomial[i] < bound && polynomial[i] > -bound)
                        samplesGen++;
                }
                iterations++;
            } while(samplesGen < dimension);
    
            //if(samplesGen == dimension)
            //    cout << "[*] All samples were successfully generated in " << iterations << " iteration(s)." << endl;

            return polynomial;
    
        }

        /* Knuth-Yao algorithm to obtain a sample from the discrete Gaussian */
        int KnuthYaoSample(int precision, int tailcut, double sigma)
        {
    
            int bound, col, d, invalidSample, pNumRows, pNumCols, r, searchRange, S;
            int enable, hit;
    
            bound = tailcut * (int)sigma;
            d = 0;      // Distance
            hit = 0;
            invalidSample = 3*bound;
            pNumRows = precision;
            pNumCols = 2 * bound + 1;    
    
            // Approximated search range required to obtain all samples with only one iteration in PolyGeneratorKnuthYao() algorithm
            searchRange = pNumRows / 4; //- ?
            S = 0;
    
            for(int row = 0; row < searchRange; row++) 
            {
                r = (int)GetRand() & 1; // Random choice between 0 and 1
                d = 2 * d + r;          // Distance calculus
        
                for(col = 0; col < pNumCols; col++) 
                {
                    d = d - _P[row][col];
                    enable = (d + 1);   // Enable turns 0 iff d = -1
                    // Enable turns 1 iff enable was 0
                    enable = enable == 0 ? 1 : 0; //(1 ^ (((enable | -enable) >> 31) & 1));
                    // When enable&!hit becomes 1, "col" is added to "S";  e.g. enable = 1 and hit = 0
                    int uhit = ((enable == 1 && hit == 0) ? 1: 0);
                    S += Select(invalidSample, col, uhit);
                    hit += uhit;     
                }
            }
    
            // Note: the "col" value is in [0, 2*bound]. So, the invalid sample must be greater than 2*bound.
            S = S % invalidSample;
            S -= bound;
    
            return S;
        }

        int Select(int a, int b, int bit)
        {
            int mask;
            int output;
            mask = -bit;
            output = mask & (a ^ b);
            output = output ^ a;
            return output;
        }

        int SetOutputPrecision(int p) 
        { 
           if (p < 1) 
              p = 1;

           return p;
        } 
    }
}
