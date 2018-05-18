#region Directives
using System;
using System.IO;
using System.ComponentModel;
#endregion

#region Notes
// A version of Brett Trotter's C# version of Ent: http://www.codeproject.com/Articles/11672/ENT-A-Pseudorandom-Number-Sequence-Test-Program-C?msg=4671947#xx4671947xx
// The original c++ program written by John Walker: http://www.fourmilab.ch/random/
#endregion

namespace VTDev.Libraries.CEXEngine.Tools
{
    /// <summary>
    /// A version of the Ent random testing class; evaluates entropy levels within a sample or a file
    /// </summary>
    public class EntResult
    {
        /// <summary>
        /// Entropy bits per byte (ex. 7.999826)
        /// </summary>
        public double Entropy;
        /// <summary>
        /// Chi square distribution
        /// </summary>
        public double ChiSquare;
        /// <summary>
        /// The Chi square probability percentage, (50% is optimum)
        /// </summary>
        public double ChiProbability;
        /// <summary>
        /// Arithmetic mean value (127.5 = random)
        /// </summary>
        public double Mean;
        /// <summary>
        /// The constant 127.5
        /// </summary>
        public double ExpectedMeanForRandom;
        /// <summary>
        /// Monte Carlo value for Pi (value should be close to Pi)
        /// </summary>
        public double MonteCarloPiCalc;
        /// <summary>
        /// The Monte Carlo error percentage (lower is better)
        /// </summary>
        public double MonteCarloErrorPct;
        /// <summary>
        /// Serial correlation coefficient (totally uncorrelated = 0.0)
        /// </summary>
        public double SerialCorrelation;
        /// <summary>
        /// The collection bin counter
        /// </summary>
        public long[] OccuranceCount;
        /// <summary>
        /// The maximum compression ratio
        /// </summary>
        public double OptimumCompressionReductionPct;
        /// <summary>
        /// The number of samples tested
        /// </summary>
        public long NumberOfSamples;
        /// <summary>
        /// The Pi sample graph
        /// </summary>
        public double[] PiSamples;
        /// <summary>
        /// The Mean sample graph
        /// </summary>
        public double[] MeanSamples;
    }

    /// <summary>
    /// The ENT random tests class
    /// </summary>
    public class Ent : IDisposable
    {
        #region Event
        /// <summary>
        /// Ent evaluation progress counter
        /// </summary>
        /// <param name="Percent">The percentage calculated</param>
        public delegate void EntCounterDelegate(long Percent);
        /// <summary>
        /// The Ent progress counter
        /// </summary>
        public event EntCounterDelegate ProgressCounter;
        #endregion

        #region Constants
        private const int BIN_BUFFER = 32768;
        private const int MONTE_COUNT = 6;
        private const int SUB_SAMPLES = 64;
        private const int SAMPLE_SIZE = 4096;
        #endregion

        #region Fields
        private long[] m_binCount = new long[256];
        private static double m_currentProgress = 0;
        private double[] m_entProbability = new double[256];
        private double m_inCirc = 0;
        private bool m_isDisposed = false;
        private double[] m_meanSamples = new double[SUB_SAMPLES];
        private long m_monteAccum = 0;
        private double m_montePi = 0;
        private uint[] m_montePiComp = new uint[MONTE_COUNT];
        private long m_monteTries = 0;
        private double m_monteX = 0;
        private double m_monteY = 0;
        private double[] m_piSamples = new double[SUB_SAMPLES];
        private long m_totalBytes = 0;
        private double m_serialCC = 0;
        private double m_serialLast = 0;
        private double m_serialRun = 0;
        private double m_serialT1 = 0;
        private double m_serialT2 = 0;
        private double m_serialT3 = 0;
        private double m_serialU0 = 0;
        private readonly double[,] m_chiSqt = new double[2, 10] 
			{
				{0.5, 0.25, 0.1, 0.05, 0.025, 0.01, 0.005, 0.001, 0.0005, 0.0001}, 
				{0.0, 0.6745, 1.2816, 1.6449, 1.9600, 2.3263, 2.5758, 3.0902, 3.2905, 3.7190}
			};
        #endregion

        #region Constructor
        /// <summary>
        /// Initialize this class
        /// </summary>
        public Ent()
        {
            this.GraphCollection = false;
            Init();
        }

        /// <summary>
        /// Finalize resources
        /// </summary>
        ~Ent()
        {
            Dispose(false);
        }
        #endregion

        #region Properties
        /// <summary>
        /// If true, returns the Pi and Mean value graphs in the EntResult structure
        /// </summary>
        public bool GraphCollection { get; set; }
        #endregion

        #region Public Methods
        /// <summary>
        /// Calculate the entropy contained in a file
        /// </summary>
        /// 
        /// <param name="FileName">The full path to the file to be tested</param>
        /// 
        /// <returns>A populated <see cref="EntResult"/> class</returns>
        public EntResult Calculate(string FileName)
        {
            byte[] fileBuffer;
            m_currentProgress = 0;

            using (FileStream fileStream = new FileStream(FileName, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                fileBuffer = new byte[fileStream.Length];
                fileStream.Read(fileBuffer, 0, (int)fileStream.Length);
            }

            AddSamples(fileBuffer);

            return EndCalculation();
        }

        /// <summary>
        /// Calculate the entropy contained in a sample
        /// </summary>
        /// 
        /// <param name="Buffer">The sample array to be tested</param>
        /// 
        /// <returns>A populated <see cref="EntResult"/> class</returns>
        public EntResult Calculate(byte[] Buffer)
        {
            m_currentProgress = 0;
            AddSamples(Buffer);

            return EndCalculation();
        }

        /// <summary>
        /// Reset the class variables
        /// </summary>
        public void Reset()
        {
            m_binCount = new long[256];
            m_currentProgress = 0;
            m_entProbability = new double[256];
            m_inCirc = Math.Pow(Math.Pow(256.0, (double)(MONTE_COUNT / 2)) - 1, 2.0);
            m_meanSamples = new double[SUB_SAMPLES];
            m_monteAccum = 0;
            m_montePi = 0;
            m_montePiComp = new uint[MONTE_COUNT];
            m_monteTries = 0;
            m_monteX = 0;
            m_monteY = 0;
            m_piSamples = new double[SUB_SAMPLES];
            m_totalBytes = 0;
            m_serialCC = 0;
            m_serialLast = 0;
            m_serialRun = 0;
            m_serialT1 = 0;
            m_serialT2 = 0;
            m_serialT3 = 0;
            m_serialU0 = 0;
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Calculate the progress
        /// </summary>
        /// 
        /// <param name="Position">Current position</param>
        /// <param name="Maximum">Progress max</param>
        private void CalculateProgress(long Position, long Maximum)
        {
            if (ProgressCounter != null)
            {
                double pos = Position;
                double percent = Math.Round((double)(pos / Maximum) * 100, 0);
                if (percent > m_currentProgress)
                {
                    ProgressCounter((long)percent);
                    m_currentProgress = percent;
                }
            }
        }

        /// <summary>
        /// Initialize random counters
        /// </summary>
        private void Init()
        {
            // Reset Monte Carlo accumulator pointer
            m_monteAccum = 0;
            // Clear Monte Carlo tries
            m_monteTries = 0;
            // Clear Monte Carlo inside count
            m_inCirc = 65535.0 * 65535.0;
            // Mark first time for serial correlation
            m_serialT1 = m_serialT2 = m_serialT3 = 0.0;
            // Clear serial correlation terms
            m_inCirc = Math.Pow(Math.Pow(256.0, (double)(MONTE_COUNT / 2)) - 1, 2.0);

            for (int i = 0; i < 256; i++)
                m_binCount[i] = 0;

            m_totalBytes = 0;
        }

        /// <summary>
        /// Add one or more bytes to accumulation
        /// </summary>
        /// 
        /// <param name="Samples">Buffer</param>
        private void AddSamples(byte[] Samples)
        {
            int mp = 0;
            bool sccFirst = true;
            int preProcessLength = (Samples.Length - BIN_BUFFER) / SAMPLE_SIZE;
            int counter = 0;

            if (this.GraphCollection)
            {
                m_piSamples = new double[preProcessLength];
                m_meanSamples = new double[preProcessLength];
            }

            for (int i = 0; i < Samples.Length; i++)
            {
                // Update counter for this bin
                m_binCount[(int)Samples[i]]++;
                m_totalBytes++;
                // Update inside/outside circle counts for Monte Carlo computation of PI
                m_montePiComp[mp++] = Samples[i];

                // Save character for Monte Carlo
                if (mp >= MONTE_COUNT)
                {
                    // Calculate every MONTEN character
                    int mj;
                    mp = 0;
                    m_monteAccum++;
                    m_monteX = m_monteY = 0;

                    for (mj = 0; mj < MONTE_COUNT / 2; mj++)
                    {
                        m_monteX = (m_monteX * 256.0) + m_montePiComp[mj];
                        m_monteY = (m_monteY * 256.0) + m_montePiComp[(MONTE_COUNT / 2) + mj];
                    }

                    if ((m_monteX * m_monteX + m_monteY * m_monteY) <= m_inCirc)
                        m_monteTries++;
                }

                // Update calculation of serial correlation coefficient
                m_serialRun = (int)Samples[i];
                if (sccFirst)
                {
                    sccFirst = false;
                    m_serialLast = 0;
                    m_serialU0 = m_serialRun;
                }
                else
                {
                    m_serialT1 = m_serialT1 + m_serialLast * m_serialRun;
                }

                m_serialT2 = m_serialT2 + m_serialRun;
                m_serialT3 = m_serialT3 + (m_serialRun * m_serialRun);
                m_serialLast = m_serialRun;

                // collect samples for graphs
                if (this.GraphCollection)
                {
                    if (i % SAMPLE_SIZE == 0 && i > BIN_BUFFER)
                    {
                        double dataSum = 0.0;

                        for (int j = 0; j < 256; j++)
                            dataSum += ((double)j) * m_binCount[j];

                        m_meanSamples[counter] = dataSum / m_totalBytes;
                        m_piSamples[counter] = 4.0 * (((double)m_monteTries) / m_monteAccum);
                        counter++;
                    }
                }

                if (i == Samples.Length - 1)
                {
                    byte[] b = new byte[16];
                    Buffer.BlockCopy(Samples, Samples.Length - 17, b, 0, 16);
                }
                CalculateProgress(m_totalBytes, Samples.Length);
            }
        }

        /// <summary>
        /// Complete calculation and return results
        /// </summary>
        /// 
        /// <returns>EntResult Structure</returns>
        private EntResult EndCalculation()
        {
            double entropy = 0.0;
            double chiSq = 0.0;
            double dataSum = 0.0;
            double binVal = 0.0;
            int pos = 0;

            // Complete calculation of serial correlation coefficient
            m_serialT1 = m_serialT1 + m_serialLast * m_serialU0;
            m_serialT2 = m_serialT2 * m_serialT2;
            m_serialCC = m_totalBytes * m_serialT3 - m_serialT2;

            if (m_serialCC == 0.0)
                m_serialCC = -100000;
            else
                m_serialCC = (m_totalBytes * m_serialT1 - m_serialT2) / m_serialCC;

            // Scan bins and calculate probability for each bin and Chi-Square distribution
            double cExp = m_totalBytes / 256.0;

            // Expected count per bin
            for (int i = 0; i < 256; i++)
            {
                m_entProbability[i] = (double)m_binCount[i] / m_totalBytes;
                binVal = m_binCount[i] - cExp;
                chiSq = chiSq + (binVal * binVal) / cExp;
                dataSum += ((double)i) * m_binCount[i];
            }

            // Calculate entropy
            for (int i = 0; i < 256; i++)
            {
                if (m_entProbability[i] > 0.0)
                    entropy += m_entProbability[i] * Log2(1 / m_entProbability[i]);
            }

            // Calculate Monte Carlo value for PI from percentage of hits within the circle
            m_montePi = 4.0 * (((double)m_monteTries) / m_monteAccum);

            // Calculate probability of observed distribution occurring from the results of the Chi-Square test
            double chip = Math.Sqrt(2.0 * chiSq) - Math.Sqrt(2.0 * 255.0 - 1.0);

            binVal = Math.Abs(chip);

            for (pos = 9; pos >= 0; pos--)
            {
                if (m_chiSqt[1, pos] < binVal)
                    break;
            }

            if (pos < 0) pos = 0;

            chip = (chip >= 0.0) ? m_chiSqt[0, pos] : 1.0 - m_chiSqt[0, pos];
            double compReductionPct = (8 - entropy) / 8.0;

            // Return results
            EntResult result = new EntResult()
            {
                Entropy = entropy,
                ChiSquare = chiSq,
                ChiProbability = chip,
                Mean = dataSum / m_totalBytes,
                ExpectedMeanForRandom = 127.5,
                MonteCarloPiCalc = m_montePi,
                MonteCarloErrorPct = (Math.Abs(Math.PI - m_montePi) / Math.PI),
                SerialCorrelation = m_serialCC,
                OptimumCompressionReductionPct = compReductionPct,
                OccuranceCount = m_binCount,
                NumberOfSamples = m_totalBytes,
                MeanSamples = m_meanSamples,
                PiSamples = m_piSamples
            };

            return result;
        }

        /// <summary>
        /// Returns log faction
        /// </summary>
        private double Log2(double x)
        {
            return Math.Log(x, 2);
        }
        #endregion

        #region IDispose
        /// <summary>
        /// Dispose of this class
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }

        void IDisposable.Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool Disposing)
        {
            if (!m_isDisposed)
            {
                if (Disposing)
                {
                    // clear the arrays
                    if (m_binCount != null)
                        Array.Clear(m_binCount, 0, m_binCount.Length);
                    if (m_entProbability != null)
                        Array.Clear(m_entProbability, 0, m_entProbability.Length);
                    if (m_meanSamples != null)
                        Array.Clear(m_meanSamples, 0, m_meanSamples.Length);
                    if (m_montePiComp != null)
                        Array.Clear(m_montePiComp, 0, m_montePiComp.Length);
                    if (m_piSamples != null)
                        Array.Clear(m_piSamples, 0, m_piSamples.Length);
                    if (m_chiSqt != null)
                        Array.Clear(m_chiSqt, 0, m_chiSqt.Length);
                }
                m_isDisposed = true;
            }
        }
        #endregion
    }
}
