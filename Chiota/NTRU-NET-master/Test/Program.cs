#region Directives
using System;
using Test.Tests.Arith;
using Test.Tests.Encode;
using Test.Tests.Encrypt;
using Test.Tests.Polynomial;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU;
using System.Runtime.InteropServices;
using System.Diagnostics;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Libraries.CEXEngine.Crypto.Prng;
using Test.Tests;
using VTDev.Libraries.CEXEngine.Crypto;
#endregion

namespace Test
{
    /// <summary>
    /// Original NTRUEncrypt paper: http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.25.8422&rep=rep1&type=pdf
    /// Follow-up NTRUEncrypt paper: http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.64.6834&rep=rep1&type=pdf
    /// Original NTRUSign paper: http://www.math.brown.edu/~jpipher/NTRUSign_RSA.pdf
    /// Follow-up NTRUSign paper: http://grouper.ieee.org/groups/1363/WorkingGroup/presentations/NTRUSignParams-2005-08.pdf
    /// NTRU articles (technical and mathematical): http://www.securityinnovation.com/security-lab/crypto.html
    /// Jeffrey Hoffstein et al: An Introduction to Mathematical Cryptography, Springer-Verlag, ISBN 978-0-387-77993-5 
    /// EESS: http://grouper.ieee.org/groups/1363/lattPK/submissions/EESS1v2.pdf
    /// </summary>
    static class Program
    {
        const int CYCLE_COUNT = 100;
        const string CON_TITLE = "NTRU> ";

        #region Main
        static void Main(string[] args)
        {
            ConsoleUtils.SizeConsole(80, 60);
            ConsoleUtils.CenterConsole();
            Console.Title = "NTRU Sharp Test Suite";

            // header
            Console.WriteLine("**********************************************");
            Console.WriteLine("* NTRU Encrypt in C# (NTRU Sharp)            *");
            Console.WriteLine("*                                            *");
            Console.WriteLine("* Release:   v1.0                            *");
            Console.WriteLine("* Date:      April 05, 2015                  *");
            Console.WriteLine("* Contact:   develop@vtdev.com               *");
            Console.WriteLine("**********************************************");
            Console.WriteLine("");
            Console.WriteLine("COMPILE as Any CPU | Release mode, RUN the .exe for real timings");
            Console.WriteLine("");

            if (Debugger.IsAttached)
            {
                Console.WriteLine("You are running in Debug mode! Compiled times will be much faster..");
                Console.WriteLine("");
            }

            Console.WriteLine(CON_TITLE + "Run Validation Tests? Press 'Y' to run, any other key to skip..");
            ConsoleKeyInfo keyInfo = Console.ReadKey();
            Console.WriteLine("");

            if (keyInfo.Key.Equals(ConsoleKey.Y))
            {
                // math
                Console.WriteLine("******TESTING BIGINTEGER MATH FUNCTIONS******");
                RunTest(new BigIntEuclideanTest());
                RunTest(new IntEuclideanTest());
                RunTest(new SchönhageStrassenTest());/**/

                // polynomials
                Console.WriteLine("******TESTING POLYNOMINAL FUNCTIONS******");
                RunTest(new BigDecimalPolynomialTest());
                RunTest(new BigIntPolynomialTest());
                RunTest(new DenseTernaryPolynomialTest());
                RunTest(new IntegerPolynomialTest());
                RunTest(new LongPolynomial2Test());
                RunTest(new LongPolynomial5Test());
                RunTest(new ProductFormPolynomialTest());
                RunTest(new SparseTernaryPolynomialTest());
                Console.WriteLine("");/**/

                // utils
                Console.WriteLine("******TESTING ARRAY ENCODERS******");
                RunTest(new ArrayEncoderTest());
                Console.WriteLine("");/**/

                // encrypt
                Console.WriteLine("******TESTING ENCRYPTION ENGINE******");
                RunTest(new BitStringTest());
                RunTest(new NtruKeyPairTest());
                RunTest(new NtruEncryptTest());
                RunTest(new NtruKeyTest());
                RunTest(new NtruParametersTest());
                RunTest(new IndexGeneratorTest());
                RunTest(new PBPRngTest());
                Console.WriteLine("");/**/

                Console.WriteLine("Validation Tests Completed!");
            }

            Console.WriteLine("");
            Console.WriteLine(CON_TITLE + "Run Speed Tests? Press 'Y' to run, any other key to skip..");
            keyInfo = Console.ReadKey();
            Console.WriteLine("");

            if (keyInfo.Key.Equals(ConsoleKey.Y))
            {
                EncryptionSpeed(CYCLE_COUNT);
                DecryptionSpeed(CYCLE_COUNT);
                KeyGenSpeed(CYCLE_COUNT);
                Console.WriteLine("Speed Tests Completed!");
                Console.WriteLine("");
            }

            Console.WriteLine("");
            Console.WriteLine(CON_TITLE + "Run Looping Full-Cycle Tests? Press 'Y' to run, all other keys close..");
            keyInfo = Console.ReadKey();
            Console.WriteLine("");

            if (keyInfo.Key.Equals(ConsoleKey.Y))
            {
                Console.WriteLine("");
                Console.WriteLine("******Looping: Key Generation/Encryption/Decryption and Verify Test******");
                Console.WriteLine(string.Format("Testing {0} Full Cycles, throws on all failures..", CYCLE_COUNT));
                try
                {
                    CycleTest(CYCLE_COUNT);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("!Loop test failed! " + ex.Message);
                }
                Console.WriteLine("");
                Console.WriteLine(CON_TITLE + "All tests have completed, press any key to close..");
                Console.ReadKey();
            }
            else
            {
                Environment.Exit(0);
            }
        }

        private static void RunTest(ITest Test)
        {
            try
            {
                Test.Progress -= OnTestProgress;
                Test.Progress += new EventHandler<TestEventArgs>(OnTestProgress);
                Console.WriteLine(Test.Description);
                Console.WriteLine(Test.Test());
                Console.WriteLine();
            }
            catch (Exception Ex)
            {
                Console.WriteLine("!An error has occured!");
                Console.WriteLine(Ex.Message);
                Console.WriteLine("");
                Console.WriteLine(">Continue Testing? Press 'Y' to continue, all other keys abort..");
                ConsoleKeyInfo keyInfo = Console.ReadKey();

                if (!keyInfo.Key.Equals(ConsoleKey.Y))
                    Environment.Exit(0);
                else
                    Console.WriteLine();
            }
        }

        private static void OnTestProgress(object sender, TestEventArgs e)
        {
            Console.WriteLine(e.Message);
        }
        #endregion

        #region Timing Tests
        static void CycleTest(int Iterations)
        {
            Stopwatch runTimer = new Stopwatch();
            runTimer.Start();
            for (int i = 0; i < Iterations; i++)
                FullCycle();
            runTimer.Stop();

            double elapsed = runTimer.Elapsed.TotalMilliseconds;
            Console.WriteLine(string.Format("{0} cycles completed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Average cycle time: {0} ms", elapsed / Iterations));
            Console.WriteLine("");
        }

        static void DecryptionSpeed(int Iterations)
        {
            Console.WriteLine(string.Format("******Looping Decryption Test: Testing {0} Iterations******", Iterations));

            Console.WriteLine("Test decryption times using the APR2011439FAST parameter set.");
            double elapsed = Decrypt(Iterations, NTRUParamSets.APR2011439FAST);
            Console.WriteLine(string.Format("{0} decryption cycles completed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Ran {0} Iterations in avg. {1} ms.", Iterations, elapsed / Iterations));
            Console.WriteLine(string.Format("Decryption Rate is {0} per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");

            Console.WriteLine("Test decryption times using the APR2011743FAST parameter set.");
            elapsed = Decrypt(Iterations, NTRUParamSets.APR2011743FAST);
            Console.WriteLine(string.Format("{0} decryption cycles completed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Ran {0} Iterations in avg. {1} ms.", Iterations, elapsed / Iterations));
            Console.WriteLine(string.Format("Decryption Rate is {0} per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");
        }

        static void EncryptionSpeed(int Iterations)
        {
            Console.WriteLine(string.Format("******Looping Encryption Test: Testing {0} Iterations******", Iterations));

            Console.WriteLine("Test encryption times using the APR2011439FAST parameter set.");
            double elapsed = Encrypt(Iterations, NTRUParamSets.APR2011439FAST);
            Console.WriteLine(string.Format("{0} encryption cycles completed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Ran {0} Iterations in avg. {1} ms.", Iterations, elapsed / Iterations));
            Console.WriteLine(string.Format("Encryption Rate is {0} per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");

            Console.WriteLine("Test encryption times using the APR2011743FAST parameter set.");
            elapsed = Encrypt(Iterations, NTRUParamSets.APR2011743FAST);
            Console.WriteLine(string.Format("{0} encryption cycles completed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Ran {0} Iterations in avg. {1} ms.", Iterations, elapsed / Iterations));
            Console.WriteLine(string.Format("Encryption Rate is {0} per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");
        }

        static void FullCycle()
        {
            NTRUParameters mpar = NTRUParamSets.APR2011439FAST; //APR2011743FAST
            NTRUKeyGenerator mkgen = new NTRUKeyGenerator(mpar);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
            byte[] enc;

            using (NTRUEncrypt mpe = new NTRUEncrypt(mpar))
            {
                mpe.Initialize(akp.PublicKey);

                byte[] data = new byte[mpe.MaxPlainText];
                enc = mpe.Encrypt(data);
                mpe.Initialize(akp);
                byte[] dec = mpe.Decrypt(enc);

                if (!Compare.AreEqual(dec, data))
                    throw new Exception("Encryption test: decryption failure!");
            }
        }

        static void KeyGenSpeed(int Iterations)
        {
            Console.WriteLine(string.Format("Key creation average time over {0} passes:", Iterations));
            Stopwatch runTimer = new Stopwatch();
            double elapsed;

            elapsed = KeyGenerator(Iterations, NTRUParamSets.APR2011439FAST);
            Console.WriteLine(string.Format("APR2011439FAST: avg. {0} ms", elapsed / Iterations, Iterations));
            Console.WriteLine(string.Format("{0} keys created in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Creation Rate is {0} keys per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");

            elapsed = KeyGenerator(Iterations, NTRUParamSets.APR2011743FAST);
            Console.WriteLine(string.Format("APR2011743FAST: avg. {0} ms", elapsed / Iterations, Iterations));
            Console.WriteLine(string.Format("{0} keys created in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Creation Rate is {0} keys per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");

            Iterations = 4;
            Console.WriteLine(string.Format("Testing each key with {0} passes:", Iterations));
            Console.WriteLine("");

            foreach (int p in Enum.GetValues(typeof(NTRUParamSets.NTRUParamNames)))
            {
                NTRUParameters param = NTRUParamSets.FromName((NTRUParamSets.NTRUParamNames)p);
                elapsed = KeyGenerator(Iterations, param);
                Console.WriteLine(string.Format(Enum.GetName(typeof(NTRUParamSets.NTRUParamNames), p) + ": avg. {0} ms", elapsed / Iterations, Iterations));
                Console.WriteLine(string.Format("{0} keys created in: {1} ms", Iterations, elapsed));
                Console.WriteLine("");
            }

            Console.WriteLine("");
        }

        static double KeyGenerator(int Iterations, NTRUParameters Param)
        {
            NTRUKeyGenerator mkgen = new NTRUKeyGenerator(Param);
            IAsymmetricKeyPair akp;
            Stopwatch runTimer = new Stopwatch();

            runTimer.Start();
            for (int i = 0; i < Iterations; i++)
                akp = mkgen.GenerateKeyPair();
            runTimer.Stop();

            return runTimer.Elapsed.TotalMilliseconds;
        }

        static double Decrypt(int Iterations, NTRUParameters Param)
        {
            NTRUKeyGenerator mkgen = new NTRUKeyGenerator(Param);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
            byte[] ptext = new CSPRng().GetBytes(64);
            byte[] rtext = new byte[64];
            byte[] ctext;
            Stopwatch runTimer = new Stopwatch();

            using (NTRUEncrypt mpe = new NTRUEncrypt(Param))
            {
                mpe.Initialize(akp.PublicKey);
                ctext = mpe.Encrypt(ptext);
                mpe.Initialize(akp);

                runTimer.Start();
                for (int i = 0; i < Iterations; i++)
                    rtext = mpe.Decrypt(ctext);
                runTimer.Stop();
            }

            //if (!Compare.AreEqual(ptext, rtext))
            //    throw new Exception("Encryption test: decryption failure!");

            return runTimer.Elapsed.TotalMilliseconds;
        }

        static double Encrypt(int Iterations, NTRUParameters Param)
        {
            NTRUKeyGenerator mkgen = new NTRUKeyGenerator(Param);
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
            byte[] ptext = new CSPRng().GetBytes(64);
            byte[] ctext;
            Stopwatch runTimer = new Stopwatch();

            using (NTRUEncrypt mpe = new NTRUEncrypt(Param))
            {
                mpe.Initialize(akp.PublicKey);

                runTimer.Start();
                for (int i = 0; i < Iterations; i++)
                    ctext = mpe.Encrypt(ptext);
                runTimer.Stop();
            }

            return runTimer.Elapsed.TotalMilliseconds;
        }
        #endregion
    }
}
