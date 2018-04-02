#region Directives
using System;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU.Arithmetic;
using VTDev.Libraries.CEXEngine.Numeric;
using VTDev.Libraries.CEXEngine.Tools;
using VTDev.Libraries.CEXEngine.Utility;
#endregion

namespace Test.Tests.Arith
{
    /// <summary>
    /// Test the validity of the SchönhageStrassen implementation
    /// </summary>
    public class SchönhageStrassenTest : ITest
    {
        #region Constants
        private const string DESCRIPTION = "Test the validity of the SchönhageStrassen implementation";
        private const string FAILURE = "FAILURE! ";
        private const string SUCCESS = "SUCCESS! SchönhageStrassen tests have executed succesfully.";
        #endregion

        #region Events
        public event EventHandler<TestEventArgs> Progress;
        protected virtual void OnProgress(TestEventArgs e)
        {
            var handler = Progress;
            if (handler != null) handler(this, e);
        }
        #endregion

        #region Properties
        /// <summary>
        /// Get: Test Description
        /// </summary>
        public string Description { get { return DESCRIPTION; } }
        #endregion

        #region Public Methods
        /// <summary>
        /// SchönhageStrassen tests
        /// </summary>
        /// 
        /// <returns>State</returns>
        public string Test()
        {
            try
            {
                TestAddModFn();
                OnProgress(new TestEventArgs("Passed SchönhageStrassen AddModFn tests"));
                TestAddShifted();
                OnProgress(new TestEventArgs("Passed SchönhageStrassen AddShifted tests"));
                TestAppendBits();
                OnProgress(new TestEventArgs("Passed SchönhageStrassen AppendBits tests"));
                TestCyclicShift();
                OnProgress(new TestEventArgs("Passed SchönhageStrassen CyclicShift tests"));
                TestDftIdft();
                OnProgress(new TestEventArgs("Passed SchönhageStrassen DftIdft tests"));
                TestModFn();
                OnProgress(new TestEventArgs("Passed SchönhageStrassen ModFn tests"));
                TestMult();
                OnProgress(new TestEventArgs("Passed SchönhageStrassen Multiplication tests"));
                TestMultKaratsuba();
                OnProgress(new TestEventArgs("Passed SchönhageStrassen MultKaratsuba tests"));
                TestMultModFn();
                OnProgress(new TestEventArgs("Passed SchönhageStrassen MultModFn tests"));
                TestSubModPow2();
                OnProgress(new TestEventArgs("Passed SchönhageStrassen SubModPow2 tests"));
                TestToBigInteger();
                OnProgress(new TestEventArgs("Passed SchönhageStrassen ToBigIntegertests"));

                return SUCCESS;
            }
            catch (Exception Ex)
            {
                string message = Ex.Message == null ? "" : Ex.Message;
                throw new Exception(FAILURE + message);
            }
        }
        #endregion

        #region Private Methods
        private void TestMult()
        {
            TestMult(BigInteger.ValueOf(0), BigInteger.ValueOf(0));
            TestMult(BigInteger.ValueOf(100), BigInteger.ValueOf(100));
            TestMult(BigInteger.ValueOf(-394786896548787L), BigInteger.ValueOf(604984572698687L));
            TestMult(BigInteger.ValueOf(415338904376L), BigInteger.ValueOf(527401434558L));
            TestMult(new BigInteger("9145524700683826415"), new BigInteger("1786442289234590209543"));

            BigInteger pow19_1 = BigInteger.ValueOf(1).ShiftLeft((1 << 19) - 1);   // 2^(2^19-1)
            BigInteger pow20_2 = BigInteger.ValueOf(1).ShiftLeft((1 << 20) - 2);   // 2^(2^20-2)
            BigInteger pow19 = BigInteger.ValueOf(1).ShiftLeft(1 << 19);   // 2^2^19
            BigInteger pow20 = BigInteger.ValueOf(1).ShiftLeft(1 << 20);   // 2^2^20

            if (!Compare.Equals(pow19_1.ShiftLeft(1024).Subtract(pow19_1), SchonhageStrassen.Multiply(pow19_1, BigInteger.ValueOf(1).ShiftLeft(1024).Subtract(BigInteger.One))))
                throw new Exception("SchönhageStrassen:TestMult test has failed!");
            if (!Compare.Equals(pow20_2, SchonhageStrassen.Multiply(pow19_1, pow19_1)))
                throw new Exception("SchönhageStrassen:TestMult test has failed!");
            if (!Compare.Equals(pow20_2.Subtract(pow19_1), SchonhageStrassen.Multiply(pow19_1, pow19_1.Subtract(BigInteger.One))))
                throw new Exception("SchönhageStrassen:TestMult test has failed!");
            if (!Compare.Equals(pow20_2.Add(pow19_1), SchonhageStrassen.Multiply(pow19_1, pow19_1.Add(BigInteger.One))))
                throw new Exception("SchönhageStrassen:TestMult test has failed!");
            if (!Compare.Equals(pow20, SchonhageStrassen.Multiply(pow19, pow19)))
                throw new Exception("SchönhageStrassen:TestMult test has failed!");
            if (!Compare.Equals(pow20.Subtract(pow19), SchonhageStrassen.Multiply(pow19, pow19.Subtract(BigInteger.One))))
                throw new Exception("SchönhageStrassen:TestMult test has failed!");
            if (!Compare.Equals(pow20.Add(pow19), SchonhageStrassen.Multiply(pow19, pow19.Add(BigInteger.One))))
                throw new Exception("SchönhageStrassen:TestMult test has failed!");
            OnProgress(new TestEventArgs("Passed Known Value Multiplication test"));

            Random rng = new Random();
            TestMult(BigInteger.ValueOf(rng.Next(1000000000) + 524288), BigInteger.ValueOf(rng.Next(1000000000) + 524288));
            TestMult(BigInteger.ValueOf((rng.Next() >> 1) + 1000), BigInteger.ValueOf((rng.Next() >> 1) + 1000));
            TestMult(BigInteger.ValueOf(rng.Next(1000000000) + 524288), BigInteger.ValueOf(rng.Next(1000000000) + 524288));
            TestMult(BigInteger.ValueOf((rng.Next() >> 1) + 1000), BigInteger.ValueOf((rng.Next() >> 1) + 1000));
            OnProgress(new TestEventArgs("Passed Random Multiplication test"));

            int aLength = 80000 + rng.Next(20000);
            int bLength = 80000 + rng.Next(20000);

            for (int i = 0; i < 2; i++)
            {
                byte[] aArr = new byte[aLength];
                rng.NextBytes(aArr);
                byte[] bArr = new byte[bLength];
                rng.NextBytes(bArr);
                BigInteger a = new BigInteger(aArr);
                BigInteger b = new BigInteger(bArr);
                TestMult(a, b);
                // double the length and test again so an even and an odd m is tested
                aLength *= 2;
                bLength *= 2;
            }
            OnProgress(new TestEventArgs("Passed Large Number Multiplication test"));
        }

        private void TestMultKaratsuba()
        {
            TestMult(new int[] { 9, 2 }, new int[] { 5, 6 });
            TestMult(new int[] { 0, -4 }, new int[] { -2, -4 });
            TestMult(new int[] { -5, 4, 0 }, new int[] { 3, 2, -2 });
            TestMult(new int[] { -5, 4, 0, -4 }, new int[] { 3, 2, -2, -4 });
            TestMult(new int[] { 2, -2, 0, -1, -4 }, new int[] { 2, -3, -1, 0, -5 });

            Random rng = new Random();
            for (int i = 0; i < 10; i++)
            {
                int[] a = new int[rng.Next(1000)];
                int[] b = new int[a.Length];
                for (int j = 0; j < a.Length; j++)
                {
                    a[j] = rng.Next(1000) - 500;
                    b[j] = rng.Next(1000) - 500;
                }
                TestMult(a, b);
            }
        }

        private void TestDftIdft()
        {
            for (int i = 0; i < 10; i++)
                TestInversion();
        }

        private void TestAddModFn()
        {
            Random rng = new Random();
            int n = 5 + rng.Next(10);
            int len = 1 << (n + 1 - 5);
            int[] aArr = new int[len];
            for (int i = 0; i < aArr.Length; i++)
                aArr[i] = rng.Next();

            BigInteger a = SchonhageStrassen.ToBigInteger(aArr);
            int[] bArr = new int[len];
            for (int i = 0; i < bArr.Length; i++)
                bArr[i] = rng.Next();

            BigInteger b = SchonhageStrassen.ToBigInteger(bArr);
            SchonhageStrassen.AddModFn(aArr, bArr);
            SchonhageStrassen.ModFn(aArr);
            BigInteger Fn = BigInteger.ValueOf(2).Pow(1 << n).Add(BigInteger.One);
            BigInteger c = a.Add(b).Mod(Fn);

            if (!Compare.Equals(c, SchonhageStrassen.ToBigInteger(aArr)))
                throw new Exception("SchönhageStrassen:AddModFn test has failed!");
        }

        private void TestMultModFn()
        {
            if (!Compare.AreEqual(new int[] { 1713569892, -280255914 }, SchonhageStrassen.MultModFn(new int[] { -142491638, 0 }, new int[] { -142491638, 0 })))
                throw new Exception("SchönhageStrassen:MultModFn test has failed!");
        }

        private void TestModFn()
        {
            int[] a = new int[] { 50593286, 151520511 };
            SchonhageStrassen.ModFn(a);
            if (!Compare.AreEqual(new int[] { -100927224, 0 }, a))
                throw new Exception("SchönhageStrassen:TestModFn test has failed!");

            a = new int[] { 1157041776, -1895306073, -1094584616, -218513495 };
            SchonhageStrassen.ModFn(a);
            if (!Compare.AreEqual(new int[] { -2043340903, -1676792579, 0, 0 }, a))
                throw new Exception("SchönhageStrassen:TestModFn test has failed!");
        }

        private void TestCyclicShift()
        {
            int[] arr = new int[] { 16712450, -2139160576 };

            // test cyclicShiftLeft
            if (!Compare.AreEqual(new int[] { 33424901, 16646144 }, SchonhageStrassen.CyclicShiftLeftBits(arr, 1)))
                throw new Exception("SchönhageStrassen:TestCyclicShift test has failed!");
            if (!Compare.AreEqual(new int[] { -16579968, 2130706432 }, SchonhageStrassen.CyclicShiftLeftBits(arr, 8)))
                throw new Exception("SchönhageStrassen:TestCyclicShift test has failed!");
            if (!Compare.AreEqual(new int[] { 50495615, 255 }, SchonhageStrassen.CyclicShiftLeftBits(arr, 16)))
                throw new Exception("SchönhageStrassen:TestCyclicShift test has failed!");
            if (!Compare.AreEqual(new int[] { 41975552, 65283 }, SchonhageStrassen.CyclicShiftLeftBits(arr, 24)))
                throw new Exception("SchönhageStrassen:TestCyclicShift test has failed!");
            if (!Compare.AreEqual(new int[] { -2139160576, 16712450 }, SchonhageStrassen.CyclicShiftLeftBits(arr, 32)))
                throw new Exception("SchönhageStrassen:TestCyclicShift test has failed!");
            if (!Compare.AreEqual(arr, SchonhageStrassen.CyclicShiftLeftBits(arr, 64)))
                throw new Exception("SchönhageStrassen:TestCyclicShift test has failed!");

            int[] arr2 = SchonhageStrassen.CyclicShiftLeftBits(arr, 17);
            arr2 = SchonhageStrassen.CyclicShiftLeftBits(arr2, 12);
            arr2 = SchonhageStrassen.CyclicShiftLeftBits(arr2, 1);
            arr2 = SchonhageStrassen.CyclicShiftLeftBits(arr2, 1);
            arr2 = SchonhageStrassen.CyclicShiftLeftBits(arr2, 24);
            arr2 = SchonhageStrassen.CyclicShiftLeftBits(arr2, 9);

            if (!Compare.AreEqual(arr, arr2))
                throw new Exception("SchönhageStrassen:TestCyclicShift test has failed!");
            // test cyclicShiftRight
            if (!Compare.AreEqual(new int[] { 8356225, 1077903360 }, SchonhageStrassen.CyclicShiftRight(arr, 1)))
                throw new Exception("SchönhageStrassen:TestCyclicShift test has failed!");
            if (!Compare.AreEqual(new int[] { 65283, 41975552 }, SchonhageStrassen.CyclicShiftRight(arr, 8)))
                throw new Exception("SchönhageStrassen:TestCyclicShift test has failed!");
            if (!Compare.AreEqual(new int[] { 255, 50495615 }, SchonhageStrassen.CyclicShiftRight(arr, 16)))
                throw new Exception("SchönhageStrassen:TestCyclicShift test has failed!");
            if (!Compare.AreEqual(new int[] { 2130706432, -16579968 }, SchonhageStrassen.CyclicShiftRight(arr, 24)))
                throw new Exception("SchönhageStrassen:TestCyclicShift test has failed!");
            if (!Compare.AreEqual(new int[] { -2139160576, 16712450 }, SchonhageStrassen.CyclicShiftRight(arr, 32)))
                throw new Exception("SchönhageStrassen:TestCyclicShift test has failed!");
            if (!Compare.AreEqual(new int[] { 41975552, 65283 }, SchonhageStrassen.CyclicShiftRight(arr, 40)))
                throw new Exception("SchönhageStrassen:TestCyclicShift test has failed!");
            if (!Compare.AreEqual(arr, SchonhageStrassen.CyclicShiftRight(arr, 64)))
                throw new Exception("SchönhageStrassen:TestCyclicShift test has failed!");

            arr2 = SchonhageStrassen.CyclicShiftRight(arr, 17);
            arr2 = SchonhageStrassen.CyclicShiftRight(arr2, 12);
            arr2 = SchonhageStrassen.CyclicShiftRight(arr2, 1);
            arr2 = SchonhageStrassen.CyclicShiftRight(arr2, 1);
            arr2 = SchonhageStrassen.CyclicShiftRight(arr2, 24);
            arr2 = SchonhageStrassen.CyclicShiftRight(arr2, 9);
            if (!Compare.AreEqual(arr, arr2))
                throw new Exception("SchönhageStrassen:TestCyclicShift test has failed!");

            // shift left, then right by the same amount
            arr2 = SchonhageStrassen.CyclicShiftLeftBits(arr, 22);
            arr2 = SchonhageStrassen.CyclicShiftRight(arr2, 22);
            if (!Compare.AreEqual(arr, arr2))
                throw new Exception("SchönhageStrassen:TestCyclicShift test has failed!");

            arr2 = SchonhageStrassen.CyclicShiftLeftBits(arr, 9);
            arr2 = SchonhageStrassen.CyclicShiftRight(arr2, 14);
            arr2 = SchonhageStrassen.CyclicShiftRight(arr2, 9);
            arr2 = SchonhageStrassen.CyclicShiftLeftBits(arr2, 14);
            if (!Compare.AreEqual(arr, arr2))
                throw new Exception("SchönhageStrassen:TestCyclicShift test has failed!");
        }

        private void TestSubModPow2()
        {
            int[] a = new int[] { 3844, 0, 0 };
            int[] b = new int[] { 627199739, 1091992276, 2332 };
            SchonhageStrassen.SubModPow2(a, b, 12);
            if (!Compare.AreEqual(new int[] { 9, 0, 0 }, a))
                throw new Exception("SchönhageStrassen:SubModPow2 test has failed!");
        }

        private void TestAddShifted()
        {
            int[] a = new int[] { 1522485231, 1933026569 };
            int[] b = new int[] { 233616584 };
            SchonhageStrassen.AddShifted(a, b, 1);
            if (!Compare.AreEqual(a, new int[] { 1522485231, -2128324143 }))
                throw new Exception("SchönhageStrassen:AddShifted test has failed!");

            a = new int[] { 796591014, -1050856894, 1260609160 };
            b = new int[] { 2093350350, -1822145887 };
            SchonhageStrassen.AddShifted(a, b, 1);
            if (!Compare.AreEqual(a, new int[] { 796591014, 1042493456, -561536726 }))
                throw new Exception("SchönhageStrassen:AddShifted test has failed!");

            a = new int[] { -1135845471, 1374513806, 391471507 };
            b = new int[] { 980775637, 1136222341 };
            SchonhageStrassen.AddShifted(a, b, 1);
            if (!Compare.AreEqual(a, new int[] { -1135845471, -1939677853, 1527693848 }))
                throw new Exception("SchönhageStrassen:AddShifted test has failed!");
        }

        private void TestAppendBits()
        {
            int[] a = new int[] { 3615777, 0 };
            SchonhageStrassen.AppendBits(a, 22, new int[] { -77, 61797 }, 1, 13);
            if (!Compare.AreEqual(new int[] { 1500982305, 4 }, a))
                throw new Exception("SchönhageStrassen:AppendBits test has failed!");
        }

        private void TestToBigInteger()
        {
            Random rng = new Random();
            byte[] a = new byte[1 + rng.Next(100)];
            rng.NextBytes(a);
            int[] b = SchonhageStrassen.ToIntArray(new BigInteger(1, a));
            BigInteger c = SchonhageStrassen.ToBigInteger(b);
            if (!Compare.Equals(new BigInteger(1, a), c))
                throw new Exception("SchönhageStrassen:ToBigInteger test has failed!");
        }

        private void TestMult(BigInteger a, BigInteger b)
        {
            Compare.Equals(a.Multiply(b), SchonhageStrassen.Multiply(a, b));
        }

        private void TestMult(int[] a, int[] b)
        {
            int[] cSimple = SchonhageStrassen.MultSimple(a, b);
            int[] cKara = SchonhageStrassen.MultKaratsuba(a, b);
            int maxLength = Math.Max(cSimple.Length, cKara.Length);
            if (!Compare.AreEqual(cSimple.CopyOf(maxLength), cKara.CopyOf(maxLength)))
                throw new Exception("SchönhageStrassen:Multiply test has failed!");
        }

        //verifies idft(dft(a)) = a 
        private void TestInversion()
        {
            Random rng = new Random();

            int m = 7 + rng.Next(10);
            int n = m / 2 + 1;
            int numElements = m % 2 == 0 ? 1 << n : 1 << (n + 1);
            numElements /= 2;

            int[][] a = ArrayUtils.CreateJagged<int[][]>(numElements, 1 << (n + 1 - 5));
            for (int i = 0; i < a.Length; i++)
            {
                for (int j = 0; j < a[i].Length; j++)
                    a[i][j] = rng.Next();
            }
            SchonhageStrassen.ModFn(a);

            int[][] aOrig = new int[a.Length][];
            for (int i = 0; i < a.Length; i++)
                aOrig[i] = (int[])a[i].Clone();
            SchonhageStrassen.Dft(a, m, n);
            SchonhageStrassen.Idft(a, m, n);
            SchonhageStrassen.ModFn(a);
            for (int j = 0; j < aOrig.Length; j++)
            {
                if (!Compare.AreEqual(aOrig[j], a[j]))
                    throw new Exception("SchönhageStrassen:Inversion test has failed!");
            }
        }
        #endregion
    }
}