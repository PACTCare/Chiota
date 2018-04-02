#region Directives
using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
#endregion

namespace VTDev.Libraries.CEXEngine.Utility
{
    /// <summary>
    /// This class is a utility class for parallel processing
    /// <para>http://blogs.msdn.com/b/pfxteam/archive/2009/08/12/9867246.aspx</para>
    /// </summary>
    public class ParallelUtils
    {
        #region Fields
        private static bool _frcLinear = false;
        #endregion

        #region Properties
        /// <summary>
        /// Get/Set: Force uni-processing (IsParallel returns false)
        /// </summary>
        public static bool ForceLinear
        {
            get { return _frcLinear; }
            set { _frcLinear = value; }
        }

        /// <summary>
        /// Get: Returns true for multi processor system
        /// </summary>
        public static bool IsParallel
        {
            get { return Environment.ProcessorCount > 1 && _frcLinear == false; }
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// An infinite parallel loop function
        /// </summary>
        /// 
        /// <param name="Options">The parallel options</param>
        /// <param name="Condition">The while conditional</param>
        /// <param name="Body">The functions body</param>
        public static void Loop(ParallelOptions Options, Func<bool> Condition, Action<ParallelLoopState> Body)
        {
            Parallel.ForEach(new InfinitePartitioner(), Options, (ignored, loopState) =>
            {
                if (Condition())
                    Body(loopState);
                else
                    loopState.Stop();
            });
        }

        /// <summary>
        /// A parallel While function
        /// </summary>
        /// 
        /// <param name="Options">The parallel options</param>
        /// <param name="Condition">The while conditional</param>
        /// <param name="Body">The functions body</param>
        public static void While(ParallelOptions Options, Func<bool> Condition, Action<ParallelLoopState> Body)
        {
            Parallel.ForEach(Until(Condition), Options, (ignored, loopState) => Body(loopState));
        }

        /// <summary>
        /// A parallel While function
        /// </summary>
        /// 
        /// <param name="Condition">The while conditional</param>
        /// <param name="Body">The functions body</param>
        public static void While(Func<bool> Condition, Action Body)
        {
            Parallel.ForEach(Until(Condition), dlg => Body());
        }

        #endregion

        #region Private Methods
        private static IEnumerable<bool> Infinite()
        {
            while (true) yield return true;
        }

        private static IEnumerable<bool> Until(Func<bool> Condition)
        {
            while (Condition()) yield return true;
        }
        #endregion

        #region While Partitioner
        internal class InfinitePartitioner : Partitioner<bool>
        {
            public override IList<IEnumerator<bool>> GetPartitions(int partitionCount)
            {
                if (partitionCount < 1)
                    throw new ArgumentOutOfRangeException("partitionCount");
                return (from i in Enumerable.Range(0, partitionCount)
                        select InfiniteEnumerator()).ToArray();
            }

            public override bool SupportsDynamicPartitions { get { return true; } }

            public override IEnumerable<bool> GetDynamicPartitions()
            {
                return new InfiniteEnumerators();
            }

            private static IEnumerator<bool> InfiniteEnumerator()
            {
                while (true) yield return true;
            }

            private class InfiniteEnumerators : IEnumerable<bool>
            {
                public IEnumerator<bool> GetEnumerator()
                {
                    return InfiniteEnumerator();
                }
                IEnumerator IEnumerable.GetEnumerator() { return GetEnumerator(); }
            }
        }
        #endregion
    }
}
