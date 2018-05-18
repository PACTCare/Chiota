#region Directives
using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;
#endregion

namespace VTDev.Libraries.CEXEngine.Utility
{
    /// <summary>
    /// A utility class for parallel processing
    /// <para>Portions based on: http://blogs.msdn.com/b/pfxteam/archive/2009/08/12/9867246.aspx</para>
    /// </summary>
    public class ParallelUtils
    {
        #region Fields
        private static bool m_frcLinear = false;
        #endregion

        #region Properties
        /// <summary>
        /// Get/Set: Force uni-processing (IsParallel returns false)
        /// </summary>
        public static bool ForceLinear
        {
            get { return m_frcLinear; }
            set { m_frcLinear = value; }
        }

        /// <summary>
        /// Get: Returns true for multi processor system
        /// </summary>
        public static bool IsParallel
        {
            get { return Environment.ProcessorCount > 1 && m_frcLinear == false; }
        }

        /// <summary>
        /// Get: The system processor count
        /// </summary>
        public static int ProcessorCount
        {
            get { return Environment.ProcessorCount; }
        }
        #endregion

        #region internal Methods
        /// <summary>
        /// An infinite parallel loop function
        /// </summary>
        /// 
        /// <param name="Options">The parallel options</param>
        /// <param name="Condition">The while conditional</param>
        /// <param name="Body">The functions body</param>
        internal static void Loop(ParallelOptions Options, Func<bool> Condition, Action<ParallelLoopState> Body)
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
        internal static void While(ParallelOptions Options, Func<bool> Condition, Action<ParallelLoopState> Body)
        {
            Parallel.ForEach(Until(Condition), Options, (ignored, loopState) => Body(loopState));
        }

        /// <summary>
        /// A parallel While function
        /// </summary>
        /// 
        /// <param name="Condition">The while conditional</param>
        /// <param name="Body">The functions body</param>
        internal static void While(Func<bool> Condition, Action Body)
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
            public override IList<IEnumerator<bool>> GetPartitions(int PartitionCount)
            {
                if (PartitionCount < 1)
                    throw new ArgumentOutOfRangeException("Partition Count is invalid!");

                return (from i in Enumerable.Range(0, PartitionCount)
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

        /// <summary>
        /// Async reset class
        /// </summary>
        public class AsyncManualResetEvent
        {
            private volatile TaskCompletionSource<bool> _taskComplete = new TaskCompletionSource<bool>();

            /// <summary>
            /// Complete wait
            /// </summary>
            /// 
            /// <returns>The Task</returns>
            public Task WaitAsync() 
            { 
                return _taskComplete.Task; 
            }

            /// <summary>
            /// Set the Task
            /// </summary>
            public void Set()
            {
                var tcs = _taskComplete;
                Task.Factory.StartNew(s => ((TaskCompletionSource<bool>)s).TrySetResult(true), tcs, CancellationToken.None, TaskCreationOptions.PreferFairness, TaskScheduler.Default);
                tcs.Task.Wait();
            }

            /// <summary>
            /// Reset the task
            /// </summary>
            public void Reset()
            {
                while (true)
                {
                    var tcs = _taskComplete;
                    if (!tcs.Task.IsCompleted || Interlocked.CompareExchange(ref _taskComplete, new TaskCompletionSource<bool>(), tcs) == tcs)
                        return;
                }
            }
        }
    }
}
