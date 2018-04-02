using System;

namespace Test
{
    public interface ITest
    {
        /// <summary>
        /// Progress event handler
        /// </summary>
        event EventHandler<TestEventArgs> Progress;

        /// <summary>
        /// Get: The tests formal description
        /// </summary>
        string Description { get; }

        /// <summary>
        /// Run the test
        /// </summary>
        /// <returns>Test result message</returns>
        string Test();
    }
}
