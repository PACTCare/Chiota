using System;

namespace Test
{
    public class TestEventArgs : EventArgs
    {
        public TestEventArgs(string Message)
        {
            this.Message = Message;
        }

        public string Message { get; set; }
        public int TestCount { get; set; }
    }
}
