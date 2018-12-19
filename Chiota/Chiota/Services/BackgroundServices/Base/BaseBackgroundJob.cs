#region References

using System.Threading.Tasks;
using Chiota.Services.Database;

#endregion

namespace Chiota.Services.BackgroundServices.Base
{
    public abstract class BaseBackgroundJob
    {
        #region Properties

        public bool IsRunning { get; set; }

        public bool IsDisposed { get; private set; }

        #endregion

        #region Constructors

        protected BaseBackgroundJob()
        {
            IsRunning = false;
            IsDisposed = false;
        }

        #endregion

        #region Methods

        #region Init

        /// <summary>
        /// Do some initialization for the background job.
        /// </summary>
        public virtual void Init(params object[] data)
        {
        }

        #endregion

        #region Dispose

        /// <summary>
        /// Do some clean up for the background job.
        /// </summary>
        public virtual void Dispose()
        {
            IsDisposed = true;
        }

        #endregion

        #region Run

        /// <summary>
        /// Run the background job.
        /// </summary>
        public abstract Task<bool> RunAsync();

        #endregion

        #endregion
    }
}
