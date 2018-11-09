using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Chiota.Services.BackgroundServices.Base
{
    public abstract class BaseBackgroundJob
    {
        #region Properties

        public string Id { get; }
        public bool IsRunning { get; set; }
        public bool IsDisposed { get; private set; }
        public bool IsRepeatable { get; }
        public TimeSpan RefreshTime { get; }

        #endregion

        #region Constructors

        private BaseBackgroundJob(bool isRepeatable)
        {
            IsRepeatable = isRepeatable;
            IsRunning = false;
            IsDisposed = !isRepeatable;
        }

        protected BaseBackgroundJob(string id) : this(false)
        {
            Id = id;
        }

        protected BaseBackgroundJob(string id, TimeSpan refreshTime) : this(true)
        {
            Id = id;
            RefreshTime = refreshTime;
        }

        #endregion

        #region Methods

        #region Init

        /// <summary>
        /// Do some initialization for the background job.
        /// </summary>
        public virtual void Init(string data = null)
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
