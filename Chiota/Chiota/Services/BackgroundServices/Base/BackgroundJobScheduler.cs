#region References

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Chiota.Services.Database;

#endregion

namespace Chiota.Services.BackgroundServices.Base
{
    public class BackgroundJobScheduler
    {
        #region Attributes

        private Queue<BaseBackgroundJob> _backgroundJobs;

        #endregion

        #region Properties

        public bool IsRunning { get; set; }

        public bool IsDisposed { get; private set; }

        #endregion

        #region Constructors

        public BackgroundJobScheduler()
        {
            _backgroundJobs = new Queue<BaseBackgroundJob>();

            IsRunning = false;
            IsDisposed = false;
        }

        #endregion

        #region Methods

        #region Init

        /// <summary>
        /// Do some initialization for the background service.
        /// </summary>
        public void Init(string data = null)
        {
        }

        #endregion

        #region Dispose

        /// <summary>
        /// Do some clean up for the background service.
        /// </summary>
        public void Dispose()
        {
            IsRunning = false;
            IsDisposed = true;
        }

        #endregion

        #region Add

        /// <summary>
        /// Add a new background job to the scheduler.
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        public void Add(BackgroundJobSchedulerMessage message)
        {
            var jobType = Type.GetType(message.Type);
            if(jobType == null) return;

            var job = (BaseBackgroundJob) Activator.CreateInstance(jobType);
            job.Init(message.Data);

            _backgroundJobs.Enqueue(job);
        }

        #endregion

        #region Run

        public async Task RunAsync()
        {
            try
            {
                //Show that the background service is running.
                IsRunning = true;

                var job = _backgroundJobs.Dequeue();

                var result = false;

                try
                {
                    result = await job.RunAsync();
                }
                catch (Exception)
                {
                    //Ignore exceptions and go on.
                }

                //Add the background job to the end of the list.
                if (result)
                    _backgroundJobs.Enqueue(job);
            }
            catch (Exception)
            {
                //Ignore all exceptions, that are throwing and go one.
            }
        }

        #endregion

        #endregion
    }
}
