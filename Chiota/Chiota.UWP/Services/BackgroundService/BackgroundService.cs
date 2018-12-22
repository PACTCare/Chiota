#region References

using System;
using System.Threading.Tasks;
using Windows.ApplicationModel.Background;
using Chiota.Services.BackgroundServices.Base;

#endregion

namespace Chiota.UWP.Services.BackgroundService
{
    public class BackgroundService
    {
        #region Attributes

        private ApplicationTrigger _trigger;
        private BackgroundJobScheduler _backgroundJobWorker;

        #endregion

        #region Constructors

        public BackgroundService(BackgroundJobScheduler backgroundJobWorker)
        {
            _backgroundJobWorker = backgroundJobWorker;
        }

        #endregion

        #region Methods

        #region Register

        /// <summary>
        /// Register the background task of the app.
        /// </summary>
        /// <returns></returns>
        public async Task RegisterAsync()
        {
            //Update the access to the execution manager.
            BackgroundExecutionManager.RemoveAccess();
            var requestAccessStatus = await BackgroundExecutionManager.RequestAccessAsync();

            //Create new background task.
            var builder = new BackgroundTaskBuilder
            {
                Name = "ChiotaBackgroundService",
                TaskEntryPoint = "RuntimeComponent.UWP.BackgroundTask"
            };

            if (requestAccessStatus == BackgroundAccessStatus.AlwaysAllowed || requestAccessStatus == BackgroundAccessStatus.AllowedSubjectToSystemPolicy)
            {
                _trigger = new ApplicationTrigger();

                //Set the triggers.
                builder.SetTrigger(_trigger);
                builder.AddCondition(new SystemCondition(SystemConditionType.InternetAvailable));

                //Register the new task.
                var task = builder.Register();

                task.Completed += TaskCompleted;

                await _trigger.RequestAsync();
            }
        }

        #endregion

        #region TaskCompleted

        /// <summary>
        /// Runs after the service is completed.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        protected void TaskCompleted(BackgroundTaskRegistration sender, BackgroundTaskCompletedEventArgs args)
        {
            Task.Run(async () =>
            {
                await _backgroundJobWorker.RunAsync();

                if (_backgroundJobWorker.IsDisposed) return;

                //Repeat it.
                await _trigger.RequestAsync();
            }).Wait();
        }

        #endregion

        #endregion
    }
}
