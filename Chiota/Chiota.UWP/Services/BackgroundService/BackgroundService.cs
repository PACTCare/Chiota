#region References

using System;
using System.Collections.Generic;
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

        #endregion

        #region Properties

        public List<BaseBackgroundJob> BackgroundJobs { get; }

        #endregion

        #region Constructors

        public BackgroundService(List<BaseBackgroundJob> backgroundJobs)
        {
            BackgroundJobs = backgroundJobs;
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
                foreach (var item in BackgroundJobs)
                {
                    var result = await item.RunAsync();

                    //Update database, because job is finished.
                    if (!result)
                    {
                        item.Dispose();
                        BackgroundJobs.Remove(item);
                        return;
                    }
                }

                if (BackgroundJobs.Count == 0) return;

                //Repeat it.
                await _trigger.RequestAsync();
            }).Wait();
        }

        #endregion

        #endregion
    }
}
