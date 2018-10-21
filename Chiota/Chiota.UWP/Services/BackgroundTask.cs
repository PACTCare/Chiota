using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel.Background;
using Chiota.Services;
using Chiota.UWP.Services;
using Xamarin.Forms;

[assembly: Dependency(typeof(BackgroundService))]
namespace Chiota.UWP.Services
{
    public class BackgroundService : IBackgroundService
    {
        #region Attributes

        private const string Name = "BackgroundTask";

        #endregion

        #region Methods

        #region Start

        public void Start()
        {
            //Register the new task.
            if (IsRegistered())
                Unregister();

            Task.Run(async () => await Register());
        }

        #endregion

        #region Register

        /// <summary>
        /// Register the background task of the app.
        /// </summary>
        /// <returns></returns>
        private async Task Register()
        {
            //Update the access to the execution manager.
            BackgroundExecutionManager.RemoveAccess();
            var requestAccessStatus = await BackgroundExecutionManager.RequestAccessAsync();

            //Create new background task.
            var builder = new BackgroundTaskBuilder
            {
                Name = Name,
                TaskEntryPoint = "RuntimeComponent.UWP.BackgroundTask"
            };

            if (requestAccessStatus == BackgroundAccessStatus.AlwaysAllowed || requestAccessStatus == BackgroundAccessStatus.AllowedSubjectToSystemPolicy)
            {
                builder.SetTrigger(new TimeTrigger(1, false));

                //Register the new task.
                var task = builder.Register();
                task.Completed += TaskCompleted;
            }
        }

        #endregion

        #region Unregister

        /// <summary>
        /// Unregister the background task of the app.
        /// </summary>
        private void Unregister()
        {
            foreach (var task in BackgroundTaskRegistration.AllTasks)
                if (task.Value.Name == Name)
                    task.Value.Unregister(true);
        }

        #endregion

        #region IsRegistered

        private bool IsRegistered()
        {
            foreach (var task in BackgroundTaskRegistration.AllTasks)
                if (task.Value.Name == Name)
                    return true;

            return false;
        }

        #endregion

        #endregion

        #region Events

        #region TaskCompleted

        private void TaskCompleted(BackgroundTaskRegistration sender, BackgroundTaskCompletedEventArgs args)
        {
            var test = new Notification("Test", "Hi");
            test.Show();
            //var settings = Windows.Storage.ApplicationData.Current.LocalSettings;
            //var message = settings.Values[Name].ToString();

            // Run your background task code here
            //MessagingCenter.Send<object, string>(this, "UpdateLabel", message);
        }

        #endregion

        #endregion
    }
}
