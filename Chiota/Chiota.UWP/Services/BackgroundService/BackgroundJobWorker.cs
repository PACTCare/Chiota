#region References

using Chiota.UWP.Services.BackgroundService;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Chiota.Services.BackgroundServices.Base;
using Chiota.Services.Database;
using Chiota.Services.UserServices;
using Chiota.UWP.Services.Database;
using Newtonsoft.Json;
using Windows.ApplicationModel.Background;
using Xamarin.Forms;

#endregion

[assembly: Dependency(typeof(BackgroundJobWorker))]
namespace Chiota.UWP.Services.BackgroundService
{
    public class BackgroundJobWorker : IBackgroundJobWorker
    {
        private static List<BaseBackgroundJob> _backgroundJobs;

        /// <summary>
        /// Add a new background job.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="data"></param>
        public void Add<T>(params object[] data)
          where T : BaseBackgroundJob
        {
            // Create an instance of the background job.
            var backgroundJob = (T)Activator.CreateInstance(
              typeof(T),
              _backgroundJobs.Count(),
              new DatabaseService(new Sqlite(), UserService.CurrentUser.EncryptionKey),
              new Notification());
            backgroundJob.Init(JsonConvert.SerializeObject(data));

            _backgroundJobs.Add(backgroundJob);
        }

        /// <summary>
        /// Remove a background job by his id.
        /// </summary>
        public void Clear()
        {
            _backgroundJobs.Clear();
        }

        /// <summary>
        /// Dispose the background service.
        /// </summary>
        public void Dispose()
        {
            foreach (var task in BackgroundTaskRegistration.AllTasks)
                task.Value.Unregister(true);
        }

        /// <summary>
        /// Init the background service.
        /// </summary>
        public void Init(params object[] data)
        {
            _backgroundJobs = new List<BaseBackgroundJob>();
        }

        /// <summary>
        /// Register the background task of the app.
        /// </summary>
        /// <returns></returns>
        public void Register()
        {
            // First cancel all running jobs.
            this.Dispose();

            var service = new BackgroundService(_backgroundJobs);
            Task.Run(async () => { await service.RegisterAsync(); });
        }
    }
}