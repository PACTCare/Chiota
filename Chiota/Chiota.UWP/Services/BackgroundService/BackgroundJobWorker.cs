using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel.Background;
using Chiota.Base;
using Chiota.Models.Database;
using Chiota.Services.BackgroundServices;
using Chiota.Services.BackgroundServices.Base;
using Chiota.Services.Database;
using Chiota.Services.UserServices;
using Chiota.UWP.Services.BackgroundService;
using Chiota.UWP.Services.Database;
using Newtonsoft.Json;
using Xamarin.Forms;

[assembly: Dependency(typeof(BackgroundJobWorker))]
namespace Chiota.UWP.Services.BackgroundService
{
    public class BackgroundJobWorker : IBackgroundJobWorker
    {
        #region Attributes

        private static List<BaseBackgroundJob> _backgroundJobs;

        #endregion

        #region Methods

        #region Init

        /// <summary>
        /// Init the background service.
        /// </summary>
        public void Init(params object[] data)
        {
            _backgroundJobs = new List<BaseBackgroundJob>();
        }

        #endregion

        #region Dispose

        /// <summary>
        /// Dispose the background service.
        /// </summary>
        public void Dispose()
        {
            foreach (var task in BackgroundTaskRegistration.AllTasks)
                    task.Value.Unregister(true);
        }

        #endregion

        #region Add

        /// <summary>
        /// Add a new background job.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="data"></param>
        public void Add<T>(params object[] data) where T : BaseBackgroundJob
        {
            //Create an instance of the background job.
            var backgroundJob = (T)Activator.CreateInstance(typeof(T), _backgroundJobs.Count(), new DatabaseService(new Sqlite(), UserService.CurrentUser.EncryptionKey), new Notification());
            backgroundJob.Init(JsonConvert.SerializeObject(data));

            _backgroundJobs.Add(backgroundJob);
        }

        #endregion

        #region Clear

        /// <summary>
        /// Remove a background job by his id.
        /// </summary>
        public void Clear()
        {
            _backgroundJobs.Clear();
        }

        #endregion

        #region Register

        /// <summary>
        /// Register the background task of the app.
        /// </summary>
        /// <returns></returns>
        public void Register()
        {
            //First cancel all running jobs.
            Dispose();

            var service = new BackgroundService(_backgroundJobs);
            Task.Run(async () => { await service.RegisterAsync(); });
        }

        #endregion

        #endregion
    }
}
