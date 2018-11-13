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

[assembly: Dependency(typeof(BackgroundWorker))]
namespace Chiota.UWP.Services.BackgroundService
{
    public class BackgroundWorker : IBackgroundJobWorker
    {
        #region Methods

        #region Init

        /// <summary>
        /// Init the background service.
        /// </summary>
        public void Init(params object[] data)
        {
        }

        #endregion

        #region Disposed

        /// <summary>
        /// Dispose the background service.
        /// </summary>
        public void Dispose()
        {
            /*_isDisposed = true;

            //Unregister the background service.
            if (IsRegistered())
                Unregister();

            //Dispose all the jobs.
            foreach (var item in _backgroundJobs)
                item?.Dispose();

            _backgroundJobs?.Clear();*/
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
            var job = new DbBackgroundJob()
            {
                Name = typeof(T).Name,
                Status = BackgroundJobStatus.Created.ToString(),
                Assembly = typeof(T).Assembly.FullName,
                Type = typeof(T).Namespace + "." + typeof(T).Name
            };

            //Add the new background job.
            var added = AppBase.Database.BackgroundJob.AddObject(job);

            //Create an instance of the background job.
            var backgroundJob = (T)Activator.CreateInstance(typeof(T), added.Id, new DatabaseService(new Sqlite(), UserService.CurrentUser.EncryptionKey), new Notification());
            backgroundJob.Init(JsonConvert.SerializeObject(data));

            var service = new BackgroundService(backgroundJob);
            service.RegisterAsync().Wait();
        }

        #endregion

        #region Remove

        /// <summary>
        /// Remove a background job by his id.
        /// </summary>
        /// <param name="id"></param>
        public void Remove(int id)
        {
            /*var exist = _backgroundJobs.First(t => t.Id == jobId);
            if (exist != null)
            {
                exist.Dispose();
                _backgroundJobs.Remove(exist);
            }*/
        }

        #endregion

        #endregion
    }
}
