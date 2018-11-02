using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Android.App;
using Android.Content;
using Android.OS;
using Chiota.Droid.Services.BackgroundService;
using Chiota.Services.BackgroundServices.Base;
using Xamarin.Forms;
using TimeTrigger = Chiota.Services.BackgroundServices.Trigger.TimeTrigger;

[assembly: Dependency(typeof(BackgroundWorker))]
namespace Chiota.Droid.Services.BackgroundService
{
    [Service]
    public class BackgroundWorker : Service, IBackgroundWorker
    {
        #region Attributes

        private BaseBackgroundService _backgroundService;

        #endregion

        #region Methods

        #region Start

        //Start a background service with the background worker.
        public void Start<T>(params object[] objects) where T : BaseBackgroundService
        {
            //Create an instance of the background service.
            _backgroundService = (T)Activator.CreateInstance(typeof(T));

            //Init the background service.
            _backgroundService.Init(objects);
            _backgroundService.PostInit();
        }

        #endregion

        #endregion

        public override IBinder OnBind(Intent intent)
        {
            throw new NotImplementedException();
        }
    }
}
