using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Android.App;
using Android.Content;
using Android.OS;
using Android.Runtime;
using Android.Views;
using Android.Widget;

namespace Chiota.Droid.Services.BackgroundService
{
    public class BackgroundServiceBinder : Binder
    {
        #region Properties

        public BackgroundService BackgroundService { get; }

        #endregion

        #region Constructors

        public BackgroundServiceBinder(BackgroundService backgroundService)
        {
            BackgroundService = backgroundService;
        }

        #endregion
    }
}