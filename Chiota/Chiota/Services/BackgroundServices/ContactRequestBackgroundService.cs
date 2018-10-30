using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Services.BackgroundServices.Base;
using Chiota.Services.BackgroundServices.Trigger;

namespace Chiota.Services.BackgroundServices
{
    public class ContactRequestBackgroundService : BaseBackgroundService
    {
        #region Attributes

        private const bool Repeatable = true;

        #endregion

        #region Constructors

        public ContactRequestBackgroundService() : base(Repeatable)
        {
            Triggers.Add(new TimeTrigger(TimeSpan.FromMinutes(5)));
            Conditions.Add(ConditionType.InternetAvailable);
        }

        #endregion

        #region Methods

        #region Run

        public override void Run()
        {
        }

        #endregion

        #endregion
    }
}
