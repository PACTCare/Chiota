using System;
using System.Collections.Generic;
using System.Text;
using Chiota.Services.BackgroundServices.Trigger.Base;

namespace Chiota.Services.BackgroundServices.Trigger
{
    public class TimeTrigger : BaseTrigger
    {
        #region Properties

        public TimeSpan Time { get; }

        #endregion

        #region Constructors

        public TimeTrigger(TimeSpan time) : base(TriggerType.Time)
        {
            Time = time;
        }

        #endregion
    }
}
