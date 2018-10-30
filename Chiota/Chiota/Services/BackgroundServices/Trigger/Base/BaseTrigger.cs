using System;
using System.Collections.Generic;
using System.Text;

namespace Chiota.Services.BackgroundServices.Trigger.Base
{
    public abstract class BaseTrigger
    {
        #region Properties

        public TriggerType Type { get; }

        #endregion

        #region Constructors

        protected BaseTrigger(TriggerType type)
        {
            Type = type;
        }

        #endregion
    }
}
