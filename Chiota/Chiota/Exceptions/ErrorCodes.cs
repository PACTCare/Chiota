using System;
using System.Collections.Generic;
using System.Text;

namespace Chiota.Exceptions
{
    public static class ErrorCodes
    {
        #region Base exceptions

        public const int Unknown = -10000;
        public const int InvalidUserInput = -10001;
        public const int MissingUserInput = -10002;

        #endregion

        #region Authentication exceptions

        public const int AuthFailedPasswordConfirmation = -20000;

        #endregion

        #region Back up exceptions

        public const int BackUpFailedSeedConfirmation = -30000;

        #endregion
    }
}
