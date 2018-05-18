#region Directives
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure;
using VTDev.Libraries.CEXEngine.Networking;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Support
{
    /// <summary>
    /// The DTM Client container (TODO)
    /// </summary>
    public class DtmNameClient
    {
        #region Constructor
        /// <summary>
        /// 
        /// </summary>
        /// <param name="Client"></param>
        public DtmNameClient(TcpSocket Client)
        {

        }
        
        /// <summary>
        /// Finalizer
        /// </summary>
        ~DtmNameClient()
        {

        }
        #endregion

        #region Public Methods
        /// <summary>
        /// 
        /// </summary>
        /// <param name="Challenge"></param>
        /// <param name="PassPhrase"></param>
        /// <returns></returns>
        public bool Authenticate(byte[] Challenge, byte[] PassPhrase)
        {
            return false;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="ClientList"></param>
        /// <returns></returns>
        public byte[] ListRequest(DtmClientStruct[] ClientList)
        {
            return null;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="Term"></param>
        /// <param name="ClientList"></param>
        /// <returns></returns>
        public byte[] QueryRequest(byte[] Term, DtmClientStruct[] ClientList)
        {
            return null;
        }

        /// <summary>
        /// 
        /// </summary>
        public void Connect()
        {

        }

        /// <summary>
        /// 
        /// </summary>
        public void Disconnect()
        {

        }
        #endregion
    }
}
