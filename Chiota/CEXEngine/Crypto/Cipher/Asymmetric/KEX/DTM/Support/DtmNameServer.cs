#region Directives
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure;
using VTDev.Libraries.CEXEngine.Networking;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Support
{
    /// <summary>
    /// The DTM Name Server (TODO)
    /// </summary>
    public class DtmNameServer
    {
        #region Constructor
        /// <summary>
        /// 
        /// </summary>
        /// <param name="Client"></param>
        public DtmNameServer(TcpSocket Client)
        {

        }

        /// <summary>
        /// 
        /// </summary>
        ~DtmNameServer()
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
        public byte[] ListResponse(DtmClientStruct[] ClientList)
        {
            return null;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="Term"></param>
        /// <param name="ClientList"></param>
        /// <returns></returns>
        public byte[] QueryResponse(byte[] Term, DtmClientStruct[] ClientList)
        {
            return null;
        }

        /// <summary>
        /// 
        /// </summary>
        public void Listen()
        {

        }

        /// <summary>
        /// 
        /// </summary>
        public void Stop()
        {

        }
        #endregion
    }
}
