// start doxygen header //

/*! \mainpage A programmers guide to the CEX .NET Cryptographic library

\section intro_sec Welcome
Welcome to the CEX Cryptographic Library, version 1.5.5.0.
\brief 
CEX is a library built for both speed and maximum security. 
This help package contains details on the cryptographic primitives used in the library, their uses, and code examples.

\author    John Underhill
\version   1.5.5.0
\date      April 14, 2016
\copyright MIT public license

\section intro_link Links
Get the latest version from the CEX Home page: http://www.vtdev.com/cexhome.html

The CEX++ Help pages: http://www.vtdev.com/CEX-Plus/Help/html/index.html

CEX++ on Github: https://github.com/Steppenwolfe65/CEX

CEX .NET on Github: https://github.com/Steppenwolfe65/CEX-NET

The Code Project article on CEX .NET: http://www.codeproject.com/Articles/828477/Cipher-EX-V
*/

// end doxygen header //

// namespace documentation //

/*!
 *  \addtogroup VTDev
 *  @{
 */
//! Root Namespace
namespace VTDev { }
/*! @} */

/*!
 *  \addtogroup Libraries
 *  @{
 */
//! VTDev Library Namespace
namespace VTDev.Libraries { }
/*! @} */

/*!
 *  \addtogroup CEXEngine 
 *  @{
 */
//! CEX Library Root Namespace
namespace VTDev.Libraries.CEXEngine { }
/*! @} */

/*!
 *  \addtogroup Crypto
 *  @{
 */
//! CEX Root Cryptographic Namespace
namespace VTDev.Libraries.CEXEngine.Crypto { }
/*! @} */

/*!
 *  \addtogroup Cipher
 *  @{
 */
//! CEX Cryptographic Cipher Namespace
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher { }
/*! @} */

/*!
 *  \addtogroup Asymmetric
 *  @{
 */
//! CEX Cryptographic Asymmetric Cipher Namespace
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric { }
/*! @} */

/*!
 *  \addtogroup Common
 *  @{
 */
//! CEX Asymmetric Cipher Common Utilities
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Common { }
/*! @} */

/*!
 *  \addtogroup Encrypt
 *  @{
 */
//! CEX Asymmetric Encryption Cipher Namespace
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt { }
/*! @} */

/*!
 *  \addtogroup McEliece
 *  @{
 */
//! The McEliece Cipher
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.McEliece { }
/*! @} */

/*!
 *  \addtogroup NTRU
 *  @{
 */
//! The NTRU Cipher
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.NTRU { }
/*! @} */

/*!
 *  \addtogroup RLWE
 *  @{
 */
//! The Ring-LWE Cipher
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Encrypt.RLWE { }
/*! @} */

/*!
 *  \addtogroup Interfaces
 *  @{
 */
//! Common Asymmetric Cipher Interfaces
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces { }
/*! @} */

/*!
 *  \addtogroup KEX
 *  @{
 */
//! CEX Key Exchange Namespace
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX { }
/*! @} */

/*!
 *  \addtogroup DTM
 *  @{
 */
//! DTM Key Exchange Protocol
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.DTM { }
/*! @} */

/*!
 *  \addtogroup Argument
 *  @{
 */
//! DTM Key Exchange Arguments
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Argument { }
/*! @} */

/*!
 *  \addtogroup Flag
 *  @{
 */
//! DTM Key Exchange Flags
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Flag { }
/*! @} */

/*!
 *  \addtogroup Structure
 *  @{
 */
//! DTM Key Exchange Structures
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Structure { }
/*! @} */

/*!
 *  \addtogroup Support
 *  @{
 */
//! DTM Key Exchange Support classes
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.KEX.DTM.Support { }
/*! @} */

/*!
 *  \addtogroup Sign
 *  @{
 */
//! CEX Asymmetric Signing Namespace
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign { }
/*! @} */

/*!
 *  \addtogroup GMSS
 *  @{
 */
//! GMSS Asymmetric Signing
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.GMSS { }
/*! @} */

/*!
 *  \addtogroup RNBW
 *  @{
 */
//! Rainbow Asymmetric Signing
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW { }
/*! @} */

/*!
 *  \addtogroup Symmetric
 *  @{
 */
//! Symmetric Cipher Namespace
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric { }
/*! @} */

/*!
 *  \addtogroup Block
 *  @{
 */
//! Symmetric Block Ciphers
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block { }
/*! @} */

/*!
 *  \addtogroup Mode
 *  @{
 */
//! Symmetric Block Cipher Modes
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Mode { }
/*! @} */

/*!
 *  \addtogroup Padding
 *  @{
 */
//! Symmetric Block Cipher Padding
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding { }
/*! @} */

/*!
 *  \addtogroup Stream
 *  @{
 */
//! Symmetric Stream Ciphers
namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Stream { }
/*! @} */

/*!
 *  \addtogroup Common
 *  @{
 */
//! Common Cryptographic Classes
namespace VTDev.Libraries.CEXEngine.Crypto.Common { }
/*! @} */

/*!
 *  \addtogroup Digest
 *  @{
 */
//! Cryptographic Hash Classes
namespace VTDev.Libraries.CEXEngine.Crypto.Digest { }
/*! @} */

/*!
 *  \addtogroup Enumeration
 *  @{
 */
//! Cryptographic Enumerations
namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration { }
/*! @} */

/*!
 *  \addtogroup Generator
 *  @{
 */
//! Deterministic Random Byte Generators
namespace VTDev.Libraries.CEXEngine.Crypto.Generator { }
/*! @} */

/*!
 *  \addtogroup Helper
 *  @{
 */
//! Cryptographic Helper Classes
namespace VTDev.Libraries.CEXEngine.Crypto.Helper { }
/*! @} */

/*!
 *  \addtogroup Mac
 *  @{
 */
//! Message Authentication Code Generators
namespace VTDev.Libraries.CEXEngine.Crypto.Mac { }
/*! @} */

/*!
 *  \addtogroup Prng
 *  @{
 */
//! Pseudo Random Number Generators
namespace VTDev.Libraries.CEXEngine.Crypto.Prng { }
/*! @} */

/*!
 *  \addtogroup Processing
 *  @{
 */
//! Cryptographic Processing Namespace
namespace VTDev.Libraries.CEXEngine.Crypto.Processing { }
/*! @} */

/*!
 *  \addtogroup Factory
 *  @{
 */
//! Cryptographic Processing Factories
namespace VTDev.Libraries.CEXEngine.Crypto.Processing.Factory { }
/*! @} */

/*!
 *  \addtogroup Structure
 *  @{
 */
//! Cryptographic Processing Structures
namespace VTDev.Libraries.CEXEngine.Crypto.Processing.Structure { }
/*! @} */

/*!
 *  \addtogroup Seed
 *  @{
 */
//! Pseudo Random Seed Generators
namespace VTDev.Libraries.CEXEngine.Crypto.Seed { }
/*! @} */

/*!
 *  \addtogroup CryptoException
 *  @{
 */
//! Cryptographic Exceptions
namespace VTDev.Libraries.CEXEngine.CryptoException { }
/*! @} */

/*!
 *  \addtogroup Networking
 *  @{
 */
//! TCP/IP Implementation
namespace VTDev.Libraries.CEXEngine.Networking { }
/*! @} */

/*!
 *  \addtogroup Numeric
 *  @{
 */
//! Big Math Number Classes
namespace VTDev.Libraries.CEXEngine.Numeric { }
/*! @} */

/*!
 *  \addtogroup Queue
 *  @{
 */
//! Network Queuing Classes
namespace VTDev.Libraries.CEXEngine.Queue { }
/*! @} */

/*!
 *  \addtogroup Security
 *  @{
 */
//! Secure Tool Implementations
namespace VTDev.Libraries.CEXEngine.Security { }
/*! @} */

/*!
 *  \addtogroup Tools
 *  @{
 */
//! Library Tool Classes
namespace VTDev.Libraries.CEXEngine.Tools { }
/*! @} */

/*!
 *  \addtogroup Utility
 *  @{
 */
//! Library Utilities Classes
namespace VTDev.Libraries.CEXEngine.Utility { }
/*! @} */


