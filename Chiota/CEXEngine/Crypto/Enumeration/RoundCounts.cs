namespace VTDev.Libraries.CEXEngine.Crypto.Enumeration
{
    /// <summary>
    /// Rounds Count. Can be cast as round count integers, 
    /// i.e. (int ct = RoundCounts.R12) is equal to 12.
    /// </summary>
    public enum RoundCounts : int
    {
        /// <summary>
        /// 8 Rounds: ChaCha
        /// </summary>
        R8 = 8,
        /// <summary>
        /// 10 Rounds: ChaCha, RHX
        /// </summary>
        R10 = 10,
        /// <summary>
        /// 12 Rounds: ChaCha, RHX
        /// </summary>
        R12 = 12,
        /// <summary>
        /// 14 Rounds: ChaCha, RHX
        /// </summary>
        R14 = 14,
        /// <summary>
        /// 16 Rounds: ChaCha, THX
        /// </summary>
        R16 = 16,
        /// <summary>
        /// 18 Rounds: ChaCha, THX
        /// </summary>
        R18 = 18,
        /// <summary>
        /// 20 Rounds: ChaCha, THX
        /// </summary>
        R20 = 20,
        /// <summary>
        /// 22 Rounds: ChaCha, RHX, THX
        /// </summary>
        R22 = 22,
        /// <summary>
        /// 24 Rounds: ChaCha, THX
        /// </summary>
        R24 = 24,
        /// <summary>
        /// 26 Rounds: ChaCha, THX
        /// </summary>
        R26 = 26,
        /// <summary>
        /// 28 Rounds: ChaCha, THX
        /// </summary>
        R28 = 28,
        /// <summary>
        /// 30 Rounds: ChaCha, THX
        /// </summary>
        R30 = 30,
        /// <summary>
        /// 32 Rounds: SHX, THX
        /// </summary>
        R32 = 32,
        /// <summary>
        /// 34 Rounds
        /// </summary>
        R34 = 34,
        /// <summary>
        /// 38 Rounds, RHX
        /// </summary>
        R38 = 38,
        /// <summary>
        /// 40 Rounds: SHX
        /// </summary>
        R40 = 40,
        /// <summary>
        /// 48 Rounds: SHX
        /// </summary>
        R48 = 48,
        /// <summary>
        /// 56 Rounds: SHX
        /// </summary>
        R56 = 56,
        /// <summary>
        /// 64 Rounds: SHX
        /// </summary>
        R64 = 64,
        /// <summary>
        /// 80 Rounds: SHX
        /// </summary>
        R80 = 80,
        /// <summary>
        /// 96 Rounds: SHX
        /// </summary>
        R96 = 96,
        /// <summary>
        /// 128 Rounds: SHX
        /// </summary>
        R128 = 128
    }
}
