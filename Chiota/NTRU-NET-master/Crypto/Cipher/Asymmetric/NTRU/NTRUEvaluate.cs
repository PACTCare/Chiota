using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.NTRU.Crypto.Cipher.Asymmetric.NTRU
{
    // BKZ simulator.
    // usage: simulate( dimension, blocksize, target hermite factor )
    //  simulates BKZ-blocksize on a unit volume lattice to which BKZ-20
    //  has been applied as preprocessing.
    // returns ["success"/"failure", achieved hermite factor, # of rounds required ]

    /*gs(M) = {
      my(M2);
      M2 = matconcat([M[,1], M[,2] - proj(M[,1], M[,2])]);
      for(j=3, #M, M2 = matconcat([M2, M[,j] - vecsum(vector(j-1, i, proj(M2[,i], M[,j])))]));
      M2;
    }

    randhkz(d) = { // Requires bash, fplll, fp2gp script
      my(B,Bgs,Bgn,vs);
      system(Strprintf("/bin/bash -c \"latticegen -randseed $(dd status=none count=1 bs=4 if=/dev/urandom | hexdump -e '\"%i\"') u %d 16 | fplll -a bkz -b %d | fp2gp > randhkz\"", d,d));
      B = read("./randhkz");
      Bgs = gs(B~);
      Bgn = vector(#Bgs, i, log(sqrt(norml2(Bgs[,i]))));
      vs = vecsum(Bgn)/#Bgs;
      Bgn = vector(#Bgs, i, Bgn[i] - vs);
    }

    public double[] simdata(int really=0) 
    {
      my(V, count, d);
      d = 50; // Dimension of lattices to HKZ reduce
      count = 100; // Number of HKZ reduced GS norms to average over
      V = vector(d);
      if(really,
        printf("This will take a while\n");
        for(i=1,count,V+=randhkz(d))
        {
            V/count,
            // average log(gram schmidt norm) over 100 HKZ reduced bases of dim 50 lattices
            [0.4809337322749968, 0.4889068929146757, 0.4629910732303647, 0.4384921120061095, 0.4198271756529734,
            0.3940124751357192, 0.3793579556691379, 0.3552017168415738, 0.3375032857978846, 0.3229996676156046,
            0.3103169826524305, 0.2978627511364960, 0.2828082600293407, 0.2685092222965025, 0.2470246073218571,
            0.2345601366183950, 0.2236298423327614, 0.2026125221670087, 0.1833511717333619, 0.1635239915325074,
            0.1460909610754462, 0.1239402813211751, 0.1033442833745716, 0.08072183355489210, 0.05747352858422083,
            0.03615285314640355, 0.009734731674006085, -0.01314276679308946, -0.03859536413875225, -0.06166664730992491,
            -0.08732858253410711, -0.1159733213895935, -0.1395873057069733, -0.1685959449423031, -0.2009987452911466,
            -0.2272943479144534, -0.2548892487960738, -0.2845907037340676, -0.3130406180111631, -0.3439519155213564,
            -0.3729166620199606, -0.4037203497626708, -0.4279121623225402, -0.4591242077605871, -0.4851668230787535,
            -0.5069333755274962, -0.5312523582495852, -0.5480002333962808, -0.5470408985906416, -0.5201614648988958]);
        }
    }


    simulate(int N, int beta, int target, int abort=50)
    {
      if(beta < 50, return(0));
      r = simdata(0);
      c = vector(beta);
      for(d=51, #c, c[d] = (1/d)*lngamma(d/2 + 1) - 1/2*log(Pi));

      // Start with BKZ-20 preprocessing.
      ll  = vector(N, i, (N-2*(i-1))*log(1.01263));
      vs = vecsum(ll)/N;
      for(i=1,N,ll[i] -= vs);
      llp = vector(N);

      R = 0;
      while(exp(ll[1]/N) > target && R < abort,
        phi = 1;
        for(k=1, N-50,
          d = min(beta,N-k+1);
          f = min(k+beta, N);
          logV = sum(i=1,f,ll[i]) - sum(i=1,k-1,llp[i]);
          if(phi,
              if(logV/d + c[d] < ll[k],
                llp[k] = logV/d + c[d];
                phi = 0),
              llp[k] = logV/d + c[d]);
          );
        logV = vecsum(ll) - vecsum(llp[1..(N-50)]);
        for(k=1, 50, llp[N-50+k] = logV/50 + r[k]);
        ll = llp;
        R += 1;
        if(phi, return(["failure", exp(ll[1]/N), R])));
      if(R >= abort, return(["failure", exp(ll[1]/N), R]));
      ["success", exp(ll[1]/N), R];
    }*/

    /// <summary>
    /// https://github.com/NTRUOpenSourceProject/ntru-params/blob/master/ntru_params.gp
    /// </summary>
    public class NTRUEvaluate
    {
        //read("bkzsim.gp");
        //"binsearchLT(f, val, low, high): "\
        //"Binary search for largest x satisfying f(x) < val in range [low, high]");
        public double binsearchLT(int f, int val, double low, double high)
        {
            if(low >= high-1)
                return(low);

            double mp = Math.Ceiling((low+high)/2);
            if(mp <= val)
            {
                binsearchLT(f, val, mp, high);
                binsearchLT(f, val, low, mp);
            }
        }


        //"dmRejectProb(N, dm): "\
        //"Probability that the number of 1s, -1s, or 0s is less than dm in a uniform "\
        //"random trinary polynomial of degree <= N");
        public void dmRejectProb(int N, int dm) 
        {
            //my(a);
            int a = 0;
            for(int p1s=dm; p1s<N-2*dm; p1s++)
            {
                for(int m1s = dm; m1s < N-dm-p1s; m1s++)
                  a += binomial(N, p1s)*binomial(N-p1s,m1s);
            }
            Math.Log(1 - a/3^N, 2.0);
        }


        
        public void hybridMITM(int N, int K, int dg1, int dg2) 
        {
            int Nc, tot, H, awork, d1, d2, d1a, d2a;
            Nc = N-K;
            tot = (binomial(N,dg1)*binomial(N-dg1,dg2));
            H = vector(dg1+1, d1a, vector(dg2+1, d2a,
                       d1 = d1a - 1;
                       d2 = d2a - 1;
                       p = binomial(Nc, dg1-d1) * binomial(Nc - dg1 + d1, dg2-d2) / tot;
                       -(binomial(K, d1) * binomial(K-d1, d2)) * p * Math.Log(p, 2.0)));
            int awork = .5*(sum(i=0, dg1, sum(j=0, dg2, H[i+1][j+1])) - Math.Log(N, 2.0));
        }

        //"minHybridMITM(N, K, dm): Calculate cost of performing hybrid attack on"\
        //"a message with maximal information leakage via m(1), i.e. m(1) = N-3dm");
        public void minHybridMITM(int N, int K, int dm)
        {
            int est,tot,t;
            int c = N-3*dm;
            t = hybridMITM(N, K, dm, dm+c) + (int)(.5*Math.Log(N, 2.0)));
        }


        //"hybridHermiteRequirement(N,q,L,K): "\
        //"Root Hermite factor required to prepare an NTRU basis for hybrid
        //"meet-in-the-middle attack. [L, N-K] is column index range of block
        //"to be reduced. L should be taken equal to the security parameter;
        public int hybridHermiteRequirement(int N,int q,int L,int K)
        {
          int ld = (int)((N - L)*Math.Log(q, 2.0));
          ld /= (4*N^2 - 4*N*(K+L) + (K^2 + 2*K*L + L^2));
          ld -= 1/(2*N - (K+L));
          return ld^=2;
        }

        //"deltaStar(k): Conjectured root Hermite factor reachable by BKZ "\
        //"with 2^k operations.");
        public int deltaStar(int k) 
        {
          return (int)(1.91157e-8 * (k^2) - 2.32633e-5*k + 1.00972);
        }

        // decFailSig(pm,pg,d1,d2,d3): returns expected standard deviation of a coefficient of 3*(r*g + m*F) + m.")
        public double decFailSig(int pm, int pg, int d1,int d2,int d3) 
        {
          return 3 * Math.Sqrt((4*d1*d2 + 2*d3) * pm + (4*d1*d2 + 2*d3) * pg);
        }


        public int numProdForm(int N, int a, int b, int c)
        {
            int S = binomial(N,a)*binomial(N-a,a) * binomial(N,b)*binomial(N-b,b) * binomial(N,c)*binomial(N-c,c);
            return(S);
        }

        public int blockSize(int N, int q) 
        {
          int h = (int)Math.Sqrt(q)^(1/(2*N));
          binsearchLT((x)->(-(simulate(2*N, x, h)[2])), -h, 60, N);
        }

        public int bkzCost(int dim, int bs, int iter)
        {
          double logNodes;
          // Quad fit to published BKZ-2.0 paper table 3 row 1
          double logNodes1 = 0.00405892*(bs^2) - 0.337913*bs + 34.9018;
          // Quad fit to Full BKZ-2.0 paper table 4
          double logNodes2 = 0.000784314 * (bs^2) + 0.366078 * bs - 6.125;
          return (int)Math.Round(logNodes1 + Math.Log(dim*iter, 2.0) + 7) + round(logNodes2 + Math.Log(dim*iter. 2.0) + 7);
        }

        public int cn11est(int dim, int hreq) 
        {
          int bs, iter, cost;

          bs = binsearchLT((x)->(-simulate(dim, x, hreq)[2]), -hreq, 60, dim) + 1;
          iter = simulate(dim, bs, hreq)[3];
          cost = bkzCost(dim, bs, iter);
          [iter, bs, cost[1], cost[2]];
        }

        public int genParams(int N, int verbose=0)
        {
          int lambda, directMITM, dm, d1, d2, d3, dg, sig,
          q, q2, decFail, decFail2, Kh, Kc, Kb, LL, LM, high, low;

          /* Standard choices for dg, d1, d2, and d3 */
          dg = Math.Round(N/3);
          d1 = d2 = d3 = ceil(vecmax(real(polroots(2*x^2 + x - N/3))));
          d2 = ceil((N/3 - d1)/(2*d1));
          d3 = max(ceil((d1 + 1)/2), ceil(N/3 - 2*d1*d2));
          //while((2*d1*(d2-1) + d3) >= round(N/3), d2 -= 1);
          //while((2*d1*d2 + (d3-1)) >= round(N/3) && (d3-1) > (d1/2), d3 -= 1);

          /* Pick initial dm based on rejection probability below 2^-10 */
          dm = binsearchLT((x)->(dmRejectProb(N,x)), -10, 0, floor(N/3));
          mRej = dmRejectProb(N,dm);

          /* Use direct product-form MITM for upper bound on security */
          directMITM = floor(0.5 * log2(numProdForm(N,d1,d2,d3)/N));

          /* Choose q as smallest power of 2 admitting negligible
             decryption failure probability */
          sig = decFailSig((1-dm/N), (2*dg + 1)/N, d1, d2, d3);
          q = binsearchLT((x)->(-log2(N*erfc(x/(sig*sqrt(2))))), directMITM, 2^4, 2^16);
          q = 2^ceil(log2(2*q + 2));
          decFail = round(log2(N*erfc(((q-2)/2)/(sig*sqrt(2)))));

          /* Kh is smallest K that can be prepared via lattice reduction in O(2^\lambda) time. */
          [lambda1, K1] = optimalK(N,q,d1,d2,d3,dg,dm,3);
          [lambda2, K2] = optimalK(N,q,d1,d2,d3,dg,dm,4);

          /* Redo search for q with new security estimate */
          /* TODO: This favors estimate 1 */
          q2 = binsearchLT((x)->(-log2(N*erfc(x/(sig*sqrt(2))))), lambda1, 2^4, 2^16);
          q2 = 2^ceil(log2(2*q2 + 2));
          decFail2 = round(log2(N*erfc(((q2-2)/2)/(sig*sqrt(2)))));
          if(q2 != q, /* If we can lower q, rederive security */
            q = q2;
            decFail = decFail2;
            [lambda1, K1] = optimalK(N,q,d1,d2,d3,dg,dm,3);
            [lambda2, K2] = optimalK(N,q,d1,d2,d3,dg,dm,4));

          //Kh = binsearchLT((x)->(hybridHermiteRequirement(N,q,lambda,x)), deltaStar(lambda), 0, N);
          //LL = cn11est(2*N - lambda - Kh, hybridHermiteRequirement(N, q, lambda, Kh))[estimate];
          //Kh = binsearchLT((x)->(hybridHermiteRequirement(N,q,LL,x)), deltaStar(LL), 0, N);
          ///* Kc is largest K that can be searched in O(2^(\lambda)) time via meet-in-the-middle technique */
          //Kc = binsearchLT((x)->(hybridMITM(N, x, dg+1, dg)), lambda, 0, N) + 1;
          //if(Kc - Kh <= 20,
          //  Kc = binsearchLT((x)->(hybridMITM(N, x, dg+1, dg)), lambda/2, 0, N) + 1);
          //LM = floor(hybridMITM(N, Kc, dg+1, dg));

          ///* Search for a K between Kc and Kh that balances the two costs */
          //low = min(Kc, Kh);
          //high = max(Kc, Kh);
          //Kb = ceil((low + high)/2);
          //printf("%d %d | %d %d\n", Kc, LM, Kh, LL);
          //while(high-low > 1, /* Binary search for balanced costs */
          //  LL = cn11est(2*N - LL - Kb, hybridHermiteRequirement(N, q, LL, Kb))[estimate];
          //  LM = floor(hybridMITM(N, Kb, dg+1, dg));
          //  if(LL < LM, high = Kb, low = Kb);
          //  Kb = ceil((low + high)/2));

          /* Update security estimate. Either keep direct MITM cost or
           * choose larger of the two costs from hybrid attack (which should
           * be roughly equal anyway). */
          //lambda = min(lambda, max(LM,LL));

          if(verbose)
            checkParams(N, q, d1, d2, d3, dg, dm, lambda1, K1, lambda2, K2);

          //[N, q, d1, d2, d3, dg, dm, lambda1, K1, lambda2, K2, decFail, directMITM]
        }

        public int optimalK(int N,int q,int d1,int d2,int d3,int dg,int dm,int estimate=3) 
        {
          int lambda, Kb, Llr, Lmitm, high, low;
          lambda = floor(0.5 * log2(numProdForm(N,d1,d2,d3)/N));

          Kh = binsearchLT((x)->(hybridHermiteRequirement(N,q,lambda,x)), deltaStar(lambda), 0, N);
          Llr = cn11est(2*N - lambda - Kh, hybridHermiteRequirement(N, q, lambda, Kh))[estimate];
          Kh = binsearchLT((x)->(hybridHermiteRequirement(N,q,Llr,x)), deltaStar(Llr), 0, N);

          /* Kc is largest K that can be searched in O(2^(\lambda)) time via meet-in-the-middle technique */
          Kc = binsearchLT((x)->(hybridMITM(N, x, dg+1, dg)), lambda, 0, N) + 1;
          if(Kc - Kh <= 20, /* Arbitrarily decide if Kh is too large compared to Kc to contain optimal point */
            Kc = binsearchLT((x)->(hybridMITM(N, x, dg+1, dg)), lambda/2, 0, N) + 1);
          Lmitm = floor(hybridMITM(N, Kc, dg+1, dg));

          /* Search for a K between Kc and Kh that balances the two costs */
          low = min(Kc, Kh);
          high = max(Kc, Kh);
          Kb = ceil((low + high)/2);
          while(high-low > 1) /* Binary search for balanced costs */
          {
            Llr = cn11est(2*N - Llr - Kb, hybridHermiteRequirement(N, q, Llr, Kb))[estimate];
            Lmitm = floor(hybridMITM(N, Kb, dg+1, dg));
            if(Llr < Lmitm, high = Kb, low = Kb);
            Kb = ceil((low + high)/2));
          }
          Lmsg = floor(minHybridMITM(N, Kb, dm));

          /* Update security estimate. Either keep direct MITM cost or
           * choose smaller (message or key recovery) of the hybrid attack costs.  */
          lambda = min(lambda, max(min(Lmitm, Lmsg),Llr));

          [lambda, Kb];
        }



        // Extra parameters needed for reference implementation */
        //"probKUniq(N,K,M): Probability that a set of M integers uniformly " \
        //"distributed in [1,N] contains K unique values. Expressed as -log2(prob). "\
        //"Estimate from: Dupuis, Zhang, Whiting, \"Refined Large Deviation Asymptotics "\
        //"for the Classical Occupancy Problem.\" 2006");
        public int probKUniq(int N, int K, int M)
        {
          my(Z, T, R, S, RHS13, JT2);
          Z = 1.0*(K/N);
          T = 1.0*(M/N);

          /* Equation 3 of reference */
          R = solve(X=0.01,(1/Z)-(1e-9),-1/X*log(1-X*Z)-T);
          /* Equation 12 */
          S = sqrt(Z/(1-R*Z) - T);
          /* RHS of Equation 13 */
          RHS13 = (2*Pi*S^2)^(-1/2) * (R/(R-1)) * sqrt((1 - R*Z)/(1-Z));
          /* Equation 2 */
          JT2 = (T - Z)*log(R) + (1-Z)*log(1-Z) - (1-R*Z)/(R)*log(1-R*Z);
          /* Probability from equation 13 */
          -log2(RHS13 / (exp(N*JT2)*sqrt(N)));
        }


        //"logBinomialCDF(k,n,p): log2(Pr(X <= k)), X binomial with parameters n and p.")
        public int logBinomialCDF(int k, int n, int p) 
        {
          log2(sum(i=1,k,binomial(n,i)*(p)^i * (1-p)^(n-i)));
        }



        public void formatParams(genoutput)
        {
          my(lambda, c, cs, cm, lLen, secOct, mLen, hashLen, minSamp, minRand, err);
          [N, q, d1, d2, d3, dg, dm, lambda1, K1, lambda2, K2] = genoutput;
          c = ceil(log2(N));
          for(cs=c, 13; cs++)
              if(lift(Mod(2^cs, N))/N < lift(Mod(2^c, N))/N, c = cs));
          cm = 2^c - lift(Mod(2^c, N));

          /* Upper bound on security */
          lambda = round(0.5 * log2(numProdForm(N,d1,d2,d3)/N));

          secOct = floor(lambda/8);
          /* max message length (bytes) using 3 bit to 2 trit encoding
             assumes mLen will be < 256, assumes b is secOct bytes */
          mLen = floor(((N-1)/2)*3/8) - secOct;
          lLen = 1 + floor(log(mLen)/log(256));
          mLen -= lLen;

          hashLen = 20; if(secOct > 20, hashLen = 32);

          /* Calculate minIGFCalls */
          need = 2*(d1+d2+d3);
          minSamp = binsearchLT((x)->probKUniq(N, need, x), lambda, need+1, 10*need);
          err = 1.0 * cm/2^c;
          minRand = binsearchLT((s)->(-logBinomialCDF(minSamp, s, err)), lambda, minSamp, floor(N*log(N)));
          minCalls = ceil(ceil(minRand*c/8)/hashLen);

          /* minMGF calls assuming 5 trits are extracted from 1 byte with probability 243/256 */
          n5 = ceil(N/5);
          minMGF = binsearchLT((x)->(-logBinomialCDF(n5, x, 243/256)), lambda, n5, 2*n5);
          minMGF = ceil(minMGF/hashLen);

        printf( \
        "    {\n"
        "        NTRU_EES%dEPX,\t\t\t/* parameter-set id */\n" \
        "        \"ees%depX\",\t\t\t/* human readable param set name */\n" \
        "        {0xFF, 0xFF, 0xFF},\t\t/* OID */\n" \
        "        0xFF,\t\t\t\t/* DER id */\n" \
        "        %d,\t\t\t\t/* no. of bits in N (i.e., in an index) */\n" \
        "        %d,\t\t\t\t/* N */\n" \
        "        %d,\t\t\t\t/* security strength in octets */\n" \
        "        %d,\t\t\t\t/* q */\n" \
        "        %d,\t\t\t\t/* no. of bits in q (i.e., in a coeff) */\n" \
        "        TRUE,\t\t\t\t/* product form */\n" \
        "        %d + (%d << 8) + (%d << 16),\t/* df, dr */\n" \
        "        %d,\t\t\t\t/* dg */\n" \
        "        %d,\t\t\t\t/* maxMsgLenBytes */\n" \
        "        %d,\t\t\t\t/* dm0 */\n" \
        "        %d,\t\t\t\t/* 2^c - (2^c mod N) */\n" \
        "        %d,\t\t\t\t/* c */\n" \
        "        1,\t\t\t\t/* lLen */\n" \
        "        %d,\t\t\t\t/* min. no. of hash calls for IGF-2 */\n" \
        "        %d,\t\t\t\t/* min. no. of hash calls for MGF-TP-1 */\n" \
        "    },\n", N,N,ceil(log2(N)), N, secOct, q, ceil(log2(q)), \
        d1, d2, d3, dg, mLen, dm, cm, c, minCalls, minMGF);
        }

        checkParams(genoutput, estimate=3) = {
          my(goodNQ, hB, L, K, bCombSec, bMSec, sig, decFail, mRej);
          [N, q, d1, d2, d3, dg, dm, lambda1, K1, lambda2, K2] = genoutput;

          goodNQ = if(isprime(N),
                      pAbove2 = (N-1)/znorder(Mod(2,N));
                      if(isprimepower(q) && Mod(q,2) == 0,
                      if(pAbove2 < 3, "Yes.",
                        Strprintf("No. %d primes above 2.", pAbove2)),
                        "No. q is not a power of 2."),
                        "No. Composite N.");

          /* Upper bound on security */
          directMITM = floor(0.5 * log2(numProdForm(N,d1,d2,d3)/N));

          if(estimate == 3,
            L = lambda1; K = K1,
            L = lambda2; K = K2);

          //directLR = cn11est(2*N, sqrt(q)^(1/(2*N)))[4];

          //hMITM = hybridHermiteRequirement(N,q,L,Kc);
          //hLR = hybridHermiteRequirement(N,q,L,Kh);
          hB = hybridHermiteRequirement(N,q,L,K);

          //curCombSec = hybridMITM(N, Kh, dg+1, dg);
          //bestCombSec = hybridMITM(N, Kc, dg+1, dg);

          //curMSec = minHybridMITM(N, Kh, dm);
          //bestMSec = minHybridMITM(N, Kc, dm);

          bCombSec = hybridMITM(N, K, dg+1, dg);
          bMSec = minHybridMITM(N, K, dm);

          //preMITM = cn11est(2*N - L - Kc, hMITM);
          //preLR = cn11est(2*N - L - Kh, hLR);
          preB = cn11est(2*N - L - K, hB);

          sig = decFailSig((1-dm/N), 2/3, d1, d2, d3);
          decFail = round(log2(N*erfc(((q-2)/2)/(sig*sqrt(2)))));
          mRej = dmRejectProb(N,dm);

          printf("[N, q, d1, d2, d3, dg, dm] = %s\n", [N,q,d1,d2,d3,dg,dm]);
          printf("Safe N and q? %s\n", goodNQ);
          printf("Decryption failure prob. = %.1f\n", decFail);
          printf("Message rejection prob. = %.1f\n\n", mRej);
          printf("Security Estimates\n\n");

          printf("Direct MITM search cost = %d\n", directMITM);
          //printf("Direct lattice reduction cost = %d to reach %.4f\n", directLR, sqrt(q)^(1/(2*N)));
          //printf("MITM K = %d : requires root Hermite factor = %.4f\n", Kc, hMITM);
          //printf("\tCN11 estimates %d rounds of BKZ-%d. Total cost = %d or %d\n", preMITM[1], preMITM[2], preMITM[3], preMITM[4]);
          //printf("\tHybrid MITM cost = %d\n\tHybrid MITM cost [msg with max m(1)] = %d\n\n", bestCombSec, bestMSec);

          printf("Hybrid attack\n\tSearch K = %d coordinates\n\tMust reach root Hermite factor = %.4f\n", K, hB);
          printf("\tCN11 estimates %d rounds of BKZ-%d. Total cost = %d or %d\n", preB[1], preB[2], preB[3], preB[4]);
          printf("\tHybrid MITM cost = %d\n\tHybrid MITM cost [msg with max m(1)] = %d\n\n", bCombSec, bMSec);

          //printf("LR K = %d : requires root Hermite factor = %.4f\n", Kh, hLR);
          //printf("\tCN11 estimates %d rounds of BKZ-%d. Total cost = %d or %d\n", preLR[1], preLR[2], preLR[3], preLR[4]);
          //printf("\tHybrid MITM cost = %d\n\tHybrid MITM cost [msg with max m(1)] = %d\n\n", curCombSec, curMSec);
        }

        P = [107, 113, 131, 139, 149, 163, 173, 181, 191, 199, 211, 227, 239, 251, 263, 271, 281, 293, 307, 317, 331, 347, 359, 367, 379, 389, 401, 439, 593, 743]



    }
}
