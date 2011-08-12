// This file is taken and modified from the public-domain poclbm project, and
// we have therefore decided to keep it public-domain in Phoenix.

// 2011-07-12: further modified by Diapolo and still public-domain
// -ck version to be compatible with cgminer
// 2011-07-14: shorter code

#if defined VECTORS4
	typedef uint4 u;
	__constant u offset = {0, 1, 2, 3};
#elif defined VECTORS2
	typedef uint2 u;
	__constant u offset = {0, 1};
#else
	typedef uint u;
#endif

__constant uint K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

__constant uint ConstW[96] = {
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000U, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000280U,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x80000000U, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000100U,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

__constant uint H[8] = { 
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0xfc08884d, 0xec9fcd13
};

// L = 0xa54ff53a + 0xb0edbdd0 + K[0] == 0x198c7e2a2
// uint 0x98c7e2a2 == ulong 0x198c7e2a2 because the long is too long for uint and rolls over
__constant uint L = 0x98c7e2a2;

#define O 15

#ifdef BITALIGN
	#pragma OPENCL EXTENSION cl_amd_media_ops : enable
	#define rot(x, y) amd_bitalign(x, x, (uint)(32 - y))
#else
	#define rot(x, y) rotate(x, (uint)y)
#endif

#ifdef BFI_INT
	#define Ch(x, y, z) amd_bytealign(x, y, z)
#else 
	#define Ch(x, y, z) bitselect(z, y, x)
#endif

// Ma now uses the Ch function, if BFI_INT is enabled, the optimized Ch version is used
#define Ma(x, y, z) Ch((z ^ x), y, x)

// Various intermediate calculations for each SHA round
#define s0(n) (rot(Vals[(128 - n) & 7], 30) ^ rot(Vals[(128 - n) & 7], 19) ^ rot(Vals[(128 - n) & 7], 10))
#define s1(n) (rot(Vals[(132 - n) & 7], 26) ^ rot(Vals[(132 - n) & 7], 21) ^ rot(Vals[(132 - n) & 7], 7))
#define ch(n) (Ch(Vals[(132 - n) & 7], Vals[(133 - n) & 7], Vals[(134 - n) & 7]))
#define ma(n) (Ma(Vals[(129 - n) & 7], Vals[(130 - n) & 7], Vals[(128 - n) & 7]))
#define t1(n) (K[n & 63] + Vals[(135 - n) & 7] + W[n - O] + s1(n) + ch(n))
#define t1_no_W(n) (K[n & 63] + Vals[(135 - n) & 7] + s1(n) + ch(n))

//Used for constant W Values (the compiler optimizes out zeros)
#define t1C(n) (K[(n) & 63] + Vals[(135 - (n)) & 7] + ConstW[(n)] + s1(n) + ch(n))

// intermediate W calculations
#define P1(x) ((W[x - 2 - O] >> 10U) ^ rot(W[x - 2 - O], 15) ^ rot(W[x - 2 - O], 13))
#define P2(x) ((W[x - 15 - O] >> 3U) ^ rot(W[x - 15 - O], 25) ^ rot(W[x - 15 - O], 14))
#define P3(x) W[x - 7 - O]
#define P4(x) W[x - 16 - O]

//Again the compiler is stupid and doesn't know how to rotate() constants
#define rotC(x,n) (x<<n | x >> (32-n))

//Partial Calcs for constant W values
#define P1C(n) ((rotC(ConstW[(n)-2],15)^rotC(ConstW[(n)-2],13)^((ConstW[(n)-2])>>10U)))
#define P2C(n) ((rotC(ConstW[(n)-15],25)^rotC(ConstW[(n)-15],14)^((ConstW[(n)-15])>>3U)))
#define P3C(x) ConstW[x-7]
#define P4C(x) ConstW[x-16]

// full W calculation
#define W(x) (W[x - O] = P4(x) + P3(x) + P2(x) + P1(x))

// SHA round with built in W calc
#define sharound(n) { Temp = t1(n); Vals[(135 - n) & 7] = Temp + s0(n) + ma(n); Vals[(131 - n) & 7] += Temp; }

// SHA round without W calc
#define sharound_no_W(n) { Vals[(131 - n) & 7] += t1_no_W(n); Vals[(135 - n) & 7] = t1_no_W(n) + s0(n) + ma(n); }

//SHA round for constant W values
#define sharoundC(n) { Temp = t1C(n); Vals[(131 - (n)) & 7] += Temp; Vals[(135 - (n)) & 7] = Temp + s0(n) + ma(n); }

__kernel
	__attribute__((reqd_work_group_size(WORKSIZE,1,1)))
	__attribute__((vec_type_hint(u)))
				void search(	const uint state0, const uint state1, const uint state2, const uint state3,
						const uint state4, const uint state5, const uint state6, const uint state7,
						const uint B1, const uint C1, const uint C1addK5, const uint D1,
						const uint F1, const uint G1, const uint H1,
						const uint base,
						const uint W2,
						const uint W16, const uint W17, const uint PreW19,
						const uint PreVal4, const uint PreVal0,
						__global uint * output)
{
	__local u W[124 - O];
	u Vals[8];
	__local u Temp;
	Vals[7] = D1 + H1;
#if defined VECTORS4
	const u W_3 = base + (uint)(get_local_id(0)<<2) + (uint)(get_group_id(0)) * (WORKSIZE<<2) + offset;
	const uint r = ((W_3.x)>>3U)^rot(W_3.x,25u)^rot(W_3.x,14u);
	W[18 - O] = W2 + (u){r, r ^ 0x2004000U, r ^ 0x4008000U, r ^ 0x600C000U};
#elif defined VECTORS2
	const u W_3 = base + (uint)(get_local_id(0)<<1) + (uint)(get_group_id(0)) * (WORKSIZE<<1) + offset;
	const uint r = ((W_3.x)>>3U)^rot(W_3.x,25u)^rot(W_3.x,14u);
	W[18 - O] = W2 + (u){r, r ^ 0x2004000U};
#else
	const u W_3 = base + get_local_id(0) + get_group_id(0) * (WORKSIZE);
	const uint r = ((W_3)>>3U)^rot(W_3,25u)^rot(W_3,14u);
	W[18 - O] = W2 + r;
#endif

	Vals[0] = W_3 + PreVal0;
	Vals[1] = B1;
	Vals[2] = C1;

	Vals[4] = W_3 + PreVal4;
	Vals[5] = F1;
	Vals[6] = G1;
	
	// used in: P2(19) == 285220864 (0x11002000), P4(20)
	// W[4] = 0x80000000U;
	// P1(x) is 0 for x == 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
	// P2(x) is 0 for x == 20, 21, 22, 23, 24, 25, 26, 27, 28, 29
	// P3(x) is 0 for x == 12, 13, 14, 15, 16, 17, 18, 19, 20, 21
	// P4(x) is 0 for x == 21, 22, 23, 24, 25, 26, 27, 28, 29, 30
	// W[x] in sharound(x) is 0 for x == 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
	// W[14] = W[13] = W[12] = W[11] = W[10] = W[9] = W[8] = W[7] = W[6] = W[5] = 0x00000000U;
	// used in: P2(30) == 10485845 (0xA00055), P3(22), P4(31)
	// K[15] + W[15] == 0xc19bf174 + 0x00000280U = 0xc19bf3f4
	W[15 - O] = (u)0x00000280U;
	W[16 - O] = W16;
	W[17 - O] = W17;
	// W[18 - O] = W2 + (rot(W_3, 25) ^ rot(W_3, 14) ^ (W_3 >> 3U));
	W[19 - O] = W_3 + PreW19;
	Vals[7] += ch(4) + s1(4);
	Vals[3] = D1 + ch(4) + s1(4) + ma(4) + s0(4);
	W[20 - O] = (u)0x80000000U + P1(20);
	Vals[6] = C1addK5 + ch(5) + s1(5) + G1;
	Vals[2] = C1addK5 + ch(5) + s1(5) + ma(5) + s0(5);
	W[21 - O] = P1(21);
	sharound_no_W(6);
	W[22 - O] = P1(22) + P3(22);
	W[23 - O] = P1(23) + P3(23);
	sharound_no_W(7);
	W[24 - O] = P1(24) + P3(24);
	sharound_no_W(8);
	W[25 - O] = P1(25) + P3(25);
	sharound_no_W(9);
	W[26 - O] = P1(26) + P3(26);
	W[27 - O] = P1(27) + P3(27);
	sharound_no_W(10);
	sharound_no_W(11);
	W[28 - O] = P1(28) + P3(28);
	sharound_no_W(12);
	W[29 - O] = P1(29) + P3(29);
	W[30 - O] = (u)0xA00055 + P1(30) + P3(30);;
	sharound_no_W(13);
	sharound_no_W(14);

	sharoundC(15);
	sharound(16);
	sharound(17);
	sharound(18);
	sharound(19);
	sharound(20);
	sharound(21);
	sharound(22);
	sharound(23);
	sharound(24);
	sharound(25);
	sharound(26);
	sharound(27);
	sharound(28);
	W(31);
	W(32);
	sharound(29);
	sharound(30);
	sharound(31);
	sharound(32);
	W(33);
	sharound(33);
	W(34);
	sharound(34);
	W(35);
	sharound(35);
	W(36);
	sharound(36);
	W(37);
	sharound(37);
	W(38);
	sharound(38);
	W(39);
	sharound(39);
	W(40);
	sharound(40);
	W(41);
	sharound(41);
	W(42);
	sharound(42);
	W(43);
	sharound(43);
	W(44);
	sharound(44);
	W(45);
	sharound(45);
	W(46);
	sharound(46);
	W(47);
	sharound(47);
	W(48);
	sharound(48);
	W(49);
	sharound(49);
	W(50);
	sharound(50);
	W(51);
	sharound(51);
	W(52);
	sharound(52);
	W(53);
	sharound(53);
	W(54);
	sharound(54);
	W(55);
	sharound(55);
	W(56);
	sharound(56);
	W(57);
	sharound(57);
	W(58);
	sharound(58);
	W(59);
	sharound(59);
	W(60);
	sharound(60);
	W(61);
	sharound(61);
	W(62);
	sharound(62);
	W(63);
	sharound(63);

	W[64 - O] = state0 + Vals[0];
	W[65 - O] = state1 + Vals[1];
	W[66 - O] = state2 + Vals[2];
	W[67 - O] = state3 + Vals[3];
	W[68 - O] = state4 + Vals[4];
	W[69 - O] = state5 + Vals[5];
	W[70 - O] = state6 + Vals[6];
	W[71 - O] = state7 + Vals[7];
	W[72 - O] = 0x80000000U;

	W[79 - O] = 0x00000100U;

	Vals[0] = H[0];
	Vals[1] = H[1];
	Vals[2] = H[2];
	Vals[3] = L + W[64 - O];
	Vals[4] = H[3];
	Vals[5] = H[4];
	Vals[6] = H[5];
	Vals[7] = H[6] + W[64 - O];
	
	W[80 - O] = P4(80) + P2(80);
	W[81 - O] = (u)0xA00000 + P4(81) + P2(81);
	sharound(65);
	sharound(66);
	W[82 - O] = P4(82) + P1(82) + P2(82);
	sharound(67);
	W[83 - O] = P4(83) + P1(83) + P2(83);
	sharound(68);
	W[84 - O] = P4(84) + P1(84) + P2(84);
	sharound(69);
	W[85 - O] = P4(85) + P1(85) + P2(85);
	sharound(70);
	W(86);
	sharound(71);
	sharoundC(72);
	W[87 - O] = (u)0x11002000 + P4(87) + P3(87) + P1(87);
	W[88 - O] = (u)0x80000000U + P1(88) + P3(88);

	// W is also zero for these rounds
	sharoundC(73);
	sharoundC(74);
	W[89 - O] = P1(89) + P3(89);
	W[90 - O] = P1(90) + P3(90);
	sharoundC(75);
	sharoundC(76);
	W[91 - O] = P1(91) + P3(91);
	W[92 - O] = P1(92) + P3(92);
	sharoundC(77);
	sharoundC(78);

	sharound(79);
	sharound(80);
	sharound(81);	
	sharound(82);
	sharound(83);
	sharound(84);
	sharound(85);
	sharound(86);
	sharound(87);
	sharound(88);
	sharound(89);
	sharound(90);
	sharound(91);
	sharound(92);
	W[93 - O] = P1(93) + P3(93);
	sharound(93);
	W[94 - O] = (u)0x400022 + P1(94) + P3(94);
	sharound(94);
	W[95 - O] = (u)0x00000100U + P3(95) + P2(95) + P1(95);
	sharound(95);

	W(96);
	sharound(96);
	W(97);
	sharound(97);
	W(98);
	sharound(98);
	W(99);
	sharound(99);
	W(100);
	sharound(100);
	W(101);
	sharound(101);
	W(102);
	sharound(102);
	W(103);
	sharound(103);
	W(104);
	sharound(104);
	W(105);
	sharound(105);
	W(106);
	sharound(106);
	W(107);
	sharound(107);
	W(108);
	sharound(108);
	W(109);
	sharound(109);
	W(110);
	sharound(110);
	W(111);
	sharound(111);
	W(112);
	sharound(112);
	W(113);
	sharound(113);
	W(114);
	sharound(114);
	W(115);
	sharound(115);
	W(116);
	sharound(116);
	W(117);
	sharound(117);
	W(118);
	sharound(118);
	W(119);
	sharound(119);
	W(120);
	sharound(120);
	W(121);
	sharound(121);
	W(122);
	sharound(122);
	W(123);
	sharound(123);

	// Round 124
	Vals[7] += Vals[3] + P4(124) + P3(124) + P2(124) + P1(124) + ch(124) + s1(124);
	
#define MAXBUFFERS (4095)
#define NFLAG (0xFFFUL)

#if defined VECTORS2
	u result = (uint2){(Vals[7].x == -H[7]), (Vals[7].y == -H[7])};
	output[NFLAG & ((result.x * W_3.x) >> 2)] = output[MAXBUFFERS * result.x] = result.x * W_3.x;
	output[NFLAG & ((result.y * W_3.y) >> 2)] = output[MAXBUFFERS * result.y] = result.y * W_3.y;
#elif defined VECTORS4
	u result = (uint4){(Vals[7].x == -H[7]), (Vals[7].y == -H[7]), (Vals[7].z == -H[7]), (Vals[7].w == -H[7])};
	output[NFLAG & ((result.x * W_3.x) >> 2)] = output[MAXBUFFERS * result.x] = result.x * W_3.x;
	output[NFLAG & ((result.y * W_3.y) >> 2)] = output[MAXBUFFERS * result.y] = result.y * W_3.y;
	output[NFLAG & ((result.z * W_3.z) >> 2)] = output[MAXBUFFERS * result.z] = result.x * W_3.z;
	output[NFLAG & ((result.w * W_3.w) >> 2)] = output[MAXBUFFERS * result.w] = result.w * W_3.w;
#else
	u result = (Vals[7] == -H[7]);
	output[NFLAG & ((result * W_3) >> 2)] = output[MAXBUFFERS * result] = result * W_3;
#endif
}
