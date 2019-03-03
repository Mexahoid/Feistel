using System;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Markup.Localizer;

namespace Feistel
{
    public class Logics
    {
        private enum Direction
        {
            Left,
            Right
        }

        private static Logics _instance;
        public static Logics Instance => _instance ?? (_instance = new Logics());

        private ulong _key = 0;

        private Logics(){ }

        public void SetKey(string skey)
        {
            if (skey != _key.ToString() && ulong.TryParse(skey, out ulong key))
                _key = key;
            else
                throw new Exception("Неверный формат ключа.");
        }
        
        public ulong InitKey()
        {
            RNGCryptoServiceProvider p = new RNGCryptoServiceProvider();
            byte[] byteArray = new byte[8];
            p.GetBytes(byteArray);
            for (int i = 0; i < 8; i++)
            {
                _key <<= 8;
                _key += byteArray[i];
            }

            return _key;
        }


        public uint Blind(uint block, int iteration)
        {
            uint keyBlind = (uint)CyclicShift(_key, iteration * 9, Direction.Right);
            return block ^ keyBlind;
        }

        public string Encrypt(string text, int rounds)
        {
            StringBuilder cipher = new StringBuilder();

            StringBuilder sb = new StringBuilder(text);
            if (text.Length % 8 != 0)
                sb.Append('\0', 8 - text.Length % 8);
            for (int i = 0; i < sb.Length / 4; i++)
            {
                ulong block = 0;
                for (int j = 0; j < 4; j++)
                {
                    block <<= 16;
                    block += sb[i * 4 + j];
                }

                uint[] LR = SplitUlong(block);
                LR[0] = Blind(LR[0], i);
                LR[1] = Blind(LR[1], i);

                for (int j = 0; j < rounds; j++)
                    LR = Round(LR, j);

                // Развернуть обратно
                var t = LR[0];
                LR[0] = LR[1];
                LR[1] = t;


                block = (ulong)LR[0] << 32;
                block += LR[1];
                

                for (int j = 0; j < 4; j++)
                {
                    ushort st = 0;
                    string a = Convert.ToString((long)block, 2).PadLeft(64, '0');
                    block = CyclicShift(block, 16, Direction.Left);
                    st = (ushort)block;
                    cipher.Append((char)st);
                    block &= 0xffff_ffff_ffff_0000;
                }
            }

            return cipher.ToString();
        }

        public string Decrypt(string cipher, int rounds)
        {
            StringBuilder text = new StringBuilder();

            StringBuilder sb = new StringBuilder(cipher);

            for (int i = 0; i < sb.Length / 4; i++)
            {
                ulong block = 0;
                for (int j = 0; j < 4; j++)
                {
                    block <<= 16;
                    block += sb[i * 4 + j];
                }

                uint[] LR = SplitUlong(block);

                for (int j = rounds - 1; j >= 0; j--)
                    LR = Round(LR, j);
                // Развернуть обратно

                var t = LR[0];
                LR[0] = LR[1];
                LR[1] = t;


                LR[0] = Blind(LR[0], i);
                LR[1] = Blind(LR[1], i);

                block = (ulong)LR[0] << 32;
                block += LR[1];

                for (int j = 0; j < 4; j++)
                {
                    ushort st = 0;
                    block = CyclicShift(block, 16, Direction.Left);
                    st = (ushort)block;
                    text.Append((char)st);
                }
            }

            for (int i = text.Length - 1; i >= 0; i--)
            {
                if (text[i] == '\0')
                    text.Remove(i, 1);
                else break;
            }


            return text.ToString();
        }

        private uint[] Round(uint[] LR, int i)
        {
            uint[] arr = new uint[2];
            uint K = CreateRoundKey(i);
            uint LFK = Function(LR[0], K);
            uint Rres = LR[1] ^ LFK;
            arr[0] = Rres;
            arr[1] = LR[0];
            return arr;
        }

        private uint Function(uint L, uint K)
        {
            uint Li9 = CyclicShift(L, 9, Direction.Left);
            uint Ki11 = CyclicShift(K, 11, Direction.Right);
            uint Ki11Li = ~(Ki11 ^ Li9);
            uint FLiKi = Li9 ^ Ki11Li;
            return FLiKi;
        }

        private uint CreateRoundKey(int i)
        {
            ulong newKey = CyclicShift(_key, i * 8, Direction.Right);
            uint[] arr = SplitUlong(newKey);
            return arr[1];
        }

        private uint[] SplitUlong(ulong value)
        {
            uint[] arr = new uint[2];
            arr[0] = (uint)((value & ((ulong)uint.MaxValue << 32)) >> 32);
            arr[1] = (uint)(value & uint.MaxValue);
            return arr;
        }

        private uint CyclicShift(uint value, int shifting, Direction dir)
        {
            if (dir == Direction.Left)
                return value >> (32 - shifting % 32) | value << shifting % 32;
            return value << (32 - shifting % 32) | value >> shifting % 32;

        }

        private ulong CyclicShift(ulong value, int shifting, Direction dir)
        {
            if (dir == Direction.Left)
                return value >> (64 - shifting % 64) | value << shifting % 64;
            return value << (64 - shifting % 64) | value >> shifting % 64;
        }
    }
}