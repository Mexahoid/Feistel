using System;
using System.Security.Cryptography;
using System.Text;

namespace Feistel
{
    /// <summary>
    /// Класс логики шифрации.
    /// </summary>
    public class Logics
    {
        /// <summary>
        /// Направление циклического сдвига.
        /// </summary>
        private enum Direction
        {
            /// <summary>
            /// Сдвиг влево.
            /// </summary>
            Left,

            /// <summary>
            /// Сдвиг вправо.
            /// </summary>
            Right
        }

        /// <summary>
        /// Тип методов шифрации.
        /// </summary>
        public enum Method
        {
            /// <summary>
            /// Обычная сеть Фейстеля.
            /// </summary>
            Normal,

            /// <summary>
            /// Режим сцепления блоков шифротекста.
            /// </summary>
            CBC,

            /// <summary>
            /// Режим обратной связи по шифротексту.
            /// </summary>
            CFB
        }

        /// <summary>
        /// Экземпляр класса.
        /// </summary>
        private static Logics _instance;

        /// <summary>
        /// Singleton класса шифрации.
        /// </summary>
        public static Logics Instance => _instance ?? (_instance = new Logics());

        /// <summary>
        /// Делегат шифрования.
        /// </summary>
        private Func<StringBuilder[], int, string> Encryptor;

        /// <summary>
        /// Делегат дешифрования.
        /// </summary>
        private Func<StringBuilder[], int, string> Decryptor;

        /// <summary>
        /// Метод шифрации.
        /// </summary>
        public Method Current
        {
            set
            {
                switch (value)
                {
                    case Method.Normal:
                        Encryptor = EncryptNormal;
                        Decryptor = DecryptNormal;
                        break;
                    case Method.CBC:
                        Encryptor = EncryptCBC;
                        Decryptor = DecryptCBC;
                        break;
                    case Method.CFB:
                        Encryptor = EncryptCFB;
                        Decryptor = DecryptCFB;
                        break;
                }
            }
        }

        /// <summary>
        /// Ключ шифрации.
        /// </summary>
        private ulong _key;

        /// <summary>
        /// Инициализационный вектор.
        /// </summary>
        private ulong _initVector;

        /// <summary>
        /// Конструктор класса.
        /// </summary>
        private Logics()
        {
            Current = Method.Normal;
        }

        #region Инициализаторы
        
        /// <summary>
        /// Устанавливает ключ шифрации или отправляет исключение.
        /// </summary>
        /// <param name="skey">Строка с ключом.</param>
        public void SetKey(string skey)
        {
            if (ulong.TryParse(skey, out ulong key))
            {
                _key = key;
            }
            else
            {
                throw new Exception("Неверный формат ключа.");
            }
        }

        /// <summary>
        /// Устанавливает инициализационный вектор.
        /// </summary>
        /// <param name="iv">Строка с вектором.</param>
        public void SetInitVector(string iv)
        {
            if (ulong.TryParse(iv, out ulong initvector))
            {
                _initVector = initvector;
            }
            else
            {
                throw new Exception("Неверный формат инициализационного вектора.");
            }
        }

        /// <summary>
        /// Создает случайный блок ulong.
        /// </summary>
        /// <returns>Возвращает ulong.</returns>
        private ulong CreateUlong()
        {
            ulong block = 0;
            RNGCryptoServiceProvider p = new RNGCryptoServiceProvider();
            byte[] byteArray = new byte[8];
            p.GetBytes(byteArray);
            for (int i = 0; i < 8; i++)
            {
                block <<= 8;
                block += byteArray[i];
            }
            return block;
        }

        /// <summary>
        /// Создает и устанавливает ключ шифрации.
        /// </summary>
        /// <returns>Возвращает новый ключ.</returns>
        public ulong InitKey()
        {
            _key = CreateUlong();
            return _key;
        }

        /// <summary>
        /// Создает и устанавливает инициализационный вектор.
        /// </summary>
        /// <returns>Возвращает новый вектор.</returns>
        public ulong InitIV()
        {
            _initVector = CreateUlong();
            return _initVector;
        }

        #endregion

        /// <summary>
        /// Основной метод шифрации.
        /// </summary>
        /// <param name="text">Шифруемая строка.</param>
        /// <param name="rounds">Количество раундов шифрации.</param>
        /// <returns>Возвращает зашифрованную строку.</returns>
        public string Encrypt(string text, int rounds)
        {
            StringBuilder cipher = new StringBuilder();
            StringBuilder sb = new StringBuilder(text);
            StringBuilder[] sbs = new StringBuilder[2];
            FillOrEmpty(ref sb, true);
            sbs[0] = cipher;
            sbs[1] = sb;
            string encrText = Encryptor(sbs, rounds);
            return encrText;
        }

        /// <summary>
        /// Основной метод дешифрации.
        /// </summary>
        /// <param name="cipher">Зашифрованная строка.</param>
        /// <param name="rounds">Количество раундов дешифрации.</param>
        /// <returns>Возвращает расшифрованный текст.</returns>
        public string Decrypt(string cipher, int rounds)
        {
            //var bytes = Convert.FromBase64String(cipher);
            //string nc = Encoding.UTF8.GetString(bytes);

            StringBuilder text = new StringBuilder();
            StringBuilder sb = new StringBuilder(cipher);
            StringBuilder[] sbs = new StringBuilder[2];
            sbs[0] = text;
            sbs[1] = sb;

            string decrText = Decryptor(sbs, rounds);
            return decrText; 
        }
        
        #region Обычный

        /// <summary>
        /// Метод шифрации обычного Фейстеля.
        /// </summary>
        /// <param name="sbs">Шифруемая выровненная строка.</param>
        /// <param name="rounds">Количество раундов.</param>
        /// <returns>Возвращает зашифрованный текст.</returns>
        private string EncryptNormal(StringBuilder[] sbs, int rounds)
        {

            for (int i = 0; i < sbs[1].Length / 4; i++)
            {
                ulong block = CreateBlock(sbs[1], i);
                uint[] LR = EncryptBlock(SplitUlong(block), i, rounds);
                block = Concat(LR);
                GetCharsFromBlock(block, ref sbs[0]);
            }
            return sbs[0].ToString();
        }

        /// <summary>
        /// Метод дешифрации обычного Фейстеля.
        /// </summary>
        /// <param name="sbs">Дешифруемая выровненная строка.</param>
        /// <param name="rounds">Количество раундов.</param>
        /// <returns>Возвращает расшифрованный текст.</returns>
        private string DecryptNormal(StringBuilder[] sbs, int rounds)
        {
            for (int i = 0; i < sbs[1].Length / 4; i++)
            {
                ulong block = CreateBlock(sbs[1], i);
                uint[] LR = SplitUlong(block);
                LR = DecryptBlock(LR, i, rounds);
                block = Concat(LR);
                GetCharsFromBlock(block, ref sbs[0]);
            }
            FillOrEmpty(ref sbs[0], false);
            return sbs[0].ToString();
        }

        #endregion

        #region CBC

        /// <summary>
        /// Метод шифрации сцеплением блоков шифротекста.
        /// </summary>
        /// <param name="sbs">Шифруемая строка.</param>
        /// <param name="rounds">Количество раундов.</param>
        /// <returns>Возвращает зашифрованный текст.</returns>
        private string EncryptCBC(StringBuilder[] sbs, int rounds)
        {
            // Опа твоя мать вектор
            ulong previousBlock = _initVector;

            for (int i = 0; i < sbs[1].Length / 4; i++)
            {
                ulong block = CreateBlock(sbs[1], i);
                // Приехали
                block ^= previousBlock;
                uint[] LR = EncryptBlock(SplitUlong(block), i, rounds);
                block = Concat(LR);
                // Хотите увидеть немного магии
                previousBlock = block;
                GetCharsFromBlock(block, ref sbs[0]);
            }
            return sbs[0].ToString();
        }

        /// <summary>
        /// Метод дешифрации сцеплением блоков шифротекста.
        /// </summary>
        /// <param name="sbs">Дешифруемая строка.</param>
        /// <param name="rounds">Количество раундов.</param>
        /// <returns>Возвращает расшифрованный текст.</returns>
        private string DecryptCBC(StringBuilder[] sbs, int rounds)
        {
            // Ага, вот эти ребята
            ulong previousBlock = _initVector;

            for (int i = 0; i < sbs[1].Length / 4; i++)
            {
                ulong block = CreateBlock(sbs[1], i);
                ulong tempBlock = block;
                uint[] LR = SplitUlong(block);
                LR = DecryptBlock(LR, i, rounds);
                block = Concat(LR);
                block ^= previousBlock;
                previousBlock = tempBlock;
                GetCharsFromBlock(block, ref sbs[0]);
            }
            FillOrEmpty(ref sbs[0], false);
            return sbs[0].ToString();
        }

        #endregion

        #region CFB

        /// <summary>
        /// Метод шифрации режимом обратной связи по шифротексту.
        /// </summary>
        /// <param name="sbs">Шифруемая строка.</param>
        /// <param name="rounds">Количество раундов.</param>
        /// <returns>Возвращает зашифрованный текст.</returns>
        private string EncryptCFB(StringBuilder[] sbs, int rounds)
        {
            // Опа твоя мать вектор
            ulong previousBlock = _initVector;

            for (int i = 0; i < sbs[1].Length / 4; i++)
            {
                // Сначала выдернуть чистый текст
                ulong block = CreateBlock(sbs[1], i);
                // Зашифровать старое
                uint[] LR = EncryptBlock(SplitUlong(previousBlock), i, rounds);
                ulong nblock = Concat(LR);
                // Ксорнуть зашифрованное и чистый текст
                previousBlock = nblock ^ block;
                GetCharsFromBlock(previousBlock, ref sbs[0]);
            }
            return sbs[0].ToString();
        }

        /// <summary>
        /// Метод дешифрации режимом обратной связи по шифротексту.
        /// </summary>
        /// <param name="sbs">Дешифруемая строка.</param>
        /// <param name="rounds">Количество раундов.</param>
        /// <returns>Возвращает расшифрованный текст.</returns>
        private string DecryptCFB(StringBuilder[] sbs, int rounds)
        {
            // Ага, вот эти ребята
            ulong previousBlock = _initVector;

            for (int i = 0; i < sbs[1].Length / 4; i++)
            {
                // Зашифрованный текст
                ulong block = CreateBlock(sbs[1], i);
                uint[] LR = SplitUlong(previousBlock);
                LR = EncryptBlock(LR, i, rounds);
                // Типа как расшифрованный ИВ
                ulong nblock = Concat(LR);
                // Выдернутый зашифрованный
                previousBlock = block;
                // Ксорнутый зашифрованный текст и ответ
                block ^= nblock;
                GetCharsFromBlock(block, ref sbs[0]);
            }
            FillOrEmpty(ref sbs[0], false);
            return sbs[0].ToString();
        }

        #endregion
        
        #region Спецметоды
        
        /// <summary>
        /// Выполняет раундовую шифрацию блока данных.
        /// </summary>
        /// <param name="LR">2 блока uint.</param>
        /// <param name="i">Номер итерации.</param>
        /// <returns>Возвращает 2 зашифрованных блока uint.</returns>
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

        /// <summary>
        /// Функция шифрации.
        /// </summary>
        /// <param name="L">Левый блок шифрации.</param>
        /// <param name="K">Ключ шифрации.</param>
        /// <returns>Возвращает uint блок.</returns>
        private uint Function(uint L, uint K)
        {
            uint Li9 = CyclicShift(L, 9, Direction.Left);
            uint Ki11 = CyclicShift(K, 11, Direction.Right);
            uint Ki11Li = ~(Ki11 ^ Li9);
            uint FLiKi = Li9 ^ Ki11Li;
            return FLiKi;
        }

        /// <summary>
        /// Создает раундовый ключ на основе итерации.
        /// </summary>
        /// <param name="i">Номер итерации.</param>
        /// <returns>Возвращает uint раундовый ключ.</returns>
        private uint CreateRoundKey(int i)
        {
            ulong newKey = CyclicShift(_key, i * 8, Direction.Right);
            uint[] arr = SplitUlong(newKey);
            return arr[1];
        }

        /// <summary>
        /// Разделяет блок ulong на 2 блока uint.
        /// </summary>
        /// <param name="value">Разделяемый блок.</param>
        /// <returns>Возвращает 2 блока uint.</returns>
        private uint[] SplitUlong(ulong value)
        {
            uint[] arr = new uint[2];
            arr[0] = (uint)((value & ((ulong)uint.MaxValue << 32)) >> 32);
            arr[1] = (uint)(value & uint.MaxValue);
            return arr;
        }

        #region Сдвиги
        
        /// <summary>
        /// Циклический сдвиг для uint.
        /// </summary>
        /// <param name="value">Сдвигаемое число.</param>
        /// <param name="shifting">Количество сдвигов.</param>
        /// <param name="dir">Направление сдвига.</param>
        /// <returns>Возвращает циклически сдвинутый блок uint.</returns>
        private uint CyclicShift(uint value, int shifting, Direction dir)
        {
            if (dir == Direction.Left)
            {
                return value >> (32 - shifting % 32) | value << shifting % 32;
            }

            return value << (32 - shifting % 32) | value >> shifting % 32;

        }

        /// <summary>
        /// Циклический сдвиг для ulong.
        /// </summary>
        /// <param name="value">Сдвигаемое число.</param>
        /// <param name="shifting">Количество сдвигов.</param>
        /// <param name="dir">Направление сдвига.</param>
        /// <returns>Возвращает циклически сдвинутый блок ulong.</returns>
        private ulong CyclicShift(ulong value, int shifting, Direction dir)
        {
            if (dir == Direction.Left)
            {
                return value >> (64 - shifting % 64) | value << shifting % 64;
            }

            return value << (64 - shifting % 64) | value >> shifting % 64;
        }
        
        #endregion

        /// <summary>
        /// Забеление блока на основе ключа и итерации.
        /// </summary>
        /// <param name="block">Блок для забеления.</param>
        /// <param name="iteration">Итерация для расчета ключа забеления.</param>
        /// <returns></returns>
        public uint Blind(uint block, int iteration)
        {
            uint keyBlind = (uint)CyclicShift(_key, iteration * 9, Direction.Right);
            return block ^ keyBlind;
        }

        /// <summary>
        /// Зашифровка блока на основе итерации и раундов.
        /// </summary>
        /// <param name="LR">2 блока uint.</param>
        /// <param name="i">Номер итерации.</param>
        /// <param name="rounds">Общее количество раундов.</param>
        /// <returns>Возвращает зашифрованные блоки.</returns>
        private uint[] EncryptBlock(uint[] LR, int i, int rounds)
        {
            LR[0] = Blind(LR[0], i);
            LR[1] = Blind(LR[1], i);

            for (int j = 0; j < rounds; j++)
            {
                LR = Round(LR, j);
            }

            // Развернуть обратно
            uint t = LR[0];
            LR[0] = LR[1];
            LR[1] = t;


            return LR;
        }

        /// <summary>
        /// Расшифровка блока на основе итерации и раундов.
        /// </summary>
        /// <param name="LR">2 блока uint.</param>
        /// <param name="i">Номер итерации.</param>
        /// <param name="rounds">Общее количество раундов.</param>
        /// <returns>Возвращает расшифрованные блоки.</returns>
        private uint[] DecryptBlock(uint[] LR, int i, int rounds)
        {
            for (int j = rounds - 1; j >= 0; j--)
            {
                LR = Round(LR, j);
            }
            // Развернуть обратно

            uint t = LR[0];
            LR[0] = LR[1];
            LR[1] = t;


            LR[0] = Blind(LR[0], i);
            LR[1] = Blind(LR[1], i);

            return LR;
        }

        /// <summary>
        /// Соединение 2 блоков uint в блок ulong.
        /// </summary>
        /// <param name="LR">2 блока uint.</param>
        /// <returns></returns>
        private ulong Concat(uint[] LR)
        {
            ulong block = (ulong)LR[0] << 32;
            block += LR[1];
            return block;
        }

        /// <summary>
        /// Расшифровывает блок ulong в 4 символа.
        /// </summary>
        /// <param name="block">Блок для расшифровки.</param>
        /// <param name="sb">StringBuilder, в который происходит расшифровка.</param>
        private void GetCharsFromBlock(ulong block, ref StringBuilder sb)
        {
            for (int j = 0; j < 4; j++)
            {
                ushort st = 0;
                block = CyclicShift(block, 16, Direction.Left);
                st = (ushort)block;
                sb.Append((char)st);
            }
        }

        /// <summary>
        /// Универсальный метод для выравнивания до кратного 8 и обратного действия.
        /// </summary>
        /// <param name="sb">StringBuilder для выравнивания.</param>
        /// <param name="filling">Если True, то добавляет. Если False, то стирает.</param>
        private void FillOrEmpty(ref StringBuilder sb, bool filling)
        {
            if (filling)
            {
                if (sb.Length % 8 != 0)
                {
                    sb.Append('\0', 8 - sb.Length % 8);
                }
            }
            else
            {
                for (int i = sb.Length - 1; i >= 0; i--)
                {
                    if (sb[i] == '\0')
                    {
                        sb.Remove(i, 1);
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }

        /// <summary>
        /// Вытягивает 4 символа из строки и создает битовый блок ulong.
        /// </summary>
        /// <param name="sb">StringBuilder, из которого вытаскиваются 4 символа.</param>
        /// <param name="i">4-кратный сдвиг относительно начала.</param>
        /// <returns>Возвращает блок ulong.</returns>
        private ulong CreateBlock(StringBuilder sb, int i)
        {
            ulong block = 0;
            for (int j = 0; j < 4; j++)
            {
                block <<= 16;
                block += sb[i * 4 + j];
            }

            return block;
        }
        
        #endregion
    }
}