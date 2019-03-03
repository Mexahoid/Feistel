using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Feistel
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private int _rounds = 2;
        public MainWindow()
        {
            InitializeComponent();
        }

        private void NudDown_Click(object sender, RoutedEventArgs e)
        {
            if(_rounds > 1)
                _rounds--;
            TxtNum.Text = _rounds.ToString();
        }

        private void NudUp_Click(object sender, RoutedEventArgs e)
        {
            if(_rounds < 12)
                _rounds++;
            TxtNum.Text = _rounds.ToString();
        }

        private void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            string text = TextInp.Text;
            TextOutput.Text = "";

            try
            {
                Logics.Instance.SetKey(KeyBox.Text);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }

            TextOutput.Text = Logics.Instance.Encrypt(text, _rounds);
            CipherInput.Text = TextOutput.Text;
            CipherOutput.Text = "";
        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            string cipher = CipherInput.Text;
            CipherOutput.Text = "";

            try
            {
                Logics.Instance.SetKey(KeyBoxDecr.Text);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }

            CipherOutput.Text = Logics.Instance.Decrypt(cipher, _rounds);
        }

        private void CreateKey_Click(object sender, RoutedEventArgs e)
        {
            ulong u = Logics.Instance.InitKey();
            KeyBox.Text = u.ToString();
            KeyBoxDecr.Text = u.ToString();
        }
    }
}
