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
            TextOutput.Text = "";
            try
            {
                Logics.Instance.SetKey(KeyBox.Text);
                TextOutput.Text = Logics.Instance.Encrypt(TextInp.Text, _rounds);
                CipherInput.Text = TextOutput.Text;
                CipherOutput.Text = "";
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            CipherOutput.Text = "";
            try
            {
                Logics.Instance.SetKey(KeyBoxDecr.Text);
                CipherOutput.Text = Logics.Instance.Decrypt(CipherInput.Text, _rounds);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }

        }

        private void CreateKey_Click(object sender, RoutedEventArgs e)
        {
            ulong u = Logics.Instance.InitKey();
            KeyBox.Text = u.ToString();
            KeyBoxDecr.Text = u.ToString();
        }
    }
}
